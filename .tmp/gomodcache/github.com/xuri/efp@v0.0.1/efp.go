// Package efp (Excel Formula Parser) tokenize an Excel formula using an
// implementation of E. W. Bachtal's algorithm.
//
// Go language version by Ri Xu: https://xuri.me
package efp

import (
	"regexp"
	"strconv"
	"strings"
)

// QuoteDouble, QuoteSingle and other's constants are token definitions.
const (
	// Character constants
	QuoteDouble  = '"'
	QuoteSingle  = '\''
	BracketClose = ']'
	BracketOpen  = '['
	BraceOpen    = '{'
	BraceClose   = '}'
	ParenOpen    = '('
	ParenClose   = ')'
	Semicolon    = ';'
	Whitespace   = ' '
	Comma        = ','
	ErrorStart   = '#'

	OperatorsSN      = "+-"
	OperatorsInfix   = "+-*/^&=><"
	OperatorsPostfix = '%'

	// Token type
	TokenTypeNoop            = "Noop"
	TokenTypeOperand         = "Operand"
	TokenTypeFunction        = "Function"
	TokenTypeSubexpression   = "Subexpression"
	TokenTypeArgument        = "Argument"
	TokenTypeOperatorPrefix  = "OperatorPrefix"
	TokenTypeOperatorInfix   = "OperatorInfix"
	TokenTypeOperatorPostfix = "OperatorPostfix"
	TokenTypeWhitespace      = "Whitespace"
	TokenTypeUnknown         = "Unknown"

	// Token subtypes
	TokenSubTypeStart         = "Start"
	TokenSubTypeStop          = "Stop"
	TokenSubTypeText          = "Text"
	TokenSubTypeNumber        = "Number"
	TokenSubTypeLogical       = "Logical"
	TokenSubTypeError         = "Error"
	TokenSubTypeRange         = "Range"
	TokenSubTypeMath          = "Math"
	TokenSubTypeConcatenation = "Concatenation"
	TokenSubTypeIntersection  = "Intersection"
	TokenSubTypeUnion         = "Union"
)

var expRegex = regexp.MustCompile(`^[1-9]{1}(\.[0-9]+)?E{1}$`)

// Token encapsulate a formula token.
type Token struct {
	TValue   string
	TType    string
	TSubType string
}

// Tokens directly maps the ordered list of tokens.
// Attributes:
//
//	items - Ordered list
//	index - Current position in the list
type Tokens struct {
	Index int
	Items []Token
}

// Parser inheritable container. TokenStack directly maps a LIFO stack of
// tokens.
type Parser struct {
	Formula    string
	fRune      []rune
	Tokens     Tokens
	TokenStack Tokens
	Offset     int
	InString   bool
	InPath     bool
	InRange    bool
	InError    bool
}

// isInComparisonSet matches <=, >=, and <>
func isInComparisonSet(r []rune) bool {
	if len(r) < 2 {
		return false
	}
	if r[0] != '>' && r[0] != '<' {
		return false
	}
	return r[1] == '=' || (r[0] == '<' && r[1] == '>')
}

// isInfix matches any of +-*/^&=><
func isInfix(r rune) bool {
	return r == '+' || r == '-' || r == '*' || r == '/' || r == '^' || r == '&' || r == '=' || r == '>' || r == '<'
}

// isAnError returns a value that indicates whether the given runes text
// represents a formula error.
func isAnError(r []rune) bool {
	return runesEqual(r, []rune("#NULL!")) ||
		runesEqual(r, []rune("#DIV/0!")) ||
		runesEqual(r, []rune("#VALUE!")) ||
		runesEqual(r, []rune("#REF!")) ||
		runesEqual(r, []rune("#NAME?")) ||
		runesEqual(r, []rune("#NUM!")) ||
		runesEqual(r, []rune("#N/A")) ||
		runesEqual(r, []rune("#SPILL!")) ||
		runesEqual(r, []rune("#CALC!")) ||
		runesEqual(r, []rune("#GETTING_DATA"))
}

// runesEqual Returns a value that indicates whether the current runes text and
// a specified runes text are equal.
func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i, r := range a {
		if b[i] != r {
			return false
		}
	}
	return true
}

// fToken provides function to encapsulate a formula token.
func fToken(value, tokenType, subType string) Token {
	return Token{
		TValue:   value,
		TType:    tokenType,
		TSubType: subType,
	}
}

// fTokens provides function to handle an ordered list of tokens.
func fTokens(size, cap int) Tokens {
	if size == 0 && cap == 0 {
		return Tokens{
			Index: -1,
		}
	}
	return Tokens{
		Index: -1,
		Items: make([]Token, size, cap),
	}
}

// add provides function to add a token to the end of the list.
func (tk *Tokens) add(value, tokenType, subType string) Token {
	token := fToken(value, tokenType, subType)
	tk.addRef(token)
	return token
}

// addRef provides function to add a token to the end of the list.
func (tk *Tokens) addRef(token Token) {
	tk.Items = append(tk.Items, token)
}

// reset provides function to reset the index to -1.
func (tk *Tokens) reset() {
	tk.Index = -1
}

// BOF provides function to check whether beginning of list.
func (tk *Tokens) BOF() bool {
	return tk.Index <= 0
}

// EOF provides function to check whether end of list.
func (tk *Tokens) EOF() bool {
	return tk.Index >= (len(tk.Items) - 1)
}

// moveNext provides function to move the index along one.
func (tk *Tokens) moveNext() bool {
	if tk.EOF() {
		return false
	}
	tk.Index++
	return true
}

// current return the current token.
func (tk *Tokens) current() *Token {
	if tk.Index == -1 {
		return nil
	}
	return &tk.Items[tk.Index]
}

// next return the next token (leave the index unchanged).
func (tk *Tokens) next() *Token {
	if tk.EOF() {
		return nil
	}
	return &tk.Items[tk.Index+1]
}

// previous return the previous token (leave the index unchanged).
func (tk *Tokens) previous() *Token {
	if tk.Index < 1 {
		return nil
	}
	return &tk.Items[tk.Index-1]
}

// push provides function to push a token onto the stack.
func (tk *Tokens) push(token Token) {
	tk.Items = append(tk.Items, token)
}

// pop provides function to pop a token off the stack.
func (tk *Tokens) pop() Token {
	if len(tk.Items) == 0 {
		return Token{
			TType:    TokenTypeFunction,
			TSubType: TokenSubTypeStop,
		}
	}
	t := tk.Items[len(tk.Items)-1]
	tk.Items = tk.Items[:len(tk.Items)-1]
	return fToken("", t.TType, TokenSubTypeStop)
}

// token provides function to non-destructively return the top item on the
// stack.
func (tk *Tokens) token() *Token {
	if len(tk.Items) > 0 {
		return &tk.Items[len(tk.Items)-1]
	}
	return nil
}

// value return the top token's value.
func (tk *Tokens) value() string {
	if tk.token() == nil {
		return ""
	}
	return tk.token().TValue
}

// tp return the top token's type.
func (tk *Tokens) tp() string {
	if tk.token() == nil {
		return ""
	}
	return tk.token().TType
}

// subtype return the top token's subtype.
func (tk *Tokens) subtype() string {
	if tk.token() == nil {
		return ""
	}
	return tk.token().TSubType
}

// ExcelParser provides function to parse an Excel formula into a stream of
// tokens.
func ExcelParser() Parser {
	return Parser{}
}

// getTokens return a token stream (list).
func (ps *Parser) getTokens() Tokens {
	ps.Formula = strings.TrimSpace(ps.Formula)
	ps.fRune = []rune(ps.Formula)
	if len(ps.fRune) > 0 && ps.fRune[0] != '=' {
		ps.Formula = "=" + ps.Formula
		ps.fRune = []rune(ps.Formula)
	}

	var token []rune

	// state-dependent character evaluation (order is important)
	for !ps.EOF() {

		// double-quoted strings
		// embeds are doubled
		// end marks token
		if ps.InString {
			if ps.currentChar() == QuoteDouble {
				if ps.nextChar() == QuoteDouble {
					token = append(token, QuoteDouble)
					ps.Offset++
				} else {
					ps.InString = false
					ps.Tokens.add(string(token), TokenTypeOperand, TokenSubTypeText)
					token = token[:0]
				}
			} else {
				token = append(token, ps.currentChar())
			}
			ps.Offset++
			continue
		}

		// single-quoted strings (links)
		// embeds are double
		// end does not mark a token
		if ps.InPath {
			if ps.currentChar() == QuoteSingle {
				if ps.nextChar() == QuoteSingle {
					token = append(token, QuoteSingle)
					ps.Offset++
				} else {
					ps.InPath = false
				}
			} else {
				token = append(token, ps.currentChar())
			}
			ps.Offset++
			continue
		}

		// bracketed strings (range offset or linked workbook name)
		// no embeds (changed to "()" by Excel)
		// end does not mark a token
		if ps.InRange {
			if ps.currentChar() == BracketClose {
				ps.InRange = false
			}
			token = append(token, ps.currentChar())
			ps.Offset++
			continue
		}

		// error values
		// end marks a token, determined from absolute list of values
		if ps.InError {
			token = append(token, ps.currentChar())
			ps.Offset++

			if isAnError(token) {
				ps.InError = false
				ps.Tokens.add(string(token), TokenTypeOperand, TokenSubTypeError)
				token = token[:0]
			}
			continue
		}

		// scientific notation check
		if len(token) > 1 && (ps.currentChar() == '+' || ps.currentChar() == '-') {
			if expRegex.MatchString(string(token)) {
				token = append(token, ps.currentChar())
				ps.Offset++
				continue
			}
		}

		// independent character evaluation (order not important)
		// establish state-dependent character evaluations
		if ps.currentChar() == QuoteDouble {
			if len(token) > 0 {
				// not expected
				ps.Tokens.add(string(token), TokenTypeUnknown, "")
				token = token[:0]
			}
			ps.InString = true
			ps.Offset++
			continue
		}

		if ps.currentChar() == QuoteSingle {
			if len(token) > 0 {
				// not expected
				ps.Tokens.add(string(token), TokenTypeUnknown, "")
				token = token[:0]
			}
			ps.InPath = true
			ps.Offset++
			continue
		}

		if ps.currentChar() == BracketOpen {
			ps.InRange = true
			token = append(token, ps.currentChar())
			ps.Offset++
			continue
		}

		if ps.currentChar() == ErrorStart {
			if len(token) > 0 {
				// not expected
				ps.Tokens.add(string(token), TokenTypeUnknown, "")
				token = token[:0]
			}
			ps.InError = true
			token = append(token, ps.currentChar())
			ps.Offset++
			continue
		}

		// mark start and end of arrays and array rows
		if ps.currentChar() == BraceOpen {
			if len(token) > 0 {
				// not expected
				ps.Tokens.add(string(token), TokenTypeUnknown, "")
				token = token[:0]
			}
			ps.TokenStack.push(ps.Tokens.add("ARRAY", TokenTypeFunction, TokenSubTypeStart))
			ps.TokenStack.push(ps.Tokens.add("ARRAYROW", TokenTypeFunction, TokenSubTypeStart))
			ps.Offset++
			continue
		}

		if ps.currentChar() == Semicolon {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			ps.Tokens.addRef(ps.TokenStack.pop())
			ps.Tokens.add(string(Comma), TokenTypeArgument, "")
			ps.TokenStack.push(ps.Tokens.add("ARRAYROW", TokenTypeFunction, TokenSubTypeStart))
			ps.Offset++
			continue
		}

		if ps.currentChar() == BraceClose {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			ps.Tokens.addRef(ps.TokenStack.pop())
			ps.Tokens.addRef(ps.TokenStack.pop())
			ps.Offset++
			continue
		}

		// trim white-space
		if ps.currentChar() == Whitespace {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			ps.Tokens.add("", TokenTypeWhitespace, "")
			ps.Offset++
			for (ps.currentChar() == Whitespace) && (!ps.EOF()) {
				ps.Offset++
			}
			continue
		}

		// multi-character comparators
		if isInComparisonSet(ps.doubleChar()) {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			ps.Tokens.add(string(ps.doubleChar()), TokenTypeOperatorInfix, TokenSubTypeLogical)
			ps.Offset += 2
			continue
		}

		// standard infix operators
		if isInfix(ps.currentChar()) {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			ps.Tokens.add(string(ps.currentChar()), TokenTypeOperatorInfix, "")
			ps.Offset++
			continue
		}

		// standard postfix operators
		if ps.currentChar() == OperatorsPostfix {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			ps.Tokens.add(string(ps.currentChar()), TokenTypeOperatorPostfix, "")
			ps.Offset++
			continue
		}

		// start subexpression or function
		if ps.currentChar() == ParenOpen {
			if len(token) > 0 {
				ps.TokenStack.push(ps.Tokens.add(string(token), TokenTypeFunction, TokenSubTypeStart))
				token = token[:0]
			} else {
				ps.TokenStack.push(ps.Tokens.add("", TokenTypeSubexpression, TokenSubTypeStart))
			}
			ps.Offset++
			continue
		}

		// function, subexpression, array parameters
		if ps.currentChar() == Comma {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			if ps.TokenStack.tp() != TokenTypeFunction {
				ps.Tokens.add(string(ps.currentChar()), TokenTypeOperatorInfix, TokenSubTypeUnion)
			} else {
				ps.Tokens.add(string(ps.currentChar()), TokenTypeArgument, "")
			}
			ps.Offset++
			continue
		}

		// stop subexpression
		if ps.currentChar() == ParenClose {
			if len(token) > 0 {
				ps.Tokens.add(string(token), TokenTypeOperand, "")
				token = token[:0]
			}
			ps.Tokens.addRef(ps.TokenStack.pop())
			ps.Offset++
			continue
		}

		// token accumulation
		token = append(token, ps.currentChar())
		ps.Offset++
	}

	// dump remaining accumulation
	if len(token) > 0 {
		ps.Tokens.add(string(token), TokenTypeOperand, "")
	}

	// move all tokens to a new collection, excluding all unnecessary white-space tokens
	tokens2 := fTokens(0, len(ps.Tokens.Items))

	for ps.Tokens.moveNext() {
		token := ps.Tokens.current()

		if token.TType == TokenTypeWhitespace {
			if ps.Tokens.BOF() || ps.Tokens.EOF() {
			} else if !(((ps.Tokens.previous().TType == TokenTypeFunction) && (ps.Tokens.previous().TSubType == TokenSubTypeStop)) || ((ps.Tokens.previous().TType == TokenTypeSubexpression) && (ps.Tokens.previous().TSubType == TokenSubTypeStop)) || (ps.Tokens.previous().TType == TokenTypeOperand)) {
			} else if !(((ps.Tokens.next().TType == TokenTypeFunction) && (ps.Tokens.next().TSubType == TokenSubTypeStart)) || ((ps.Tokens.next().TType == TokenTypeSubexpression) && (ps.Tokens.next().TSubType == TokenSubTypeStart)) || (ps.Tokens.next().TType == TokenTypeOperand)) {
			} else {
				tokens2.add(token.TValue, TokenTypeOperatorInfix, TokenSubTypeIntersection)
			}
			continue
		}

		tokens2.addRef(Token{
			TValue:   token.TValue,
			TType:    token.TType,
			TSubType: token.TSubType,
		})
	}

	// switch infix "-" operator to prefix when appropriate, switch infix "+"
	// operator to noop when appropriate, identify operand and infix-operator
	// subtypes, pull "@" from in front of function names
	for tokens2.moveNext() {
		token := tokens2.current()
		if (token.TType == TokenTypeOperatorInfix) && (len(token.TValue) == 1 && token.TValue[0] == '-') {
			if tokens2.BOF() {
				token.TType = TokenTypeOperatorPrefix
			} else if ((tokens2.previous().TType == TokenTypeFunction) && (tokens2.previous().TSubType == TokenSubTypeStop)) || ((tokens2.previous().TType == TokenTypeSubexpression) && (tokens2.previous().TSubType == TokenSubTypeStop)) || (tokens2.previous().TType == TokenTypeOperatorPostfix) || (tokens2.previous().TType == TokenTypeOperand) {
				token.TSubType = TokenSubTypeMath
			} else {
				token.TType = TokenTypeOperatorPrefix
			}
			continue
		}

		if (token.TType == TokenTypeOperatorInfix) && (len(token.TValue) == 1 && token.TValue[0] == '+') {
			if tokens2.BOF() {
				token.TType = TokenTypeNoop
			} else if (tokens2.previous().TType == TokenTypeFunction) && (tokens2.previous().TSubType == TokenSubTypeStop) || ((tokens2.previous().TType == TokenTypeSubexpression) && (tokens2.previous().TSubType == TokenSubTypeStop) || (tokens2.previous().TType == TokenTypeOperatorPostfix) || (tokens2.previous().TType == TokenTypeOperand)) {
				token.TSubType = TokenSubTypeMath
			} else {
				token.TType = TokenTypeNoop
			}
			continue
		}

		if (token.TType == TokenTypeOperatorInfix) && (len(token.TSubType) == 0) {
			if token.TValue[0] == '<' || token.TValue[0] == '>' || token.TValue[0] == '=' {
				token.TSubType = TokenSubTypeLogical
			} else if len(token.TValue) == 1 && token.TValue[0] == '&' {
				token.TSubType = TokenSubTypeConcatenation
			} else {
				token.TSubType = TokenSubTypeMath
			}
			continue
		}

		if (token.TType == TokenTypeOperand) && (len(token.TSubType) == 0) {
			if _, err := strconv.ParseFloat(string(token.TValue), 64); err != nil {
				if (string(token.TValue) == "TRUE") || (string(token.TValue) == "FALSE") {
					token.TSubType = TokenSubTypeLogical
				} else {
					token.TSubType = TokenSubTypeRange
				}
			} else {
				token.TSubType = TokenSubTypeNumber
			}
			continue
		}

		if token.TType == TokenTypeFunction {
			if (len(token.TValue) > 0) && token.TValue[0] == '@' {
				token.TValue = token.TValue[1:]
			}
			continue
		}
	}

	tokens2.reset()

	// move all tokens to a new collection, excluding all no-ops
	tokens := fTokens(0, len(tokens2.Items))
	for tokens2.moveNext() {
		if tokens2.current().TType != TokenTypeNoop {
			tokens.addRef(Token{
				TValue:   tokens2.current().TValue,
				TType:    tokens2.current().TType,
				TSubType: tokens2.current().TSubType,
			})
		}
	}

	tokens.reset()
	if len(tokens.Items) == 0 {
		tokens.Items = nil
	}
	return tokens
}

// doubleChar provides function to get two characters after the current
// position.
func (ps *Parser) doubleChar() []rune {
	if len(ps.fRune) >= ps.Offset+2 {
		return ps.fRune[ps.Offset : ps.Offset+2]
	}
	return nil
}

// currentChar provides function to get the character of the current position.
func (ps *Parser) currentChar() rune {
	return ps.fRune[ps.Offset]
}

// nextChar provides function to get the next character of the current position.
func (ps *Parser) nextChar() rune {
	if len(ps.fRune) >= ps.Offset+2 {
		return ps.fRune[ps.Offset+1]
	}
	return 0
}

// EOF provides function to check whether end of tokens stack.
func (ps *Parser) EOF() bool {
	return ps.Offset >= len(ps.fRune)
}

// Parse provides function to parse formula as a token stream (list).
func (ps *Parser) Parse(formula string) []Token {
	ps.Formula = formula
	ps.Tokens = ps.getTokens()
	return ps.Tokens.Items
}

// PrettyPrint provides function to pretty the parsed result with the indented
// format.
func (ps *Parser) PrettyPrint() string {
	indent := 0
	var output strings.Builder
	for _, t := range ps.Tokens.Items {
		if t.TSubType == TokenSubTypeStop {
			indent--
		}
		for i := 0; i < indent; i++ {
			output.WriteRune('\t')
		}

		output.WriteString(t.TValue)
		output.WriteString(" <")
		output.WriteString(t.TType)
		output.WriteString("> <")
		output.WriteString(t.TSubType)
		output.WriteString(">\n")

		if t.TSubType == TokenSubTypeStart {
			indent++
		}
	}
	return output.String()
}

// Render provides function to get formatted formula after parsed.
func (ps *Parser) Render() string {
	var output strings.Builder
	for _, t := range ps.Tokens.Items {
		if t.TType == TokenTypeFunction && t.TSubType == TokenSubTypeStart {
			output.WriteString(t.TValue)
			output.WriteRune(ParenOpen)
		} else if t.TType == TokenTypeFunction && t.TSubType == TokenSubTypeStop {
			output.WriteRune(ParenClose)
		} else if t.TType == TokenTypeSubexpression && t.TSubType == TokenSubTypeStart {
			output.WriteRune(ParenOpen)
		} else if t.TType == TokenTypeSubexpression && t.TSubType == TokenSubTypeStop {
			output.WriteRune(ParenClose)
		} else if t.TType == TokenTypeOperand && t.TSubType == TokenSubTypeText {
			output.WriteRune(QuoteDouble)
			output.WriteString(t.TValue)
			output.WriteRune(QuoteDouble)
		} else if t.TType == TokenTypeOperatorInfix && t.TSubType == TokenSubTypeIntersection {
			output.WriteRune(Whitespace)
		} else {
			output.WriteString(t.TValue)
		}
	}
	return output.String()
}
