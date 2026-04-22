package efp

import "testing"

func TestEFP(t *testing.T) {
	formulae := []string{
		`=SUM())`,
		`=SUM("")`,
		// Simple test formulae
		`="あいうえお"&H3&"b"`,
		`=1+3+5`,
		`=3 * 4 + 5`,
		`=50`,
		`=1+1`,
		`=$A1`,
		`=$B$2`,
		`=SUM(B5:B15)`,
		`=SUM(B5:B15,D5:D15)`,
		`=SUM(B5:B15 A7:D7)`,
		`=SUM(sheet1!$A$1:$B$2)`,
		`=[data.xls]sheet1!$A$1`,
		`=[#data.xls]`,
		`=[{data.xls]`,
		`=SUM((A:A 1:1))`,
		`=SUM((A:A,1:1))`,
		`=SUM((A:A A1:B1))`,
		`=SUM(D9:D11,E9:E11,F9:F11)`,
		`=SUM((D9:D11,(E9:E11,F9:F11)))`,
		`=((D2 * D3) + D4) & " should be 10"`,
		`=AND(1=1),1=1`,
		`='x'`,
		`=a"b""`,
		`=#]#NUM!`,
		`=3.1E-24-2.1E-24`,
		`''`,
		`=IF(R#`,
		`=IF(R{`,
		`=""+'''`,
		`=1%2`,
		`={1,2}`,
		`=TRUE`,
		`=--1-1`,
		`=1 .  +" "`,
		`=10*2^(2*(1+1))% (=10.28114; % has greater precedence than ^)`,
		`=2+(10*2^(2*(1+1)+SUM(A2)))*3 (who knows, but you'll push and pop here multiple times)`,
		// E. W. Bachtal's test formulae
		`=IF(P5=1.0,"NA",IF(P5=2.0,"A",IF(P5=3.0,"B",IF(P5=4.0,"C",IF(P5=5.0,"D",IF(P5=6.0,"E",IF(P5=7.0,"F",IF(P5=8.0,"G"))))))))`,
		`={SUM(B2:D2*B3:D3)}`,
		`=SUM(123 + SUM(456) + (45<6))+456+789`,
		`=AVG(((((123 + 4 + AVG(A1:A2))))))`,
		`=IF("a"={"a","b";"c",#N/A;-1,TRUE}, "yes", "no") &   "  more ""test"" text"`,
		`=+ AName- (-+-+-2^6) = {"A","B"} + @SUM(R1C1) + (@ERROR.TYPE(#VALUE!) = 2)`,
		`=IF(R13C3>DATE(2002,1,6),0,IF(ISERROR(R[41]C[2]),0,IF(R13C3>=R[41]C[2],0, IF(AND(R[23]C[11]>=55,R[24]C[11]>=20),R53C3,0))))`,
	}
	for _, f := range formulae {
		p := ExcelParser()
		t.Log("========================================")
		t.Log("Formula:     ", f)
		p.Parse(f)
		t.Log("Pretty printed:\n", p.PrettyPrint())
		t.Log("----------------------------------------")
		t.Log("Render printed:\n", p.Render())
		p.Tokens.tp()
		p.Tokens.value()
		p.Tokens.subtype()
	}
	tk := Tokens{Index: -1}
	tk.current()
	tk.next()
	tk.previous()
}

func TestNonFormulas(t *testing.T) {
	formulae := []string{
		``,
		`+`,
		``,
		`                 `,
	}
	for _, f := range formulae {
		t.Run(`"`+f+`"`, func(t *testing.T) {
			p := ExcelParser()
			if p.Parse(f) != nil {
				t.Log(`non-nil result given`)
				t.Fail()
			}
		})
	}
}
