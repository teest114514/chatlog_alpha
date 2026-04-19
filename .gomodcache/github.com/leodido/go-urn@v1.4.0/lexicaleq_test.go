package urn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type equivalenceTestCase struct {
	eq bool
	lx []byte
	rx []byte
}

var equivalenceTests = []equivalenceTestCase{
	{
		true,
		[]byte("urn:foo:a123%2C456"),
		[]byte("URN:FOO:a123%2c456"),
	},
	{
		true,
		[]byte("urn:example:a123%2Cz456"),
		[]byte("URN:EXAMPLE:a123%2cz456"),
	},
	{
		true,
		[]byte("urn:foo:AbC123%2C456"),
		[]byte("URN:FOO:AbC123%2c456"),
	},
	{
		true,
		[]byte("urn:foo:AbC123%2C456%1f"),
		[]byte("URN:FOO:AbC123%2c456%1f"),
	},
	{
		true,
		[]byte("URN:foo:a123,456"),
		[]byte("urn:foo:a123,456"),
	},
	{
		true,
		[]byte("URN:foo:a123,456"),
		[]byte("urn:FOO:a123,456"),
	},
	{
		true,
		[]byte("urn:foo:a123,456"),
		[]byte("urn:FOO:a123,456"),
	},
	{
		true,
		[]byte("urn:ciao:%2E"),
		[]byte("urn:ciao:%2e"),
	},
	{
		false,
		[]byte("urn:foo:A123,456"),
		[]byte("URN:foo:a123,456"),
	},
	{
		false,
		[]byte("urn:foo:A123,456"),
		[]byte("urn:foo:a123,456"),
	},
	{
		false,
		[]byte("urn:foo:A123,456"),
		[]byte("urn:FOO:a123,456"),
	},
	{
		false,
		[]byte("urn:example:a123%2Cz456"),
		[]byte("urn:example:a123,z456"),
	},
	{
		false,
		[]byte("urn:example:A123,z456"),
		[]byte("urn:example:a123,Z456"),
	},
}

var equivalenceTests8141 = []equivalenceTestCase{
	{
		false,
		[]byte("urn:example:a123,z456/bar"),
		[]byte("urn:example:a123,z456/foo"),
	},
	{
		true,
		[]byte("urn:example:a123,z456?+abc"),
		[]byte("urn:example:a123,z456?=xyz"),
	},
	{
		true,
		[]byte("urn:example:a123,z456#789"),
		[]byte("urn:example:a123,z456?=xyz"),
	},
}

func lexicalEqual(t *testing.T, ii int, tt equivalenceTestCase, os ...Option) {
	t.Helper()
	urnlx, oklx := Parse(tt.lx, os...)
	urnrx, okrx := Parse(tt.rx, os...)

	if oklx && okrx {
		assert.True(t, urnlx.Equal(urnlx))
		assert.True(t, urnrx.Equal(urnrx))

		if tt.eq {
			assert.True(t, urnlx.Equal(urnrx), ierror(ii))
			assert.True(t, urnrx.Equal(urnlx), ierror(ii))
		} else {
			assert.False(t, urnlx.Equal(urnrx), ierror(ii))
			assert.False(t, urnrx.Equal(urnlx), ierror(ii))
		}
	} else {
		t.Log("Something wrong in the testing table ...")
	}
}

func TestLexicalEquivalence(t *testing.T) {
	for ii, tt := range equivalenceTests {
		lexicalEqual(t, ii, tt, WithParsingMode(RFC2141Only))
	}

	// The r-component, q-component, and f-component not taken into account for purposes of URN-equivalence
	// See [RFC8141#3.2](https://datatracker.ietf.org/doc/html/rfc8141#section-3.2)
	for ii, tt := range append(equivalenceTests, equivalenceTests8141...) {
		lexicalEqual(t, ii, tt, WithParsingMode(RFC8141Only))
	}
}

func TestEqualNil(t *testing.T) {
	u, ok := Parse([]byte("urn:hello:world"))
	require.NotNil(t, u)
	require.True(t, ok)
	require.False(t, u.Equal(nil))
}
