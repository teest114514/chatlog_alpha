package urn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultParsingMode(t *testing.T) {
	m := NewMachine()
	require.NotNil(t, m)
	require.IsType(t, &machine{}, m)
	require.Equal(t, DefaultParsingMode, m.(*machine).parsingMode)
}

func exec(t *testing.T, testCases []testCase, mode ParsingMode) {
	t.Helper()
	m := NewMachine(WithParsingMode(mode))
	for ii, tt := range testCases {
		urn, err := m.Parse([]byte(tt.in))
		ok := err == nil

		if ok {
			assert.True(t, tt.ok, herror(ii, tt))
			assert.Equal(t, tt.obj.prefix, urn.prefix, herror(ii, tt))
			assert.Equal(t, tt.obj.ID, urn.ID, herror(ii, tt))
			assert.Equal(t, tt.obj.SS, urn.SS, herror(ii, tt))
			assert.Equal(t, tt.str, urn.String(), herror(ii, tt))
			assert.Equal(t, tt.norm, urn.Normalize().String(), herror(ii, tt))
			if mode == RFC8141Only {
				assert.Equal(t, tt.obj.rComponent, urn.rComponent, herror(ii, tt))
				assert.Equal(t, tt.obj.rComponent, urn.rComponent, herror(ii, tt))
				assert.Equal(t, tt.obj.rComponent, urn.rComponent, herror(ii, tt))
				assert.Equal(t, urn.RFC(), RFC8141, herror(ii, tt))
			}
			if mode == RFC7643Only {
				assert.Equal(t, tt.isSCIM, urn.IsSCIM(), herror(ii, tt))
			}
		} else {
			assert.False(t, tt.ok, herror(ii, tt))
			assert.Empty(t, urn, herror(ii, tt))
			assert.Equal(t, tt.estr, err.Error(), herror(ii, tt))
			assert.Equal(t, tt.estr, m.Error().Error(), herror(ii, tt))
		}
	}
}

func TestParseDefaultMode(t *testing.T) {
	require.Equal(t, RFC2141Only, DefaultParsingMode)
	exec(t, urn2141OnlyTestCases, DefaultParsingMode)
}

func TestParse2141Only(t *testing.T) {
	exec(t, urn2141OnlyTestCases, RFC2141Only)
}

func TestParseUrnLex2141Only(t *testing.T) {
	exec(t, urnlexTestCases, RFC2141Only)
}

func TestSCIMOnly(t *testing.T) {
	exec(t, scimOnlyTestCases, RFC7643Only)
}

func TestParse8141Only(t *testing.T) {
	exec(t, rfc8141TestCases, RFC8141Only)
}
