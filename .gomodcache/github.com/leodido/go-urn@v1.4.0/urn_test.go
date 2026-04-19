package urn

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultPrefixWhenString(t *testing.T) {
	u := &URN{
		ID: "pippo",
		SS: "pluto",
	}

	assert.Equal(t, "urn:pippo:pluto", u.String())
}

func TestParseSignature(t *testing.T) {
	urn, ok := Parse([]byte(``))
	assert.Nil(t, urn)
	assert.False(t, ok)
}

func TestJSONMarshaling(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		// Marshal
		expected := URN{ID: "oid", SS: "1.2.3.4"}
		bytes, err := json.Marshal(expected)
		if !assert.NoError(t, err) {
			return
		}
		// Unmarshal
		var actual URN
		err = json.Unmarshal(bytes, &actual)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, expected.String(), actual.String())
	})

	t.Run("invalid URN", func(t *testing.T) {
		var actual URN
		err := json.Unmarshal([]byte(`"not a URN"`), &actual)
		assert.EqualError(t, err, "invalid URN: not a URN")
	})

	t.Run("empty", func(t *testing.T) {
		var actual URN
		err := actual.UnmarshalJSON(nil)
		assert.EqualError(t, err, "unexpected end of JSON input")
	})
}
