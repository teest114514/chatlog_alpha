package urn

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURN8141JSONMarshaling(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		// Marshal
		expected := URN8141{
			URN: &URN{
				ID:         "lex",
				SS:         "it:ministero.giustizia:decreto:1992-07-24;358~art5",
				rComponent: "r",
				qComponent: "q%D0",
				fComponent: "frag",
			},
		}
		bytes, err := json.Marshal(expected)
		if !assert.NoError(t, err) {
			return
		}
		require.Equal(t, `"urn:lex:it:ministero.giustizia:decreto:1992-07-24;358~art5?+r?=q%D0#frag"`, string(bytes))
		// Unmarshal
		var got URN8141
		err = json.Unmarshal(bytes, &got)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, expected.String(), got.String())
		assert.Equal(t, expected.fComponent, got.FComponent())
		assert.Equal(t, expected.qComponent, got.QComponent())
		assert.Equal(t, expected.rComponent, got.RComponent())
	})

	t.Run("invalid URN", func(t *testing.T) {
		var actual URN8141
		err := json.Unmarshal([]byte(`"not a URN"`), &actual)
		assert.EqualError(t, err, "invalid URN per RFC 8141: not a URN")
	})

	t.Run("empty", func(t *testing.T) {
		var actual URN8141
		err := actual.UnmarshalJSON(nil)
		assert.EqualError(t, err, "unexpected end of JSON input")
	})
}
