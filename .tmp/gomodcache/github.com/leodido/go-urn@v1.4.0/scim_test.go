package urn

import (
	"encoding/json"
	"fmt"
	"testing"

	scimschema "github.com/leodido/go-urn/scim/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSCIMJSONMarshaling(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		// Marshal
		exp := SCIM{Type: scimschema.Schemas, Name: "core", Other: "extension:enterprise:2.0:User"}
		mar, err := json.Marshal(exp)
		require.NoError(t, err)
		require.Equal(t, `"urn:ietf:params:scim:schemas:core:extension:enterprise:2.0:User"`, string(mar))

		// Unmarshal
		var act SCIM
		err = json.Unmarshal(mar, &act)
		require.NoError(t, err)
		exp.pos = 34
		require.Equal(t, exp, act)
	})

	t.Run("unmarshal", func(t *testing.T) {
		exp := `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`
		var got SCIM
		err := json.Unmarshal([]byte(fmt.Sprintf(`"%s"`, exp)), &got)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, exp, got.String())
		assert.Equal(t, SCIM{
			Type:  scimschema.Schemas,
			Name:  "extension",
			Other: "enterprise:2.0:User",
			pos:   39,
		}, got)
	})

	t.Run("unmarshal without the <other> part", func(t *testing.T) {
		exp := `urn:ietf:params:scim:schemas:core`
		var got SCIM
		err := json.Unmarshal([]byte(fmt.Sprintf(`"%s"`, exp)), &got)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, exp, got.String())
		assert.Equal(t, SCIM{
			Type: scimschema.Schemas,
			Name: "core",
			pos:  29,
		}, got)
	})

	t.Run("invalid URN", func(t *testing.T) {
		var actual SCIM
		err := json.Unmarshal([]byte(`"not a URN"`), &actual)
		assert.EqualError(t, err, "invalid SCIM URN: not a URN")
	})

	t.Run("empty", func(t *testing.T) {
		var actual SCIM
		err := actual.UnmarshalJSON(nil)
		assert.EqualError(t, err, "unexpected end of JSON input")
	})
}
