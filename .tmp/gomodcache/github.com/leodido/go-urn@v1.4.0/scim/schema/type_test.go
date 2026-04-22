package scimschema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTypeFromString(t *testing.T) {
	uns := TypeFromString("wrong")
	require.Equal(t, Unsupported, uns)
	require.Empty(t, uns.String())

	schemas := TypeFromString("schemas")
	require.Equal(t, Schemas, schemas)
	require.Equal(t, "schemas", schemas.String())

	api := TypeFromString("api")
	require.Equal(t, API, api)
	require.Equal(t, "api", api.String())

	param := TypeFromString("param")
	require.Equal(t, Param, param)
	require.Equal(t, "param", param.String())
}
