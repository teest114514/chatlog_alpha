package jsonschema_test

import (
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
)

func TestID(t *testing.T) {
	base := "https://invopop.com/schema"
	id := jsonschema.ID(base)

	assert.Equal(t, base, id.String())

	id = id.Add("user")
	assert.EqualValues(t, base+"/user", id)

	id = id.Anchor("Name")
	assert.EqualValues(t, base+"/user#Name", id)

	id = id.Anchor("Title")
	assert.EqualValues(t, base+"/user#Title", id)

	id = id.Def("Name")
	assert.EqualValues(t, base+"/user#/$defs/Name", id)
}

func TestIDValidation(t *testing.T) {
	id := jsonschema.ID("https://invopop.com/schema/user")
	assert.NoError(t, id.Validate())

	id = "https://encoding/json"
	if assert.Error(t, id.Validate()) {
		assert.Contains(t, id.Validate().Error(), "hostname does not look valid")
	}

	id = "time"
	if assert.Error(t, id.Validate()) {
		assert.Contains(t, id.Validate().Error(), "hostname")
	}

	id = "http://invopop.com"
	if assert.Error(t, id.Validate()) {
		assert.Contains(t, id.Validate().Error(), "path")
	}

	id = "foor://invopop.com/schema/user"
	if assert.Error(t, id.Validate()) {
		assert.Contains(t, id.Validate().Error(), "schema")
	}

	id = "invopop.com\n/test"
	if assert.Error(t, id.Validate()) {
		assert.Contains(t, id.Validate().Error(), "invalid URL")
	}
}
