package examples

import (
	"github.com/invopop/jsonschema/examples/nested"
)

// User is used as a base to provide tests for comments.
// Don't forget to checkout the nested path.
type User struct {
	// Unique sequential identifier.
	ID int `json:"id" jsonschema:"required"`
	// This comment will be ignored
	Name    string         `json:"name" jsonschema:"required,minLength=1,maxLength=20,pattern=.*,description=this is a property,title=the name,example=joe,example=lucy,default=alex"`
	Friends []int          `json:"friends,omitempty" jsonschema_description:"list of IDs, omitted when empty"`
	Tags    map[string]any `json:"tags,omitempty"`

	// An array of pets the user cares for.
	Pets nested.Pets `json:"pets"`

	// Set of animal names to pets
	NamedPets nested.NamedPets `json:"named_pets"`

	// Set of plants that the user likes
	Plants []*nested.Plant `json:"plants" jsonschema:"title=Plants"`
}
