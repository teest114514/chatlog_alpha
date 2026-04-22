package nested

// Pet defines the user's fury friend.
type Pet struct {
	// Name of the animal.
	Name string `json:"name" jsonschema:"title=Name"`
}

// Pets is a collection of Pet objects.
type Pets []*Pet

// NamedPets is a map of animal names to pets.
type NamedPets map[string]*Pet

type (
	// Plant represents the plants the user might have and serves as a test
	// of structs inside a `type` set.
	Plant struct {
		Variant string `json:"variant" jsonschema:"title=Variant"` // This comment will be used
		// Multicellular is true if the plant is multicellular
		Multicellular bool `json:"multicellular,omitempty" jsonschema:"title=Multicellular"` // This comment will be ignored
	}
)
