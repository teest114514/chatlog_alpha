package urn_test

import (
	"fmt"

	"github.com/leodido/go-urn"
)

func ExampleParse() {
	var uid = "URN:foo:a123,456"

	if u, ok := urn.Parse([]byte(uid)); ok {
		fmt.Println(u.ID)
		fmt.Println(u.SS)
		fmt.Println(u.SCIM())
	}

	// Output: foo
	// a123,456
	// <nil>
}

func ExampleURN_MarshalJSON() {
	var uid = "URN:foo:a123,456"

	if u, ok := urn.Parse([]byte(uid)); ok {
		json, err := u.MarshalJSON()
		if err != nil {
			panic("invalid urn")
		}
		fmt.Println(string(json))
	}

	// Output: "URN:foo:a123,456"
}

func ExampleURN_Equal() {
	var uid1 = "URN:foo:a123,456"
	var uid2 = "URN:FOO:a123,456"

	u1, ok := urn.Parse([]byte(uid1))
	if !ok {
		panic("invalid urn")
	}

	u2, ok := urn.Parse([]byte(uid2))
	if !ok {
		panic("invalid urn")
	}

	if u1.Equal(u2) {
		fmt.Printf("%s equals %s", u1.String(), u2.String())
	}

	// Output: URN:foo:a123,456 equals URN:FOO:a123,456
}

func ExampleParse_scim() {
	input := "urn:ietf:params:scim:api:messages:2.0:ListResponse"

	u, ok := urn.Parse([]byte(input), urn.WithParsingMode(urn.RFC7643Only))
	if !ok {
		panic("invalid SCIM urn")
	}
	data, err := u.MarshalJSON()
	if err != nil {
		panic("couldn't marshal")
	}
	fmt.Println(string(data))
	fmt.Println(u.IsSCIM())
	scim := u.SCIM()
	fmt.Println(scim.Type.String())
	fmt.Println(scim.Name)
	fmt.Println(scim.Other)

	// Output:
	// "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	// true
	// api
	// messages
	// 2.0:ListResponse
}
