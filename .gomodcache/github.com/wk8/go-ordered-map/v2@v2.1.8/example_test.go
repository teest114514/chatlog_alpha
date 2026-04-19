package orderedmap_test

import (
	"encoding/json"
	"fmt"

	"github.com/wk8/go-ordered-map/v2"
)

func Example() {
	om := orderedmap.New[string, string](3)

	om.Set("foo", "bar")
	om.Set("bar", "baz")
	om.Set("coucou", "toi")

	fmt.Println("## Get operations: ##")
	fmt.Println(om.Get("foo"))
	fmt.Println(om.Get("i dont exist"))
	fmt.Println(om.Value("coucou"))

	fmt.Println("## Iterating over pairs from oldest to newest: ##")
	for pair := om.Oldest(); pair != nil; pair = pair.Next() {
		fmt.Printf("%s => %s\n", pair.Key, pair.Value)
	}

	fmt.Println("## Iterating over the 2 newest pairs: ##")
	i := 0
	for pair := om.Newest(); pair != nil; pair = pair.Prev() {
		fmt.Printf("%s => %s\n", pair.Key, pair.Value)
		i++
		if i >= 2 {
			break
		}
	}

	fmt.Println("## JSON serialization: ##")
	data, err := json.Marshal(om)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))

	fmt.Println("## JSON deserialization: ##")
	om2 := orderedmap.New[string, string]()
	if err := json.Unmarshal(data, &om2); err != nil {
		panic(err)
	}
	fmt.Println(om2.Oldest().Key)

	// Output:
	// ## Get operations: ##
	// bar true
	//  false
	// toi
	// ## Iterating over pairs from oldest to newest: ##
	// foo => bar
	// bar => baz
	// coucou => toi
	// ## Iterating over the 2 newest pairs: ##
	// coucou => toi
	// bar => baz
	// ## JSON serialization: ##
	// {"foo":"bar","bar":"baz","coucou":"toi"}
	// ## JSON deserialization: ##
	// foo
}
