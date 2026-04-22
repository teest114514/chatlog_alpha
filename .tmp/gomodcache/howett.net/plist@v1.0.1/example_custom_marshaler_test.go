package plist_test

import (
	"encoding/base64"
	"fmt"

	"howett.net/plist"
)

type Base64String string

func (e Base64String) MarshalPlist() (interface{}, error) {
	return base64.StdEncoding.EncodeToString([]byte(e)), nil
}

func (e *Base64String) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var b64 string
	if err := unmarshal(&b64); err != nil {
		return err
	}

	bytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}

	*e = Base64String(bytes)
	return nil
}

func Example() {
	s := Base64String("Dustin")

	data, err := plist.Marshal(&s, plist.OpenStepFormat)
	if err != nil {
		panic(err)
	}

	fmt.Println("Property List:", string(data))

	var decoded Base64String
	_, err = plist.Unmarshal(data, &decoded)
	if err != nil {
		panic(err)
	}

	fmt.Println("Raw Data:", string(decoded))

	// Output:
	// Property List: RHVzdGlu
	// Raw Data: Dustin
}
