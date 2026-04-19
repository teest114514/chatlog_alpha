package plist

import (
	"reflect"
	"testing"
	"time"
)

func BenchmarkStructMarshal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := &Encoder{}
		e.marshal(reflect.ValueOf(plistValueTreeRawData))
	}
}

func BenchmarkMapMarshal(b *testing.B) {
	data := map[string]interface{}{
		"intarray": []interface{}{
			int(1),
			int8(8),
			int16(16),
			int32(32),
			int64(64),
			uint(2),
			uint8(9),
			uint16(17),
			uint32(33),
			uint64(65),
		},
		"floats": []interface{}{
			float32(32.0),
			float64(64.0),
		},
		"booleans": []bool{
			true,
			false,
		},
		"strings": []string{
			"Hello, ASCII",
			"Hello, 世界",
		},
		"data": []byte{1, 2, 3, 4},
		"date": time.Date(2013, 11, 27, 0, 34, 0, 0, time.UTC),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := &Encoder{}
		e.marshal(reflect.ValueOf(data))
	}
}

func TestInvalidMarshal(t *testing.T) {
	tests := []struct {
		Name  string
		Thing interface{}
	}{
		{"Function", func() {}},
		{"Nil", nil},
		{"Map with integer keys", map[int]string{1: "hi"}},
		{"Channel", make(chan int)},
	}

	for _, v := range tests {
		subtest(t, v.Name, func(t *testing.T) {
			data, err := Marshal(v.Thing, OpenStepFormat)
			if err == nil {
				t.Fatalf("expected error; got plist data: %x", data)
			} else {
				t.Log(err)
			}
		})
	}
}

type Cat struct{}

func (c *Cat) MarshalPlist() (interface{}, error) {
	return "cat", nil
}

func TestInterfaceMarshal(t *testing.T) {
	var c Cat
	b, err := Marshal(&c, XMLFormat)
	if err != nil {
		t.Log(err)
	} else if len(b) == 0 {
		t.Log("expect non-zero data")
	}
}

func TestInterfaceFieldMarshal(t *testing.T) {
	type X struct {
		C interface{} // C's type does not implement Marshaler
	}
	x := &X{
		C: &Cat{}, // C's value implements Marshaler
	}

	b, err := Marshal(x, XMLFormat)
	if err != nil {
		t.Log(err)
	} else if len(b) == 0 {
		t.Log("expect non-zero data")
	}
}
