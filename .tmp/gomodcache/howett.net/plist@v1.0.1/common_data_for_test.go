package plist

import (
	"errors"
	"math"
	"reflect"
	"time"
)

type TestData struct {
	Name        string
	Value       interface{}
	DecodeValue interface{} // used when the document cannot encode parts of Value
	Documents   map[int][]byte
	SkipDecode  map[int]bool
	SkipEncode  map[int]bool
}

type SparseBundleHeader struct {
	InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion"`
	BandSize              uint64 `plist:"band-size"`
	BackingStoreVersion   int    `plist:"bundle-backingstore-version"`
	DiskImageBundleType   string `plist:"diskimage-bundle-type"`
	Size                  uint64 `plist:"size"`
}

type EmbedA struct {
	EmbedC
	EmbedB EmbedB
	FieldA string
}

type EmbedB struct {
	FieldB string
	*EmbedC
}

type EmbedC struct {
	FieldA1 string `plist:"FieldA"`
	FieldA2 string
	FieldB  string
	FieldC  string
}

type TextMarshalingBool struct {
	b bool
}

func (b TextMarshalingBool) MarshalText() ([]byte, error) {
	if b.b {
		return []byte("truthful"), nil
	}
	return []byte("non-factual"), nil
}

func (b *TextMarshalingBool) UnmarshalText(text []byte) error {
	if string(text) == "truthful" {
		b.b = true
	}
	return nil
}

type TextMarshalingBoolViaPointer struct {
	b bool
}

func (b *TextMarshalingBoolViaPointer) MarshalText() ([]byte, error) {
	if b.b {
		return []byte("plausible"), nil
	}
	return []byte("unimaginable"), nil
}

func (b *TextMarshalingBoolViaPointer) UnmarshalText(text []byte) error {
	if string(text) == "plausible" {
		b.b = true
	}
	return nil
}

type ArrayThatSerializesAsOneObject struct {
	values []uint64
}

func (f ArrayThatSerializesAsOneObject) MarshalPlist() (interface{}, error) {
	if len(f.values) == 1 {
		return f.values[0], nil
	}
	return f.values, nil
}

func (f *ArrayThatSerializesAsOneObject) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var ui uint64
	if err := unmarshal(&ui); err == nil {
		f.values = []uint64{ui}
		return nil
	}

	return unmarshal(&f.values)
}

type PlistMarshalingBoolByPointer struct {
	b bool
}

func (b *PlistMarshalingBoolByPointer) MarshalPlist() (interface{}, error) {
	if b.b {
		return int64(-1), nil
	}
	return int64(-2), nil
}

func (b *PlistMarshalingBoolByPointer) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var val int64
	err := unmarshal(&val)
	if err != nil {
		return err
	}

	b.b = val == -1
	return nil
}

type BothMarshaler struct{}

func (b *BothMarshaler) MarshalPlist() (interface{}, error) {
	return map[string]string{"a": "b"}, nil
}

func (b *BothMarshaler) MarshalText() ([]byte, error) {
	return []byte("shouldn't see this"), nil
}

type BothUnmarshaler struct {
	Blah int64 `plist:"blah,omitempty"`
}

func (b *BothUnmarshaler) UnmarshalPlist(unmarshal func(interface{}) error) error {
	// no error
	return nil
}

func (b *BothUnmarshaler) UnmarshalText(text []byte) error {
	return errors.New("shouldn't hit this")
}

var xmlPreamble = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
`

var tests = []TestData{
	{
		Name:  "String",
		Value: "Hello",
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`Hello`),
			GNUStepFormat:  []byte(`Hello`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><string>Hello</string></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 85, 72, 101, 108, 108, 111, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14},
		},
	},
	{
		Name:  "String containing apostrophe",
		Value: "'",
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`"'"`),
			GNUStepFormat:  []byte(`"'"`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><string>&#39;</string></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 81, 39, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10},
		},
	},
	{
		Name: "Basic Structure",
		Value: struct {
			Name string
		}{
			Name: "Dustin",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{Name=Dustin;}`),
			GNUStepFormat:  []byte(`{Name=Dustin;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>Name</key><string>Dustin</string></dict></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 209, 1, 2, 84, 78, 97, 109, 101, 86, 68, 117, 115, 116, 105, 110, 8, 11, 16, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23},
		},
	},
	{
		Name: "Basic Structure with non-exported fields",
		Value: struct {
			Name string
			age  int
		}{
			Name: "Dustin",
			age:  24,
		},
		DecodeValue: struct {
			Name string
			age  int
		}{
			Name: "Dustin",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{Name=Dustin;}`),
			GNUStepFormat:  []byte(`{Name=Dustin;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>Name</key><string>Dustin</string></dict></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 209, 1, 2, 84, 78, 97, 109, 101, 86, 68, 117, 115, 116, 105, 110, 8, 11, 16, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23},
		},
	},
	{
		Name: "Basic Structure with omitted fields",
		Value: struct {
			Name string
			Age  int `plist:"-"`
		}{
			Name: "Dustin",
			Age:  24,
		},
		DecodeValue: struct {
			Name string
			Age  int `plist:"-"`
		}{
			Name: "Dustin",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{Name=Dustin;}`),
			GNUStepFormat:  []byte(`{Name=Dustin;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>Name</key><string>Dustin</string></dict></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 209, 1, 2, 84, 78, 97, 109, 101, 86, 68, 117, 115, 116, 105, 110, 8, 11, 16, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23},
		},
	},
	{
		Name: "Basic Structure with empty omitempty fields",
		Value: struct {
			Name      string
			Age       int     `plist:"age,omitempty"`
			Slice     []int   `plist:",omitempty"`
			Bool      bool    `plist:",omitempty"`
			Uint      uint    `plist:",omitempty"`
			Float32   float32 `plist:",omitempty"`
			Float64   float64 `plist:",omitempty"`
			Stringptr *string `plist:",omitempty"`
			Notempty  uint    `plist:",omitempty"`
		}{
			Name:     "Dustin",
			Notempty: 10,
		},
		DecodeValue: struct {
			Name      string
			Age       int     `plist:"age,omitempty"`
			Slice     []int   `plist:",omitempty"`
			Bool      bool    `plist:",omitempty"`
			Uint      uint    `plist:",omitempty"`
			Float32   float32 `plist:",omitempty"`
			Float64   float64 `plist:",omitempty"`
			Stringptr *string `plist:",omitempty"`
			Notempty  uint    `plist:",omitempty"`
		}{
			Name:     "Dustin",
			Notempty: 10,
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{Name=Dustin;Notempty=10;}`),
			GNUStepFormat:  []byte(`{Name=Dustin;Notempty=<*I10>;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>Name</key><string>Dustin</string><key>Notempty</key><integer>10</integer></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd2, 0x1, 0x2, 0x3, 0x4, 0x54, 0x4e, 0x61, 0x6d, 0x65, 0x58, 0x4e, 0x6f, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x56, 0x44, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x10, 0xa, 0x8, 0xd, 0x12, 0x1b, 0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x24},
		},
	},
	{
		Name: "Structure with Anonymous Embeds",
		Value: EmbedA{
			EmbedC: EmbedC{
				FieldA1: "",
				FieldA2: "",
				FieldB:  "A.C.B",
				FieldC:  "A.C.C",
			},
			EmbedB: EmbedB{
				FieldB: "A.B.B",
				EmbedC: &EmbedC{
					FieldA1: "A.B.C.A1",
					FieldA2: "A.B.C.A2",
					FieldB:  "", // Shadowed by A.B.B
					FieldC:  "A.B.C.C",
				},
			},
			FieldA: "A.A",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{EmbedB={FieldA="A.B.C.A1";FieldA2="A.B.C.A2";FieldB="A.B.B";FieldC="A.B.C.C";};FieldA="A.A";FieldA2="";FieldB="A.C.B";FieldC="A.C.C";}`),
			GNUStepFormat:  []byte(`{EmbedB={FieldA=A.B.C.A1;FieldA2=A.B.C.A2;FieldB=A.B.B;FieldC=A.B.C.C;};FieldA=A.A;FieldA2="";FieldB=A.C.B;FieldC=A.C.C;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>EmbedB</key><dict><key>FieldA</key><string>A.B.C.A1</string><key>FieldA2</key><string>A.B.C.A2</string><key>FieldB</key><string>A.B.B</string><key>FieldC</key><string>A.B.C.C</string></dict><key>FieldA</key><string>A.A</string><key>FieldA2</key><string/><key>FieldB</key><string>A.C.B</string><key>FieldC</key><string>A.C.C</string></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd5, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xb, 0xc, 0xd, 0xe, 0x56, 0x45, 0x6d, 0x62, 0x65, 0x64, 0x42, 0x56, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x41, 0x57, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x41, 0x32, 0x56, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x42, 0x56, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x43, 0xd4, 0x2, 0x3, 0x4, 0x5, 0x7, 0x8, 0x9, 0xa, 0x58, 0x41, 0x2e, 0x42, 0x2e, 0x43, 0x2e, 0x41, 0x31, 0x58, 0x41, 0x2e, 0x42, 0x2e, 0x43, 0x2e, 0x41, 0x32, 0x55, 0x41, 0x2e, 0x42, 0x2e, 0x42, 0x57, 0x41, 0x2e, 0x42, 0x2e, 0x43, 0x2e, 0x43, 0x53, 0x41, 0x2e, 0x41, 0x50, 0x55, 0x41, 0x2e, 0x43, 0x2e, 0x42, 0x55, 0x41, 0x2e, 0x43, 0x2e, 0x43, 0x8, 0x13, 0x1a, 0x21, 0x29, 0x30, 0x37, 0x40, 0x49, 0x52, 0x58, 0x60, 0x64, 0x65, 0x6b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x71},
		},
	},
	{
		Name:  "Arbitrary Byte Data",
		Value: []byte{'h', 'e', 'l', 'l', 'o'},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`<68656c6c 6f>`),
			GNUStepFormat:  []byte(`<[aGVsbG8=]>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><data>aGVsbG8=</data></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 69, 104, 101, 108, 108, 111, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14},
		},
		// We are not encoding base64 for GNUstep yet
		SkipEncode: map[int]bool{GNUStepFormat: true},
	},
	{
		Name:  "Arbitrary Byte Data (array)",
		Value: [5]byte{'h', 'e', 'l', 'l', 'o'},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`<68656c6c 6f>`),
			GNUStepFormat:  []byte(`<[aGVsbG8=]>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><data>aGVsbG8=</data></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 69, 104, 101, 108, 108, 111, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14},
		},
		// We are not encoding base64 for GNUstep yet
		SkipEncode: map[int]bool{GNUStepFormat: true},
	},
	{
		Name:  "Arbitrary Integer Slice",
		Value: []int{'h', 'e', 'l', 'l', 'o'},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(104,101,108,108,111,)`),
			GNUStepFormat:  []byte(`(<*I104>,<*I101>,<*I108>,<*I108>,<*I111>,)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><integer>104</integer><integer>101</integer><integer>108</integer><integer>108</integer><integer>111</integer></array></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 165, 1, 2, 3, 3, 4, 16, 104, 16, 101, 16, 108, 16, 111, 8, 14, 16, 18, 20, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22},
		},
	},
	{
		Name:  "Arbitrary Integer Array",
		Value: [3]int{'h', 'i', '!'},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(104,105,33,)`),
			GNUStepFormat:  []byte(`(<*I104>,<*I105>,<*I33>,)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><integer>104</integer><integer>105</integer><integer>33</integer></array></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 163, 1, 2, 3, 16, 104, 16, 105, 16, 33, 8, 12, 14, 16, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18},
		},
	},
	{
		Name:  "Unsigned Integers of Increasing Size",
		Value: []uint64{0xff, 0xfff, 0xffff, 0xfffff, 0xffffff, 0xfffffff, 0xffffffff, 0x7fffffffffffffff, 0xdeadbeeffacecafe},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(255,4095,65535,1048575,16777215,268435455,4294967295,9223372036854775807,16045690985305262846,)`),
			GNUStepFormat:  []byte(`(<*I255>,<*I4095>,<*I65535>,<*I1048575>,<*I16777215>,<*I268435455>,<*I4294967295>,<*I9223372036854775807>,<*I16045690985305262846>,)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><integer>255</integer><integer>4095</integer><integer>65535</integer><integer>1048575</integer><integer>16777215</integer><integer>268435455</integer><integer>4294967295</integer><integer>9223372036854775807</integer><integer>16045690985305262846</integer></array></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xa9, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0xff, 0x11, 0x0f, 0xff, 0x11, 0xff, 0xff, 0x12, 0x00, 0x0f, 0xff, 0xff, 0x12, 0x00, 0xff, 0xff, 0xff, 0x12, 0x0f, 0xff, 0xff, 0xff, 0x12, 0xff, 0xff, 0xff, 0xff, 0x13, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xca, 0xfe, 0x08, 0x12, 0x14, 0x17, 0x1a, 0x1f, 0x24, 0x29, 0x2e, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48},
		},
	},
	{
		Name:  "Hexadecimal Integers",
		Value: []int{'h', 'e', 'x', 'i', 'n', 't', -42},
		Documents: map[int][]byte{
			XMLFormat: []byte(xmlPreamble + `<plist version="1.0"><array><integer>0x68</integer><integer>0X65</integer><integer>0x78</integer><integer>0X69</integer><integer>0x6e</integer><integer>0X74</integer><integer>-0x2a</integer></array></plist>`),
		},
		SkipEncode: map[int]bool{XMLFormat: true},
	},
	{
		Name:  "Octal Integers (treated as Decimal)",
		Value: []int{'o', 'c', 't', 'i', 'n', 't', -42},
		Documents: map[int][]byte{
			XMLFormat: []byte(xmlPreamble + `<plist version="1.0"><array><integer>0111</integer><integer>099</integer><integer>0116</integer><integer>0105</integer><integer>0110</integer><integer>0116</integer><integer>-042</integer></array></plist>`),
		},
		SkipEncode: map[int]bool{XMLFormat: true},
	},
	{
		Name:  "Floats of Increasing Bitness",
		Value: []interface{}{float32(math.MaxFloat32), float64(math.MaxFloat64)},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(3.4028234663852886e+38,1.7976931348623157e+308,)`),
			GNUStepFormat:  []byte(`(<*R3.4028234663852886e+38>,<*R1.7976931348623157e+308>,)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><real>3.4028234663852886e+38</real><real>1.7976931348623157e+308</real></array></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 162, 1, 2, 34, 127, 127, 255, 255, 35, 127, 239, 255, 255, 255, 255, 255, 255, 8, 11, 16, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25},
		},
		// We can't store varying bitness in text formats.
		SkipDecode: map[int]bool{XMLFormat: true, OpenStepFormat: true, GNUStepFormat: true},
	},
	{
		Name:  "Boolean True",
		Value: true,
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`1`),
			GNUStepFormat:  []byte(`<*BY>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><true/></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 9, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9},
		},
	},
	{
		Name:  "Floating-Point Value",
		Value: 3.14159265358979323846264338327950288,
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`3.141592653589793`),
			GNUStepFormat:  []byte(`<*R3.141592653589793>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><real>3.141592653589793</real></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 35, 64, 9, 33, 251, 84, 68, 45, 24, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},
		},
	},
	{
		Name: "Map (containing arbitrary types)",
		Value: map[string]interface{}{
			"float":  1.0,
			"uint64": uint64(1),
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{float=1;uint64=1;}`),
			GNUStepFormat:  []byte(`{float=<*R1>;uint64=<*I1>;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>float</key><real>1</real><key>uint64</key><integer>1</integer></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd2, 0x1, 0x2, 0x3, 0x4, 0x55, 0x66, 0x6c, 0x6f, 0x61, 0x74, 0x56, 0x75, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x23, 0x3f, 0xf0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x1, 0x8, 0xd, 0x13, 0x1a, 0x23, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x25},
		},
		// Can't lax decode strings into numerics in a map (we don't know they want numbers)
		SkipDecode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name: "Map (containing all variations of all types)",
		Value: interface{}(map[string]interface{}{
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
		}),
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{booleans=(1,0,);data=<01020304>;date="2013-11-27 00:34:00 +0000";floats=(32,64,);intarray=(1,8,16,32,64,2,9,17,33,65,);strings=("Hello, ASCII","Hello, \U4e16\U754c",);}`),
			GNUStepFormat:  []byte(`{booleans=(<*BY>,<*BN>,);data=<01020304>;date=<*D2013-11-27 00:34:00 +0000>;floats=(<*R32>,<*R64>,);intarray=(<*I1>,<*I8>,<*I16>,<*I32>,<*I64>,<*I2>,<*I9>,<*I17>,<*I33>,<*I65>,);strings=("Hello, ASCII","Hello, \U4e16\U754c",);}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>booleans</key><array><true/><false/></array><key>data</key><data>AQIDBA==</data><key>date</key><date>2013-11-27T00:34:00Z</date><key>floats</key><array><real>32</real><real>64</real></array><key>intarray</key><array><integer>1</integer><integer>8</integer><integer>16</integer><integer>32</integer><integer>64</integer><integer>2</integer><integer>9</integer><integer>17</integer><integer>33</integer><integer>65</integer></array><key>strings</key><array><string>Hello, ASCII</string><string>Hello, 世界</string></array></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd6, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0xa, 0xb, 0xc, 0xf, 0x1a, 0x58, 0x62, 0x6f, 0x6f, 0x6c, 0x65, 0x61, 0x6e, 0x73, 0x54, 0x64, 0x61, 0x74, 0x61, 0x54, 0x64, 0x61, 0x74, 0x65, 0x56, 0x66, 0x6c, 0x6f, 0x61, 0x74, 0x73, 0x58, 0x69, 0x6e, 0x74, 0x61, 0x72, 0x72, 0x61, 0x79, 0x57, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0xa2, 0x8, 0x9, 0x9, 0x8, 0x44, 0x1, 0x2, 0x3, 0x4, 0x33, 0x41, 0xb8, 0x45, 0x75, 0x78, 0x0, 0x0, 0x0, 0xa2, 0xd, 0xe, 0x22, 0x42, 0x0, 0x0, 0x0, 0x23, 0x40, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xaa, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x10, 0x1, 0x10, 0x8, 0x10, 0x10, 0x10, 0x20, 0x10, 0x40, 0x10, 0x2, 0x10, 0x9, 0x10, 0x11, 0x10, 0x21, 0x10, 0x41, 0xa2, 0x1b, 0x1c, 0x5c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x41, 0x53, 0x43, 0x49, 0x49, 0x69, 0x0, 0x48, 0x0, 0x65, 0x0, 0x6c, 0x0, 0x6c, 0x0, 0x6f, 0x0, 0x2c, 0x0, 0x20, 0x4e, 0x16, 0x75, 0x4c, 0x8, 0x15, 0x1e, 0x23, 0x28, 0x2f, 0x38, 0x40, 0x43, 0x44, 0x45, 0x4a, 0x53, 0x56, 0x5b, 0x64, 0x6f, 0x71, 0x73, 0x75, 0x77, 0x79, 0x7b, 0x7d, 0x7f, 0x81, 0x83, 0x86, 0x93, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6},
		},
		SkipDecode: map[int]bool{OpenStepFormat: true, GNUStepFormat: true, XMLFormat: true, BinaryFormat: true},
	},
	{
		Name: "Map (containing nil)",
		Value: map[string]interface{}{
			"float":  1.5,
			"uint64": uint64(1),
			"nil":    nil,
		},
		DecodeValue: map[string]interface{}{
			"float":  1.5,
			"uint64": uint64(1),
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{float=1.5;uint64=1;}`),
			GNUStepFormat:  []byte(`{float=<*R1.5>;uint64=<*I1>;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>float</key><real>1.5</real><key>uint64</key><integer>1</integer></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd2, 0x1, 0x2, 0x3, 0x4, 0x55, 0x66, 0x6c, 0x6f, 0x61, 0x74, 0x56, 0x75, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x23, 0x3f, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x1, 0x8, 0xd, 0x13, 0x1a, 0x23, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x25},
		},
		// Can't lax decode strings into numerics in a map (we don't know they want numbers)
		SkipDecode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name: "Pointer to structure with plist tags",
		Value: &SparseBundleHeader{
			InfoDictionaryVersion: "6.0",
			BandSize:              8388608,
			Size:                  4 * 1048576 * 1024 * 1024,
			DiskImageBundleType:   "com.apple.diskimage.sparsebundle",
			BackingStoreVersion:   1,
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{CFBundleInfoDictionaryVersion="6.0";"band-size"=8388608;"bundle-backingstore-version"=1;"diskimage-bundle-type"="com.apple.diskimage.sparsebundle";size=4398046511104;}`),
			GNUStepFormat:  []byte(`{CFBundleInfoDictionaryVersion=6.0;band-size=<*I8388608>;bundle-backingstore-version=<*I1>;diskimage-bundle-type=com.apple.diskimage.sparsebundle;size=<*I4398046511104>;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>CFBundleInfoDictionaryVersion</key><string>6.0</string><key>band-size</key><integer>8388608</integer><key>bundle-backingstore-version</key><integer>1</integer><key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string><key>size</key><integer>4398046511104</integer></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd5, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0x5f, 0x10, 0x1d, 0x43, 0x46, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x59, 0x62, 0x61, 0x6e, 0x64, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x5f, 0x10, 0x1b, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2d, 0x62, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2d, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x10, 0x15, 0x64, 0x69, 0x73, 0x6b, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2d, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x54, 0x73, 0x69, 0x7a, 0x65, 0x53, 0x36, 0x2e, 0x30, 0x12, 0x0, 0x80, 0x0, 0x0, 0x10, 0x1, 0x5f, 0x10, 0x20, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x64, 0x69, 0x73, 0x6b, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e, 0x73, 0x70, 0x61, 0x72, 0x73, 0x65, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x13, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x13, 0x33, 0x3d, 0x5b, 0x73, 0x78, 0x7c, 0x81, 0x83, 0xa6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xaf},
		},
		SkipDecode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name: "Array of byte arrays",
		Value: [][]byte{
			[]byte("Hello"),
			[]byte("World"),
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(<48656c6c 6f>,<576f726c 64>,)`),
			GNUStepFormat:  []byte(`(<48656c6c 6f>,<576f726c 64>,)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><data>SGVsbG8=</data><data>V29ybGQ=</data></array></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 162, 1, 2, 69, 72, 101, 108, 108, 111, 69, 87, 111, 114, 108, 100, 8, 11, 17, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23},
		},
	},
	{
		Name:  "Date",
		Value: time.Date(2013, 11, 27, 0, 34, 0, 0, time.UTC),
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`"2013-11-27 00:34:00 +0000"`),
			GNUStepFormat:  []byte(`<*D2013-11-27 00:34:00 +0000>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><date>2013-11-27T00:34:00Z</date></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 51, 65, 184, 69, 117, 120, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},
		},
	},
	{
		Name:  "Floating-Point NaN",
		Value: math.NaN(),
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`NaN`),
			GNUStepFormat:  []byte(`<*RNaN>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><real>nan</real></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 35, 127, 248, 0, 0, 0, 0, 0, 1, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},
		},
		SkipDecode: map[int]bool{OpenStepFormat: true, GNUStepFormat: true, XMLFormat: true, BinaryFormat: true},
	},
	{
		Name:  "Floating-Point Infinity",
		Value: math.Inf(1),
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`+Inf`),
			GNUStepFormat:  []byte(`<*R+Inf>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><real>inf</real></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 35, 127, 240, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},
		},
	},
	{
		Name:  "Floating-Point Negative Infinity",
		Value: math.Inf(-1),
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`-Inf`),
			GNUStepFormat:  []byte(`<*R-Inf>`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><real>-inf</real></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 35, 255, 240, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},
		},
	},
	{
		Name:  "UTF-8 string",
		Value: []string{"Hello, ASCII", "Hello, 世界"},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`("Hello, ASCII","Hello, \U4e16\U754c",)`),
			GNUStepFormat:  []byte(`("Hello, ASCII","Hello, \U4e16\U754c",)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><string>Hello, ASCII</string><string>Hello, 世界</string></array></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 162, 1, 2, 92, 72, 101, 108, 108, 111, 44, 32, 65, 83, 67, 73, 73, 105, 0, 72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 44, 0, 32, 78, 22, 117, 76, 8, 11, 24, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43},
		},
	},
	{
		Name:  "An array containing more than fifteen items",
		Value: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,)`),
			GNUStepFormat:  []byte(`(<*I1>,<*I2>,<*I3>,<*I4>,<*I5>,<*I6>,<*I7>,<*I8>,<*I9>,<*I10>,<*I11>,<*I12>,<*I13>,<*I14>,<*I15>,<*I16>,)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><integer>1</integer><integer>2</integer><integer>3</integer><integer>4</integer><integer>5</integer><integer>6</integer><integer>7</integer><integer>8</integer><integer>9</integer><integer>10</integer><integer>11</integer><integer>12</integer><integer>13</integer><integer>14</integer><integer>15</integer><integer>16</integer></array></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 175, 16, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 1, 16, 2, 16, 3, 16, 4, 16, 5, 16, 6, 16, 7, 16, 8, 16, 9, 16, 10, 16, 11, 16, 12, 16, 13, 16, 14, 16, 15, 16, 16, 8, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59},
		},
	},
	{
		Name:  "TextMarshaler/TextUnmarshaler",
		Value: TextMarshalingBool{true},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`truthful`),
			GNUStepFormat:  []byte(`truthful`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><string>truthful</string></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 88, 116, 114, 117, 116, 104, 102, 117, 108, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},
		},
		// We expect false here because the non-pointer version cannot mutate itself.
	},
	{
		Name:  "TextMarshaler/TextUnmarshaler via Pointer",
		Value: &TextMarshalingBoolViaPointer{false},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`unimaginable`),
			GNUStepFormat:  []byte(`unimaginable`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><string>unimaginable</string></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 92, 117, 110, 105, 109, 97, 103, 105, 110, 97, 98, 108, 101, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21},
		},
		DecodeValue: TextMarshalingBoolViaPointer{false},
	},
	{
		Name: "Duplicated Values",
		Value: []interface{}{
			"Hello",
			float32(32.0),
			float64(32.0),
			[]byte("data"),
			float32(64.0),
			float64(64.0),
			uint64(100),
			float32(32.0),
			time.Date(2013, 11, 27, 0, 34, 0, 0, time.UTC),
			float64(32.0),
			float32(64.0),
			float64(64.0),
			"Hello",
			[]byte("data"),
			uint64(100),
			time.Date(2013, 11, 27, 0, 34, 0, 0, time.UTC),
		},
		Documents: map[int][]byte{
			BinaryFormat: []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xaf, 0x10, 0x10, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x2, 0x8, 0x3, 0x5, 0x6, 0x1, 0x4, 0x7, 0x8, 0x55, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x22, 0x42, 0x0, 0x0, 0x0, 0x23, 0x40, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x44, 0x64, 0x61, 0x74, 0x61, 0x22, 0x42, 0x80, 0x0, 0x0, 0x23, 0x40, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x64, 0x33, 0x41, 0xb8, 0x45, 0x75, 0x78, 0x0, 0x0, 0x0, 0x8, 0x1b, 0x21, 0x26, 0x2f, 0x34, 0x39, 0x42, 0x44, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4d},
		},
	},
	{
		Name: "Funny Characters",
		Value: map[string]string{
			"\a":     "\b",
			"\v":     "\f",
			"\\":     "\"",
			"\t\r":   "\n",
			"\u00C8": "wat",
			"\u0100": "hundred",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{"\a"="\b";` + "\"\t\r\"=\"\n\";" + `"\v"="\f";"\\"="\"";"\310"=wat;"\U0100"=hundred;}`),
			GNUStepFormat:  []byte(`{"\a"="\b";` + "\"\t\r\"=\"\n\";" + `"\v"="\f";"\\"="\"";"\310"=wat;"\U0100"=hundred;}`),
		},
	},
	{
		Name:  "Signed Integers",
		Value: []int64{-1, -127, -255, -32767, -65535, -9223372036854775808},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(-1,-127,-255,-32767,-65535,-9223372036854775808,)`),
			GNUStepFormat:  []byte(`(<*I-1>,<*I-127>,<*I-255>,<*I-32767>,<*I-65535>,<*I-9223372036854775808>,)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><integer>-1</integer><integer>-127</integer><integer>-255</integer><integer>-32767</integer><integer>-65535</integer><integer>-9223372036854775808</integer></array></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xa6, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x13, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x0f, 0x18, 0x21, 0x2a, 0x33, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45},
		},
	},
	{
		Name: "A map with a blank key",
		Value: map[string]string{
			"": "Hello",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{""=Hello;}`),
			GNUStepFormat:  []byte(`{""=Hello;}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key/><string>Hello</string></dict></plist>`),
			BinaryFormat:   []byte{98, 112, 108, 105, 115, 116, 48, 48, 209, 1, 2, 80, 85, 72, 101, 108, 108, 111, 8, 11, 12, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18},
		},
	},
	{
		Name: "CF Keyed Archiver UIDs (interface{})",
		Value: []UID{
			0xff,
			0xffff,
			0xffffff,
			0xffffffff,
			0xffffffffff,
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`({CF$UID=255;},{CF$UID=65535;},{CF$UID=16777215;},{CF$UID=4294967295;},{CF$UID=1099511627775;},)`),
			GNUStepFormat:  []byte(`({CF$UID=<*I255>;},{CF$UID=<*I65535>;},{CF$UID=<*I16777215>;},{CF$UID=<*I4294967295>;},{CF$UID=<*I1099511627775>;},)`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><array><dict><key>CF$UID</key><integer>255</integer></dict><dict><key>CF$UID</key><integer>65535</integer></dict><dict><key>CF$UID</key><integer>16777215</integer></dict><dict><key>CF$UID</key><integer>4294967295</integer></dict><dict><key>CF$UID</key><integer>1099511627775</integer></dict></array></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xa5, 0x01, 0x02, 0x03, 0x04, 0x05, 0x80, 0xff, 0x81, 0xff, 0xff, 0x83, 0x00, 0xff, 0xff, 0xff, 0x83, 0xff, 0xff, 0xff, 0xff, 0x87, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x0e, 0x10, 0x13, 0x18, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26},
		},
	},
	{
		Name: "CF Keyed Archiver UID (struct)",
		Value: struct {
			U UID `plist:"identifier"`
		}{
			U: 1024,
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{identifier={CF$UID=1024;};}`),
			GNUStepFormat:  []byte(`{identifier={CF$UID=<*I1024>;};}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>identifier</key><dict><key>CF$UID</key><integer>1024</integer></dict></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd1, 0x01, 0x02, 0x5a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x81, 0x04, 0x00, 0x08, 0x0b, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19},
		},
	},
	{
		Name: "CF Keyed Archiver UID as Legacy Int",
		Value: struct {
			U UID `plist:"identifier"`
		}{
			U: 1024,
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{identifier={CF$UID=1024;};}`),
			GNUStepFormat:  []byte(`{identifier={CF$UID=<*I1024>;};}`),
			XMLFormat:      []byte(xmlPreamble + `<plist version="1.0"><dict><key>identifier</key><dict><key>CF$UID</key><integer>1024</integer></dict></dict></plist>`),
			BinaryFormat:   []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd1, 0x01, 0x02, 0x5a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x81, 0x04, 0x00, 0x08, 0x0b, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19},
		},
		DecodeValue: struct {
			U uint64 `plist:"identifier"`
		}{
			U: 1024,
		},
	},
	{
		Name: "Custom Marshaller/Unmarshaller by Value",
		Value: []ArrayThatSerializesAsOneObject{
			ArrayThatSerializesAsOneObject{[]uint64{100}},
			ArrayThatSerializesAsOneObject{[]uint64{2, 4, 6, 8}},
		},
		Documents: map[int][]byte{
			GNUStepFormat: []byte(`(<*I100>,(<*I2>,<*I4>,<*I6>,<*I8>,),)`),
		},
	},
	{
		Name:  "Custom Marshaller/Unmarshaller by Pointer",
		Value: &PlistMarshalingBoolByPointer{true},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`-1`),
			GNUStepFormat:  []byte(`<*I-1>`),
		},
	},
	{
		Name:  "Type implementing both Text and Plist Marshaler",
		Value: &BothMarshaler{},
		Documents: map[int][]byte{
			GNUStepFormat: []byte(`{a=b;}`),
		},
	},
	{
		Name:  "Type implementing both Text and Plist Unmarshaler",
		Value: &BothUnmarshaler{int64(1024)},
		Documents: map[int][]byte{
			GNUStepFormat: []byte(`{blah=<*I1024>;}`),
		},
		DecodeValue: &BothUnmarshaler{int64(0)},
	},
	{
		Name: "Comments",
		Value: struct {
			A, B, C int
			S, S2   string
		}{
			1, 2, 3,
			"/not/a/comment/", "/not*a/*comm*en/t",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{
				A=1 /* A is 1 because it is the first letter */;
				B=2; // B is 2 because comment-to-end-of-line.
				C=3;
				S = /not/a/comment/;
				S2 = /not*a/*comm*en/t;
			}`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name: "Escapes",
		Value: struct {
			W, A, B, V, F, T, R, N, Hex1, Unicode1, Unicode2, Octal1 string
		}{
			"w", "\a", "\b", "\v", "\f", "\t", "\r", "\n", "\u00ab", "\u00ac", "\u00ad", "\033",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`{
				W="\w";
				A="\a";
				B="\b";
				V="\v";
				F="\f";
				T="\t";
				R="\r";
				N="\n";
				Hex1="\xAB";
				Unicode1="\u00AC";
				Unicode2="\U00AD";
				Octal1="\033";
			}`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "Empty Strings in Arrays",
		Value: []string{"A"},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`(A,,,"",)`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "Empty Data",
		Value: []byte{},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`<>`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "UTF-8 with BOM",
		Value: "Hello",
		Documents: map[int][]byte{
			OpenStepFormat: []byte("\uFEFFHello"),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "UTF-16LE with BOM",
		Value: "Hello",
		Documents: map[int][]byte{
			OpenStepFormat: []byte{0xFF, 0xFE, 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0},
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "UTF-16BE with BOM",
		Value: "Hello",
		Documents: map[int][]byte{
			OpenStepFormat: []byte{0xFE, 0xFF, 0, 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o'},
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "UTF-16LE without BOM",
		Value: "Hello",
		Documents: map[int][]byte{
			OpenStepFormat: []byte{'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0},
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "UTF-16BE without BOM",
		Value: "Hello",
		Documents: map[int][]byte{
			OpenStepFormat: []byte{0, 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o'},
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "UTF-16BE with High Characters",
		Value: "Hello, 世界",
		Documents: map[int][]byte{
			OpenStepFormat: []byte{0, '"', 0, 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, ',', 0, ' ', 0x4E, 0x16, 0x75, 0x4C, 0, '"'},
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name: "Legacy Strings File Format (No Dictionary)",
		Value: map[string]string{
			"Key":  "Value",
			"Key2": "Value2",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`"Key" = "Value";
			"Key2" = "Value2";`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name: "Strings File Shortcut Format (No Values)",
		Value: map[string]string{
			"Key":  "Key",
			"Key2": "Key2",
		},
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`"Key";
			"Key2";`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "Various Truncated Escapes",
		Value: "\x01\x02\x03\x04\x057",
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`"\x1\u02\U003\4\0057"`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "Various Case-Insensitive Escapes",
		Value: "\u00AB\uCDEF",
		Documents: map[int][]byte{
			OpenStepFormat: []byte(`"\xaB\uCdEf"`),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "Text data long enough to trigger implementation-specific reallocation", // this is for coverage :(
		Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		Documents: map[int][]byte{
			OpenStepFormat: []byte("<0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001>"),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "Empty Text Document",
		Value: map[string]interface{}{}, // Defined to be an empty dictionary
		Documents: map[int][]byte{
			OpenStepFormat: []byte{},
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name:  "Text document consisting of only whitespace",
		Value: map[string]interface{}{}, // Defined to be an empty dictionary
		Documents: map[int][]byte{
			OpenStepFormat: []byte(" \n\t"),
		},
		SkipEncode: map[int]bool{OpenStepFormat: true},
	},
	{
		Name: "Sized integers at size boundaries",
		Value: []interface{}{
			int8(-128),
			int8(127),
			int16(-32768),
			int16(32767),
			int32(-2147483648),
			int32(2147483647),
			int64(-9223372036854775808),
			int64(9223372036854775807),
		},
		DecodeValue: []interface{}{
			// interface decoding promotes all numbers to u/int64
			int64(-128),
			uint64(127),
			int64(-32768),
			uint64(32767),
			int64(-2147483648),
			uint64(2147483647),
			int64(-9223372036854775808),
			uint64(9223372036854775807),
		},
		Documents: map[int][]byte{
			BinaryFormat: []byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xa8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x10, 0x7f, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x11, 0x7f, 0xff, 0x13, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x12, 0x7f, 0xff, 0xff, 0xff, 0x13, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x11, 0x1a, 0x1c, 0x25, 0x28, 0x31, 0x36, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48},
		},
	},
	{
		Name: "Duplicate Dictionary Keys",
		Value: map[string]interface{}{
			"key": "second value",
		},
		Documents: map[int][]byte{
			XMLFormat:      []byte(`<plist><dict><key>key</key><string>value</string><key>key</key><string>second value</string></dict></plist>`),
			OpenStepFormat: []byte(`{"key" = "value"; "key" = "second value";}`),
			GNUStepFormat:  []byte(`{"key" = "value"; "key" = "second value";}`),
			BinaryFormat: []byte{
				'b', 'p', 'l', 'i', 's', 't', '0', '0',

				0xD2, 0x01, 0x01, 0x02, 0x03,
				0x53, 'k', 'e', 'y',
				0x55, 'v', 'a', 'l', 'u', 'e',
				0x5C, 's', 'e', 'c', 'o', 'n', 'd', ' ', 'v', 'a', 'l', 'u', 'e',

				0x08, 0x0D, 0x11, 0x17,

				0x00, 0x00, 0x00, 0x00, 0x00,
				0x00,
				0x01,
				0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24,
			},
		},
		SkipEncode: map[int]bool{XMLFormat: true, OpenStepFormat: true, GNUStepFormat: true, BinaryFormat: true},
	},
	{
		Name: "GNUStep base64 data ignoring invalid chars",
		Value: [][]byte{
			{'h', 'e', 'l', 'l', 'o'},
			{'h', 'e', 'l', 'l', 'o'},
		},
		Documents: map[int][]byte{
			GNUStepFormat: []byte(`(<[aGVs^^bG8=]>,<[ a G V s b G 8 = ]>)`),
		},
		// We are not encoding base64 for GNUstep yet
		SkipEncode: map[int]bool{GNUStepFormat: true},
	},
	{
		Name:  "Text document with quoted GNUstep values",
		Value: []interface{}{uint64(1048576), uint64(1234), true},
		Documents: map[int][]byte{
			GNUStepFormat: []byte(`(<*I"1048576">, <*I"1234>, <*B"Y>)`),
		},
		SkipEncode: map[int]bool{GNUStepFormat: true},
	},
}

type EverythingTestData struct {
	Intarray []uint64  `plist:"intarray"`
	Floats   []float64 `plist:"floats"`
	Booleans []bool    `plist:"booleans"`
	Strings  []string  `plist:"strings"`
	Dat      []byte    `plist:"data"`
	Date     time.Time `plist:"date"`
}

var plistValueTreeRawData = &EverythingTestData{
	Intarray: []uint64{1, 8, 16, 32, 64, 2, 9, 17, 33, 65},
	Floats:   []float64{32.0, 64.0},
	Booleans: []bool{true, false},
	Strings:  []string{"Hello, ASCII", "Hello, 世界"},
	Dat:      []byte{1, 2, 3, 4},
	Date:     time.Date(2013, 11, 27, 0, 34, 0, 0, time.UTC),
}
var plistValueTree cfValue
var plistValueTreeAsBplist = []byte{98, 112, 108, 105, 115, 116, 48, 48, 214, 1, 13, 17, 21, 25, 27, 2, 14, 18, 22, 26, 28, 88, 105, 110, 116, 97, 114, 114, 97, 121, 170, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 1, 16, 8, 16, 16, 16, 32, 16, 64, 16, 2, 16, 9, 16, 17, 16, 33, 16, 65, 86, 102, 108, 111, 97, 116, 115, 162, 15, 16, 34, 66, 0, 0, 0, 35, 64, 80, 0, 0, 0, 0, 0, 0, 88, 98, 111, 111, 108, 101, 97, 110, 115, 162, 19, 20, 9, 8, 87, 115, 116, 114, 105, 110, 103, 115, 162, 23, 24, 92, 72, 101, 108, 108, 111, 44, 32, 65, 83, 67, 73, 73, 105, 0, 72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 44, 0, 32, 78, 22, 117, 76, 84, 100, 97, 116, 97, 68, 1, 2, 3, 4, 84, 100, 97, 116, 101, 51, 65, 184, 69, 117, 120, 0, 0, 0, 8, 21, 30, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 68, 71, 76, 85, 94, 97, 98, 99, 107, 110, 123, 142, 147, 152, 157, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166}
var plistValueTreeAsXML = xmlPreamble + `<plist version="1.0"><dict><key>intarray</key><array><integer>1</integer><integer>8</integer><integer>16</integer><integer>32</integer><integer>64</integer><integer>2</integer><integer>9</integer><integer>17</integer><integer>33</integer><integer>65</integer></array><key>floats</key><array><real>32</real><real>64</real></array><key>booleans</key><array><true/><false/></array><key>strings</key><array><string>Hello, ASCII</string><string>Hello, 世界</string></array><key>data</key><data>AQIDBA==</data><key>date</key><date>2013-11-27T00:34:00Z</date></dict></plist>`
var plistValueTreeAsOpenStep = `{booleans=(1,0,);data=<01020304>;date="2013-11-27 00:34:00 +0000";floats=(32,64,);intarray=(1,8,16,32,64,2,9,17,33,65,);strings=("Hello, ASCII","Hello, \U4e16\U754c",);}`
var plistValueTreeAsGNUStep = `{booleans=(<*BY>,<*BN>,);data=<01020304>;date=<*D2013-11-27 00:34:00 +0000>;floats=(<*R32>,<*R64>,);intarray=(<*I1>,<*I8>,<*I16>,<*I32>,<*I64>,<*I2>,<*I9>,<*I17>,<*I33>,<*I65>,);strings=("Hello, ASCII","Hello, \U4e16\U754c",);}`

type LaxTestData struct {
	I64 int64
	U64 uint64
	F64 float64
	B   bool
	D   time.Time
}

var laxTestData = LaxTestData{1, 2, 3.0, true, time.Date(2013, 11, 27, 0, 34, 0, 0, time.UTC)}

func setupPlistValues() {
	plistValueTree = &cfDictionary{
		keys: []string{
			"intarray",
			"floats",
			"booleans",
			"strings",
			"data",
			"date",
		},
		values: []cfValue{
			&cfArray{
				values: []cfValue{
					&cfNumber{value: 1},
					&cfNumber{value: 8},
					&cfNumber{value: 16},
					&cfNumber{value: 32},
					&cfNumber{value: 64},
					&cfNumber{value: 2},
					&cfNumber{value: 8},
					&cfNumber{value: 17},
					&cfNumber{value: 33},
					&cfNumber{value: 65},
				},
			},
			&cfArray{
				values: []cfValue{
					&cfReal{wide: false, value: 32.0},
					&cfReal{wide: true, value: 64.0},
				},
			},
			&cfArray{
				values: []cfValue{
					cfBoolean(true),
					cfBoolean(false),
				},
			},
			&cfArray{
				values: []cfValue{
					cfString("Hello, ASCII"),
					cfString("Hello, 世界"),
				},
			},
			cfData{1, 2, 3, 4},
			cfDate(time.Date(2013, 11, 27, 0, 32, 0, 0, time.UTC)),
		},
	}
}

func init() {
	setupPlistValues()

	// Pre-warm the type info struct to remove it from benchmarking
	getTypeInfo(reflect.ValueOf(plistValueTreeRawData).Type())
}
