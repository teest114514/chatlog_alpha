package plist

import (
	"bytes"
	"fmt"
	"testing"
)

func BenchmarkXMLEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewEncoder(&bytes.Buffer{}).Encode(plistValueTreeRawData)
	}
}

func BenchmarkBplistEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewBinaryEncoder(&bytes.Buffer{}).Encode(plistValueTreeRawData)
	}
}

func BenchmarkOpenStepEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewEncoderForFormat(&bytes.Buffer{}, OpenStepFormat).Encode(plistValueTreeRawData)
	}
}

func TestEncode(t *testing.T) {
	for _, test := range tests {
		subtest(t, test.Name, func(t *testing.T) {
			for fmt, doc := range test.Documents {
				if test.SkipEncode[fmt] {
					continue
				}
				subtest(t, FormatNames[fmt], func(t *testing.T) {
					encoded, err := Marshal(test.Value, fmt)

					if err != nil {
						t.Error(err)
					}

					if !bytes.Equal(doc, encoded) {
						printype := "%s"
						if fmt == BinaryFormat {
							printype = "%2x"
						}
						t.Logf("Value: %#v", test.Value)
						t.Logf("Expected: "+printype+"\n", doc)
						t.Logf("Received: "+printype+"\n", encoded)
						t.Fail()
					}
				})
			}
		})
	}
}

func ExampleEncoder_Encode() {
	type sparseBundleHeader struct {
		InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion"`
		BandSize              uint64 `plist:"band-size"`
		BackingStoreVersion   int    `plist:"bundle-backingstore-version"`
		DiskImageBundleType   string `plist:"diskimage-bundle-type"`
		Size                  uint64 `plist:"size"`
	}
	data := &sparseBundleHeader{
		InfoDictionaryVersion: "6.0",
		BandSize:              8388608,
		Size:                  4 * 1048576 * 1024 * 1024,
		DiskImageBundleType:   "com.apple.diskimage.sparsebundle",
		BackingStoreVersion:   1,
	}

	buf := &bytes.Buffer{}
	encoder := NewEncoder(buf)
	err := encoder.Encode(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(buf.String())

	// Output: <?xml version="1.0" encoding="UTF-8"?>
	// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	// <plist version="1.0"><dict><key>CFBundleInfoDictionaryVersion</key><string>6.0</string><key>band-size</key><integer>8388608</integer><key>bundle-backingstore-version</key><integer>1</integer><key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string><key>size</key><integer>4398046511104</integer></dict></plist>
}

func ExampleMarshal_xml() {
	type sparseBundleHeader struct {
		InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion"`
		BandSize              uint64 `plist:"band-size"`
		BackingStoreVersion   int    `plist:"bundle-backingstore-version"`
		DiskImageBundleType   string `plist:"diskimage-bundle-type"`
		Size                  uint64 `plist:"size"`
	}
	data := &sparseBundleHeader{
		InfoDictionaryVersion: "6.0",
		BandSize:              8388608,
		Size:                  4 * 1048576 * 1024 * 1024,
		DiskImageBundleType:   "com.apple.diskimage.sparsebundle",
		BackingStoreVersion:   1,
	}

	plist, err := MarshalIndent(data, XMLFormat, "\t")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(plist))

	// Output: <?xml version="1.0" encoding="UTF-8"?>
	// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	// <plist version="1.0">
	// 	<dict>
	// 		<key>CFBundleInfoDictionaryVersion</key>
	// 		<string>6.0</string>
	// 		<key>band-size</key>
	// 		<integer>8388608</integer>
	// 		<key>bundle-backingstore-version</key>
	// 		<integer>1</integer>
	// 		<key>diskimage-bundle-type</key>
	// 		<string>com.apple.diskimage.sparsebundle</string>
	// 		<key>size</key>
	// 		<integer>4398046511104</integer>
	// 	</dict>
	// </plist>
}

func ExampleMarshal_gnustep() {
	type sparseBundleHeader struct {
		InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion"`
		BandSize              uint64 `plist:"band-size"`
		BackingStoreVersion   int    `plist:"bundle-backingstore-version"`
		DiskImageBundleType   string `plist:"diskimage-bundle-type"`
		Size                  uint64 `plist:"size"`
	}
	data := &sparseBundleHeader{
		InfoDictionaryVersion: "6.0",
		BandSize:              8388608,
		Size:                  4 * 1048576 * 1024 * 1024,
		DiskImageBundleType:   "com.apple.diskimage.sparsebundle",
		BackingStoreVersion:   1,
	}

	plist, err := MarshalIndent(data, GNUStepFormat, "\t")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(plist))

	// Output: {
	// 	CFBundleInfoDictionaryVersion = 6.0;
	// 	band-size = <*I8388608>;
	// 	bundle-backingstore-version = <*I1>;
	// 	diskimage-bundle-type = com.apple.diskimage.sparsebundle;
	// 	size = <*I4398046511104>;
	// }
}
