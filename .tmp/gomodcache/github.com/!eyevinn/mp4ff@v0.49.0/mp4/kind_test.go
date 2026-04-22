package mp4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestKind(t *testing.T) {
	t.Run("encode and decode", func(t *testing.T) {
		kind := &mp4.KindBox{SchemeURI: "urn:mpeg:dash:role:2011", Value: "forced-subtitle"}
		boxDiffAfterEncodeAndDecode(t, kind)
	})
	t.Run("decode with full box header", func(t *testing.T) {
		rawHex := ("000000296b696e64" +
			"0000000075726e3a6d7065673a646173" +
			"683a726f6c653a32303131006d61696e00")
		rawBytes, err := hex.DecodeString(rawHex)
		if err != nil {
			t.Error(err)
		}
		buffer := bytes.NewReader(rawBytes)
		box, err := mp4.DecodeBox(0, buffer)
		if err != nil {
			t.Errorf("Error decoding kind box: %v", err)
		}
		kind := box.(*mp4.KindBox)
		if kind.SchemeURI != "urn:mpeg:dash:role:2011" {
			t.Errorf("Expected scheme URI 'urn:mpeg:dash:role:2011', got '%s'", kind.SchemeURI)
		}
		if kind.Value != "main" {
			t.Errorf("Expected value 'main', got '%s'", kind.Value)
		}
	})
}
