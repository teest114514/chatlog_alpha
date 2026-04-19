package mp4_test

import (
	"encoding/hex"
	"testing"
)

func TestLudt(t *testing.T) {
	ludtBox := `0000002c6c75647400000024746c6f75010000000100000043f43e2305017923037a13047c13057a13060113`
	data, err := hex.DecodeString(ludtBox)
	if err != nil {
		t.Error(err)
	}
	cmpAfterDecodeEncodeBox(t, data)
}
