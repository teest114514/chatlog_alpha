package mp4_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

func TestTopBoxInfo(t *testing.T) {
	testfile := "testdata/init_prog.mp4"

	testCases := []struct {
		name        string
		stopBoxType string
		wantedTBI   []mp4.TopBoxInfo
	}{
		{
			"before moov", "moov", []mp4.TopBoxInfo{{"ftyp", 24, 0}},
		},
		{
			"all", "", []mp4.TopBoxInfo{{"ftyp", 24, 0}, {"moov", 5089, 24}},
		},
	}

	for _, tc := range testCases {
		fh, err := os.Open(testfile)
		if err != nil {
			t.Error(err)
		}
		gotTBI, err := mp4.GetTopBoxInfoList(fh, tc.stopBoxType)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(gotTBI, tc.wantedTBI) {
			diff := deep.Equal(gotTBI, tc.wantedTBI)
			if diff != nil {
				t.Errorf("test case: %q, diff: %v", tc.name, diff)
			}
		}
		fh.Close()
	}
}
