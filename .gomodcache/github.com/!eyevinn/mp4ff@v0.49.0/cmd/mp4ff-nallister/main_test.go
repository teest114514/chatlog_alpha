package main

import (
	"bytes"
	"os"
	"testing"
)

func TestOptions(t *testing.T) {
	cases := []struct {
		desc        string
		args        []string
		expectedErr bool
		goldenOut   string
	}{
		{desc: "no args", args: []string{appName}, expectedErr: true},
		{desc: "unknown args", args: []string{appName, "-x"}, expectedErr: true},
		{desc: "non-existing file", args: []string{appName, "infile.mp4"}, expectedErr: true},
		{desc: "bad file", args: []string{appName, "main.go"}, expectedErr: true},
		{desc: "annexB, bad file", args: []string{appName, "-annexb", "main.go"}, expectedErr: true},
		{desc: "annexB, non-existing file", args: []string{appName, "-annexb", "none.264"}, expectedErr: true},
		{desc: "annexBH264", args: []string{appName, "-annexb", "-ps", "testdata/4pics.264"},
			goldenOut: "testdata/golden_4pics_h264.txt", expectedErr: false},
		{desc: "annexBBadCodec", args: []string{appName, "-annexb", "-c", "av1", "testdata/4pics.264"},
			expectedErr: true},
		{desc: "initFile", args: []string{appName, "../../mp4/testdata/init.mp4"}, expectedErr: false},
		{desc: "progH264", args: []string{appName, "-ps", "-m", "4", "../../mp4/testdata/prog_8s.mp4"},
			goldenOut: "testdata/golden_prot_h264_4pics.txt", expectedErr: false},
		{desc: "mp4H264", args: []string{appName, "testdata/h264.mp4"},
			goldenOut: "testdata/golden_h264_mp4.txt", expectedErr: false},
		{desc: "annexBHEVC", args: []string{appName, "-annexb", "-c", "hevc", "testdata/hevc.265"},
			goldenOut: "testdata/golden_hevc_265.txt", expectedErr: false},
		{desc: "annexBHEVC with SEI", args: []string{appName, "-annexb", "-c", "hevc", "-sei", "2", "testdata/hevc.265"},
			goldenOut: "", expectedErr: false},
		{desc: "mp4HEVC", args: []string{appName, "testdata/hevc.mp4"},
			goldenOut: "testdata/golden_hevc_mp4.txt", expectedErr: false},
		{desc: "h264 frag mp4 raw", args: []string{appName, "-m", "6", "-raw", "4", "../../mp4/testdata/prog_8s_dec_dashinit.mp4"},
			goldenOut: "testdata/golden_h264_frag_raw.txt", expectedErr: false},
		{desc: "avcSeiTime", args: []string{appName, "-sei", "2", "-annexb", "testdata/4pics.264"},
			goldenOut: "testdata/golden_4pic_sei_264.txt", expectedErr: false},
		{desc: "version", args: []string{appName, "-version"}, expectedErr: false},
		{desc: "help", args: []string{appName, "-h"}, expectedErr: false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			gotOut := bytes.Buffer{}
			err := run(c.args, &gotOut)
			if c.expectedErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				return
			}
			if c.goldenOut != "" {
				expectedString := getExpected(t, c.goldenOut)
				gotString := gotOut.String()
				if gotString != expectedString {
					t.Errorf("expected %s, got %s", expectedString, gotString)
				}
			}
		})
	}
}

func getExpected(t *testing.T, filename string) string {
	t.Helper()
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("could not read golden file %s: %s", filename, err)
	}
	r := bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return string(r)
}
