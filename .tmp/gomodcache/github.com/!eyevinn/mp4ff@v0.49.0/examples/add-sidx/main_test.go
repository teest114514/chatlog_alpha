package main

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestCommandLine(t *testing.T) {
	inPath := "testdata/clear_with_enc_boxes.mp4"
	tmpDir := t.TempDir()
	testCases := []struct {
		desc           string
		args           []string
		expectedErr    bool
		checkOutput    bool
		wantedNrSegs   uint32
		wantedSize     uint32
		wantedFirstDur uint32
	}{
		{desc: "help", args: []string{appName, "-h"}, expectedErr: false},
		{desc: "version", args: []string{appName, "-version"}, expectedErr: false},
		{desc: "no args", args: []string{appName}, expectedErr: true},
		{desc: "unknown args", args: []string{appName, "-x"}, expectedErr: true},
		{
			desc:           "sidx, enc boxes, 1 segment",
			args:           []string{appName, inPath, path.Join(tmpDir, "out1.mp4")},
			checkOutput:    true,
			wantedNrSegs:   1,
			wantedFirstDur: 2 * 144144,
		},
		{
			desc:           "sidx, enc boxes, many segments",
			args:           []string{appName, "-startSegOnMoof", inPath, path.Join(tmpDir, "out2.mp4")},
			checkOutput:    true,
			wantedNrSegs:   2,
			wantedFirstDur: 144144,
		},
		{
			desc:           "sidx, no enc boxes, many segments",
			args:           []string{appName, "-removeEnc", "-startSegOnMoof", inPath, path.Join(tmpDir, "out3.mp4")},
			checkOutput:    true,
			wantedNrSegs:   2,
			wantedFirstDur: 144144,
		},
		{
			desc:           "normal file with styp",
			args:           []string{appName, "../resegmenter/testdata/testV300.mp4", path.Join(tmpDir, "out4.mp4")},
			checkOutput:    true,
			wantedNrSegs:   4,
			wantedFirstDur: 180000,
		},
	}

	for _, c := range testCases {
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
			if !c.checkOutput {
				return
			}
			outPath := c.args[len(c.args)-1]
			ofh, err := os.Open(outPath)
			if err != nil {
				t.Fatal(err)
			}
			defer ofh.Close()
			decOut, err := mp4.DecodeFile(ofh)
			if err != nil {
				t.Error()
			}
			if decOut.Sidx == nil {
				t.Error("no sidx box")
			}
			sidxEntries := decOut.Sidx.SidxRefs
			gotNrEntries := len(sidxEntries)
			if gotNrEntries != int(c.wantedNrSegs) {
				t.Errorf("got %d sidx entries instead of %d", gotNrEntries, c.wantedNrSegs)
			}
			if sidxEntries[0].SubSegmentDuration != c.wantedFirstDur {
				t.Errorf("got first duration %d instead of %d", sidxEntries[0].SubSegmentDuration, c.wantedFirstDur)
			}
			if contains(c.args, "-removeEnc") {
				for _, seg := range decOut.Segments {
					for _, frag := range seg.Fragments {
						if frag.Moof.Traf.Senc != nil {
							t.Error("senc is still present in fragment")
						}
					}
				}
			}
		})
	}
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
