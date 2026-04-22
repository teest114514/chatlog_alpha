package main

import (
	"bytes"
	"testing"
)

func TestCommandLines(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := tmpDir + "/cropped.mp4"
	cases := []struct {
		desc         string
		args         []string
		expectedErr  bool
		wantedOutput string
	}{
		{desc: "help", args: []string{appName, "-h"}, expectedErr: false},
		{desc: "no args", args: []string{appName}, expectedErr: true},
		{desc: "duration = 0", args: []string{appName, "-d", "0", "dummy.mp4", "dummy.mp4"}, expectedErr: true},
		{desc: "non-existing infile", args: []string{appName, "-d", "1000", "notExists.mp4", "dummy.mp4"}, expectedErr: true},
		{desc: "segment 2s to 1s (30fps 3000 ticks/frame)", args: []string{appName, "-v", "-d", "90000", "../../mp4/testdata/1.m4s",
			outFile},
			wantedOutput: `Started segment 1 at dts=0 pts=6000
   0 DTS 0 PTS 6000
  30 DTS 90000 PTS 96000
Started segment 2 at dts=90000 pts=96000
`,
			expectedErr: false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			buf := bytes.Buffer{}
			err := run(c.args, &buf)
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
			if c.wantedOutput != "" {
				gotOutput := buf.String()
				if gotOutput != c.wantedOutput {
					t.Errorf("unexpected output: got %s, wanted %s", gotOutput, c.wantedOutput)
				}
			}
		})
	}
}
