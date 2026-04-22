package main

import (
	"os"
	"sort"
	"strings"
	"testing"
)

func TestCommandLines(t *testing.T) {
	tmpDir := t.TempDir()
	testIn := "../../mp4/testdata/bbb_prog_10s.mp4"
	cases := []struct {
		desc        string
		args        []string
		expectedErr bool
		wantedFiles []string
	}{
		{desc: "help", args: []string{appName, "-h"}, expectedErr: false},
		{desc: "no args", args: []string{appName}, expectedErr: true},
		{desc: "duration = 0", args: []string{appName, "-d", "0", "dummy.mp4", "dummy.mp4"}, expectedErr: true},
		{desc: "non-existing infile", args: []string{appName, "-d", "1000", "notExists.mp4", "dummy.mp4"}, expectedErr: true},
		{desc: "segment 10s to 5s", args: []string{appName, "-d", "5000", testIn, "split"}, expectedErr: false,
			wantedFiles: []string{"split_a1_1.m4s", "split_a1_2.m4s", "split_a1_init.mp4", "split_v1_1.m4s",
				"split_v1_2.m4s", "split_v1_init.mp4"},
		},
		{desc: "segment 10s to 5s lazy", args: []string{appName, "-d", "5000", "-lazy", testIn, "lazy"}, expectedErr: false,
			wantedFiles: []string{"lazy_a1_1.m4s", "lazy_a1_2.m4s", "lazy_a1_init.mp4", "lazy_v1_1.m4s",
				"lazy_v1_2.m4s", "lazy_v1_init.mp4"},
		},
		{desc: "segment 10s to 5s muxed", args: []string{appName, "-d", "5000", "-m", testIn, "mux"}, expectedErr: false,
			wantedFiles: []string{"mux_init.mp4", "mux_media_1.m4s", "mux_media_2.m4s"},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			err := run(c.args, tmpDir)
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
		})
		prefix := c.args[len(c.args)-1]
		files := getFileNames(t, tmpDir, prefix)
		if len(files) != len(c.wantedFiles) {
			t.Errorf("got %d files, wanted %d", len(files), len(c.wantedFiles))
		}
		for i, f := range files {
			if f != c.wantedFiles[i] {
				t.Errorf("got %s, wanted %s", f, c.wantedFiles[i])
			}
		}
	}
}

func getFileNames(t *testing.T, dir, prefix string) []string {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fileNames := []string{}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), prefix) {
			fileNames = append(fileNames, f.Name())
		}
	}
	sort.Strings(fileNames)
	return fileNames
}
