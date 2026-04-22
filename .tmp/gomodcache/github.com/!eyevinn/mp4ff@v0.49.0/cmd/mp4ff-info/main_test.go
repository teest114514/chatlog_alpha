package main

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestOptions(t *testing.T) {
	cases := []struct {
		desc string
		args []string
		w    io.Writer
		err  bool
	}{
		{desc: "no args", args: []string{appName}, w: os.Stdout, err: true},
		{desc: "unknown args", args: []string{appName, "-x"}, w: os.Stdout, err: true},
		{desc: "non-existing file", args: []string{appName, "infile.mp4"}, w: os.Stdout, err: true},
		{desc: "bad file", args: []string{appName, "main.go"}, w: os.Stdout, err: true},
		{desc: "bad writer", args: []string{appName, "../../mp4/testdata/init.mp4"}, w: &badWriter{}, err: true},
		{desc: "good file", args: []string{appName, "../../mp4/testdata/init.mp4"}, w: os.Stdout, err: false},
		{desc: "good with details", args: []string{appName, "-l", "all:1", "../../mp4/testdata/init.mp4"}, w: os.Stdout, err: false},
		{desc: "version", args: []string{appName, "-version"}, w: os.Stdout, err: false},
		{desc: "help", args: []string{appName, "-h"}, w: os.Stdout, err: false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			err := run(c.args, c.w)
			if c.err && err == nil {
				t.Error("expected error but got nil")
			}
			if !c.err && err != nil {
				t.Errorf("unexpected error: %s", err)
			}
		})
	}
}

func TestTruncatedFile(t *testing.T) {

	w := &bytes.Buffer{}
	wantedOutput := `[ftyp] size=32
 - majorBrand: iso5
 - minorVersion: 0
 - compatibleBrand: isom
 - compatibleBrand: iso5
 - compatibleBrand: dash
 - compatibleBrand: mp42
[skip] size=37
`

	t.Run("truncated file", func(t *testing.T) {
		args := []string{appName, "../../mp4/testdata/init_truncated.mp4"}
		err := run(args, w)
		if err == nil {
			t.Error("expected error for truncated file, but got nil")
		}
		out := w.String()
		if out != wantedOutput {
			t.Errorf("expected output:\n%s\nbut got:\n%s", wantedOutput, out)
		}
	})
}

type badWriter struct{}

func (w *badWriter) Write(p []byte) (n int, err error) {
	return 0, os.ErrClosed
}
