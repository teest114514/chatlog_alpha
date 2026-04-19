package main

import (
	"io"
	"os"
	"path"
	"testing"
)

func TestOptionCases(t *testing.T) {
	init := "../../mp4/testdata/init.mp4"
	inSeg := "../../mp4/testdata/1.m4s"
	key := "00112233445566778899aabbccddeeff"
	iv := "00112233445566778899aabbccddeeff"
	kid := "00112233445566778899aabbccddeeff"
	pssh := "../../mp4/testdata/pssh.bin"
	tmpDir := t.TempDir()
	outFile := path.Join(tmpDir, "outfile.mp4")
	combFile := path.Join(tmpDir, "combfile.mp4")
	err := concatenateFiles(combFile, init, inSeg)
	if err != nil {
		t.Fatalf("error making combined segment: %v", err)
	}

	cases := []struct {
		desc string
		args []string
		err  bool
	}{
		{desc: "no args", args: []string{appName}, err: true},
		{desc: "unknown args", args: []string{appName, "-x"}, err: true},
		{desc: "no outfile", args: []string{appName, inSeg}, err: true},
		{desc: "no key", args: []string{appName, inSeg, outFile}, err: true},
		{desc: "non-existing infile",
			args: []string{appName, "-key", key, "-iv", iv, "infile.mp4", outFile},
			err:  true},
		{desc: "bad outfile", args: []string{appName, "-key", key, "-iv", iv, inSeg, "/.."},
			err: true},
		{desc: "non-existing initFile",
			args: []string{appName, "-key", key, "-iv", iv, "-init", "init.mp4", inSeg, outFile},
			err:  true},
		{desc: "bad initFile",
			args: []string{appName, "-key", key, "-iv", iv, "-init", "main.go", inSeg, outFile},
			err:  true},
		{desc: "too short iv ",
			args: []string{appName, "-key", key, "-iv", "00", "-init", init, inSeg, outFile},
			err:  true},
		{desc: "bad iv ",
			args: []string{appName, "-key", key, "-iv", badHex(iv), "-init", init, inSeg, outFile},
			err:  true},
		{desc: "too short key ",
			args: []string{appName, "-key", "00", "-iv", iv, "-init", init, inSeg, outFile},
			err:  true},
		{desc: "bad key ",
			args: []string{appName, "-key", badHex(key), "-iv", iv, "-init", init, inSeg, outFile},
			err:  true},
		{desc: "too short kid ",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", "00", inSeg, outFile},
			err:  true},
		{desc: "bad  kid ",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", badHex(kid), inSeg, outFile},
			err:  true},
		{desc: "bad scheme ",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", kid, "-scheme", "badScheme", inSeg, outFile},
			err:  true},
		{desc: "bad inFile ",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", kid, "main.go", outFile},
			err:  true},
		{desc: "init-enc missing ",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", kid, inSeg, outFile},
			err:  true},
		{desc: "bad pssh ",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", kid, "-pssh", "main.go", inSeg, outFile},
			err:  true},
		{desc: "segFile",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", kid, "-pssh", pssh, inSeg, outFile},
			err:  true},
		{desc: "combined file with bad pssh",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", kid, "-pssh", "main.go", combFile, outFile},
			err:  true},
		{desc: "successful combined file",
			args: []string{appName, "-key", key, "-iv", iv, "-kid", kid, "-pssh", pssh, combFile, outFile},
			err:  false},
		{desc: "version", args: []string{appName, "-version"}, err: false},
		{desc: "help", args: []string{appName, "-h"}, err: false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			t.Log("running test case: ", c.desc)
			err := run(c.args)
			if c.err && err == nil {
				t.Error("expected error but got nil")
			}
			if !c.err && err != nil {
				t.Errorf("unexpected error: %s", err)
			}
		})
	}
}

func badHex(hex string) string {
	return hex[:len(hex)-1] + "x"
}

// concatenateFiles concatenates multiple files into a new one
// the last file is the output path
func concatenateFiles(outFile string, inFiles ...string) error {
	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()

	for _, inFile := range inFiles {
		in, err := os.Open(inFile)
		if err != nil {
			return err
		}
		defer in.Close()

		_, err = io.Copy(out, in)
		if err != nil {
			return err
		}
	}

	return nil
}
