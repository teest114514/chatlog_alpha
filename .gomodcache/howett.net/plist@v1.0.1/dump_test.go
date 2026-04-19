// +build dump

// To dump a directory containing all the plist package test data, run
// $ go test -tags dump
//
// To customize where the dumps are stored, set the env variable PLIST_DUMP_DIR.

package plist

import (
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var filenameReplacer = strings.NewReplacer(`<`, `_`, `>`, `_`, `:`, `_`, `"`, `_`, `/`, `_`, `\`, `_`, `|`, `_`, `?`, `_`, `*`, `_`)

var extensions = map[int]string{
	BinaryFormat:   ".binary.plist",
	XMLFormat:      ".xml.plist",
	GNUStepFormat:  ".gnustep.plist",
	OpenStepFormat: ".openstep.plist",
}

func sanitizeFilename(f string) string {
	return filenameReplacer.Replace(f)
}

func oneshotGob(v interface{}, path string) {
	f, _ := os.Create(path)
	defer f.Close()
	enc := gob.NewEncoder(f)
	enc.Encode(v)
}

func makeDirs(dirs ...string) error {
	for _, v := range dirs {
		err := os.MkdirAll(v, 0777)
		if err != nil {
			return err
		}
	}
	return nil
}

func touch(path string) {
	f, _ := os.Create(path)
	f.Close()
}

func TestDump(t *testing.T) {
	dir := os.Getenv("PLIST_DUMP_DIR")
	if dir == "" {
		dir = "dump"
	}

	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}

	documentDir := filepath.Join(dir, "golden")
	encodeDir := filepath.Join(dir, "encode_from")
	decodeDir := filepath.Join(dir, "decode_as")
	invalidDir := filepath.Join(dir, "invalid")
	err = makeDirs(dir, documentDir, encodeDir, decodeDir, invalidDir)
	if err != nil {
		t.Fatal(err)
	}

	// Dump golden plists for known-valid tests and gobs for their encode/decode values
	for _, td := range tests {
		t.Log("Dumping", td.Name)

		saneName := sanitizeFilename(td.Name)

		encv := td.Value
		if encv != nil && len(td.SkipEncode) < len(extensions) {
			// If we have an "encode from" and we are intending to encode
			oneshotGob(encv, filepath.Join(encodeDir, saneName+".gob"))
		}

		decv := td.DecodeValue
		if decv != nil && len(td.SkipDecode) < len(extensions) {
			// If we have an "expected to decode as" and we are intending to decode
			oneshotGob(decv, filepath.Join(decodeDir, saneName+".gob"))
		}

		for k, v := range td.Documents {
			extName := saneName + extensions[k]
			path := filepath.Join(documentDir, extName)
			_ = ioutil.WriteFile(path, v, 0666)
			if td.SkipEncode[k] {
				touch(path + ".decode_only")
			}
			if td.SkipDecode[k] {
				touch(path + ".encode_only")
			}
		}
	}

	// Dump invalid text plists
	for _, td := range InvalidTextPlists {
		saneName := sanitizeFilename(td.Name)
		ext := extensions[OpenStepFormat]
		if strings.Contains(td.Name, "GNUStep") {
			ext = extensions[GNUStepFormat]
		}

		ioutil.WriteFile(filepath.Join(invalidDir, saneName+ext), []byte(td.Data), 0666)
	}

	// Dump invalid XML plists (We don't have any right now.)
	for i, v := range InvalidXMLPlists {
		ioutil.WriteFile(filepath.Join(invalidDir, fmt.Sprintf("invalid-x-%2.02d", i)+extensions[XMLFormat]), []byte(v), 0666)
	}

	// Dump invalid binary plists
	for i, v := range InvalidBplists {
		ioutil.WriteFile(filepath.Join(invalidDir, fmt.Sprintf("invalid-b-%2.02d", i)+extensions[BinaryFormat]), v, 0666)
	}
}
