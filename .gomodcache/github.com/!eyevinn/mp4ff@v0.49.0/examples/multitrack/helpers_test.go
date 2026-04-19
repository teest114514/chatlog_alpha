package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-test/deep"
)

// Helpers to tests. By including t.Helper(), the right failing line in the test
// itself is reported.

var (
	update = flag.Bool("update", false, "update the golden files of this test")
)

// writeGolden - write golden file that to be used for later tests
func writeGolden(t *testing.T, goldenAssetPath string, data []byte) error {
	t.Helper()
	fd, err := os.Create(goldenAssetPath)
	if err != nil {
		return err
	}
	_, err = fd.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// compareOrUpdateGolden - compare generated data  with golden dump or update it with -update flag set
func compareOrUpdateGolden(t *testing.T, genData []byte, path string) (err error) {
	t.Helper()

	if *update { // Generate golden dump file
		err = writeGolden(t, path, genData)
		if err != nil {
			t.Error(err)
		}
		return nil
	}

	// Compare with golden dump file
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Error(err)
	}
	if strings.HasSuffix(path, ".txt") || strings.HasSuffix(path, ".scc") {
		// Replace \r\n with \n to handle accidental Windows line endings
		golden = bytes.ReplaceAll(golden, []byte{13, 10}, []byte{10})
	}
	diff := deep.Equal(golden, genData)
	if diff != nil {
		return fmt.Errorf("Generated data different from %s", path)
	}
	return nil
}

// TestMain is to set flags for tests. In particular, the update flag to update golden files.
func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}
