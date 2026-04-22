package mp4_test

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

// Helpers to tests. By including t.Helper(), the right failing line in the test
// itself is reported.

var (
	update = flag.Bool("update", false, "update the golden files of this test")
)

// cmpAfterDecodeEncodeBox compares bytes after a box has been decoded and encoded.
func cmpAfterDecodeEncodeBox(t *testing.T, data []byte) {
	t.Helper()

	// First SliceReader + SliceWriter
	sr := bits.NewFixedSliceReader(data)
	box, err := mp4.DecodeBoxSR(0, sr)
	if err != nil {
		t.Error(err)
	}
	sw := bits.NewFixedSliceWriter(int(box.Size()))
	err = box.EncodeSW(sw)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(data, sw.Bytes()) {
		t.Error("non-matching DecodeBoxSR/EncodeSW")
	}

	bufIn := bytes.NewBuffer(data)
	box, err = mp4.DecodeBox(0, bufIn)
	if err != nil {
		t.Error(err)
	}
	bufOut := bytes.Buffer{}
	err = box.Encode(&bufOut)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(data, bufOut.Bytes()) {
		t.Error("non-matchin DecodeBox/Encode")
	}
}

// boxDiffAfterEncodeAndDecode compares a box after encoding and decoding using deep.Equal().
// Further check that Info can be run without an error.
func boxDiffAfterEncodeAndDecode(t *testing.T, box mp4.Box) {
	t.Helper()

	// First do encode in a slice via SliceWriter
	size := box.Size()
	sw := bits.NewFixedSliceWriter(int(size))
	err := box.EncodeSW(sw)
	if err != nil {
		t.Error(err)
	}
	buf := bytes.NewBuffer(sw.Bytes())

	boxDec, err := mp4.DecodeBox(0, buf)
	if err != nil {
		t.Error(err)
	}

	if diff := deep.Equal(boxDec, box); diff != nil {
		t.Error(diff)
	}

	// Then do encode using io.Writer
	midBuf := bytes.Buffer{}
	err = box.Encode(&midBuf)
	if err != nil {
		t.Error(err)
	}
	// and decode using SliceReader
	sr := bits.NewFixedSliceReader(midBuf.Bytes())
	boxDec, err = mp4.DecodeBoxSR(0, sr)
	if err != nil {
		t.Error(err)
	}

	if diff := deep.Equal(boxDec, box); diff != nil {
		t.Error(diff)
	}
	// Finally check that the Info method does not render an error

	infoBuf := bytes.Buffer{}
	err = box.Info(&infoBuf, "all:1", "", "  ")
	if err != nil {
		t.Error(err)
	}
}

func boxAfterEncodeAndDecode(t *testing.T, box mp4.Box) mp4.Box {
	t.Helper()
	buf := bytes.Buffer{}
	err := box.Encode(&buf)
	if err != nil {
		t.Error(err)
	}

	boxDec, err := mp4.DecodeBox(0, &buf)
	if err != nil {
		t.Error(err)
	}
	return boxDec
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("Got error %s but expected none", err)
	}
}

func assertError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Error(msg)
	}
}

func changeBoxSizeAndAssertError(t *testing.T, data []byte, pos uint64, newSize uint32, errMsg string) {
	t.Helper()
	raw := make([]byte, len(data))
	copy(raw, data)
	binary.BigEndian.PutUint32(raw[pos:pos+4], newSize)
	assertBoxDecodeError(t, raw, pos, errMsg)
}

func assertBoxDecodeError(t *testing.T, data []byte, pos uint64, errMsg string) {
	t.Helper()
	_, err := mp4.DecodeBox(pos, bytes.NewBuffer(data))
	if err == nil || err.Error() != errMsg {
		got := ""
		if err != nil {
			got = err.Error()
		}
		t.Errorf("DecodeBox: Expected error msg: %q, got: %q", errMsg, got)
	}
	_, err = mp4.DecodeBoxSR(pos, bits.NewFixedSliceReader(data))
	if err == nil || err.Error() != errMsg {
		got := ""
		if err != nil {
			got = err.Error()
		}
		t.Errorf("DecodeBox: Expected error msg: %q, got: %q", errMsg, got)
	}
}

func encodeBox(t *testing.T, box mp4.Box) []byte {
	buf := bytes.Buffer{}
	err := box.Encode(&buf)
	if err != nil {
		t.Error(err)
	}
	return buf.Bytes()
}

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

type testReadSeeker struct {
	data []byte
	pos  int
}

func newTestReadSeeker(data []byte) *testReadSeeker {
	return &testReadSeeker{
		data: data,
		pos:  0,
	}
}

func (sr *testReadSeeker) Read(p []byte) (n int, err error) {
	if sr.pos >= len(sr.data) {
		return 0, io.EOF
	}
	n = copy(p, sr.data[sr.pos:])
	sr.pos += n
	return n, nil
}

func (sr *testReadSeeker) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
		sr.pos = int(offset)
	case 1:
		sr.pos += int(offset)
	case 2:
		sr.pos = len(sr.data) + int(offset)
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}
	return int64(sr.pos), nil
}

func createLazyMdat(t *testing.T, data []byte) (*mp4.MdatBox, io.ReadSeeker) {
	t.Helper()
	fullData := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(fullData[0:4], uint32(len(data)+8))
	copy(fullData[4:], "mdat")
	copy(fullData[8:], data)
	testSeeker := newTestReadSeeker(fullData)
	box, err := mp4.DecodeBoxLazyMdat(0, testSeeker)
	if err != nil {
		t.Error(err)
	}
	lazyMdat := box.(*mp4.MdatBox)
	return lazyMdat, testSeeker
}

// TestMain is to set flags for tests. In particular, the update flag to update golden files.
func TestMain(m *testing.M) {
	flag.Parse()
	if *update {
		fmt.Println("update flag is set to:", *update)
	}
	os.Exit(m.Run())
}
