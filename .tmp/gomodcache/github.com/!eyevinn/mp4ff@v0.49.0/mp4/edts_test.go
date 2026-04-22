package mp4_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

func TestEncodeDecodeEdts(t *testing.T) {

	elst := &mp4.ElstBox{
		Version: 0,
		Flags:   0,
		Entries: []mp4.ElstEntry{{1000, 1234, 1, 1}},
	}
	edts := &mp4.EdtsBox{}
	edts.AddChild(elst)
	buf := bytes.Buffer{}
	err := edts.Encode(&buf)
	if err != nil {
		t.Error(err)
	}
	box, err := mp4.DecodeBox(0, &buf)
	if err != nil {
		t.Error(err)
	}
	edts2 := box.(*mp4.EdtsBox)
	elst2 := edts2.Elst[0]
	if !reflect.DeepEqual(elst, elst2) {
		t.Errorf("elst box not equal after decode: %s", deep.Equal(elst, elst2))
	}
}
