package mp4_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestTkhd(t *testing.T) {
	var buf bytes.Buffer

	tkhdCreated := mp4.CreateTkhd()
	err := tkhdCreated.Encode(&buf)
	if err != nil {
		t.Error(err)
	}

	if uint64(buf.Len()) != tkhdCreated.Size() {
		t.Errorf("Mismatch bytes written %d not equal to size %d", buf.Len(), tkhdCreated.Size())
	}

	reader := &buf
	hdr, err := mp4.DecodeHeader(reader)
	if err != nil {
		t.Error(err)
	}
	tkhdRead, err := mp4.DecodeTkhd(hdr, 0, reader)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(tkhdRead, tkhdCreated) {
		t.Errorf("Mismatch mvhdCreated vs mvhdRead:\n%+v\n%+v", tkhdCreated, tkhdRead)
	}
}
