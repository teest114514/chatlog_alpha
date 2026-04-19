package mp4_test

import (
	"testing"

	"github.com/go-test/deep"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

func TestEmsg(t *testing.T) {

	boxes := []mp4.Box{
		&mp4.EmsgBox{Version: 1,
			TimeScale:        90000,
			PresentationTime: 10000000,
			EventDuration:    90000,
			ID:               42,
			SchemeIDURI:      "https://aomedia.org/emsg/ID3",
			Value:            "relative",
		},
		&mp4.EmsgBox{Version: 0,
			TimeScale:             90000,
			PresentationTimeDelta: 45000,
			EventDuration:         90000,
			ID:                    42,
			SchemeIDURI:           "schid",
			Value:                 "special"},
		&mp4.EmsgBox{Version: 1,
			TimeScale:        90000,
			PresentationTime: 10000000,
			EventDuration:    90000,
			ID:               42,
			SchemeIDURI:      "https://aomedia.org/emsg/ID3",
			Value:            "relative",
			MessageData:      []byte{73, 68, 51, 4, 0, 32, 0, 0, 2, 5, 80, 82, 73, 86, 0, 0, 1, 123, 0, 0, 119, 119, 119},
		},
		&mp4.EmsgBox{Version: 0,
			TimeScale:             90000,
			PresentationTimeDelta: 45000,
			EventDuration:         90000,
			ID:                    42,
			SchemeIDURI:           "schid",
			Value:                 "special",
			MessageData:           []byte{73, 68, 51, 4, 0, 32, 0, 0, 2, 5, 80, 82, 73, 86, 0, 0, 1, 123, 0, 0, 119, 119, 119}},
	}

	for _, inBox := range boxes {
		boxDiffAfterEncodeAndDecode(t, inBox)
	}
}

func TestEmsgMessageDataIsEncoded(t *testing.T) {

	b1 := mp4.EmsgBox{Version: 1,
		TimeScale:        90000,
		PresentationTime: 10000000,
		EventDuration:    90000,
		ID:               42,
		SchemeIDURI:      "https://aomedia.org/emsg/ID3",
		Value:            "relative",
		MessageData:      []byte{73, 68, 51, 4, 0, 32, 0, 0, 2, 5, 80, 82, 73, 86, 0, 0, 1, 123, 0, 0, 119, 119, 119},
	}

	b2 := mp4.EmsgBox{Version: 1,
		TimeScale:        90000,
		PresentationTime: 10000000,
		EventDuration:    90000,
		ID:               42,
		SchemeIDURI:      "https://aomedia.org/emsg/ID3",
		Value:            "relative"}

	if b1.Size() == b2.Size() {
		t.Error("Different emsg boxes have the same calculated size")
	}

	b1writer := bits.NewFixedSliceWriter(int(b1.Size()))
	err := b1.EncodeSW(b1writer)
	if err != nil {
		t.Error(err)
	}

	b2writer := bits.NewFixedSliceWriter(int(b2.Size()))
	err = b2.EncodeSW(b2writer)
	if err != nil {
		t.Error(err)
	}

	if diff := deep.Equal(b1writer.Bytes(), b2writer.Bytes()); diff == nil {
		t.Error("Different emsg boxes have the same encoded data")
	}
}
