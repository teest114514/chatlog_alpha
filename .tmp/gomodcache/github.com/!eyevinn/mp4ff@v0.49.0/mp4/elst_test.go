package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestElst(t *testing.T) {

	boxes := []mp4.Box{
		&mp4.ElstBox{
			Version: 0,
			Flags:   0,
			Entries: []mp4.ElstEntry{
				{1000, 1234, 1, 1},
			},
		},
		&mp4.ElstBox{
			Version: 1,
			Flags:   0,
			Entries: []mp4.ElstEntry{
				{1000, 1234, 1, 1},
			},
		},
	}

	for _, elst := range boxes {
		boxDiffAfterEncodeAndDecode(t, elst)
	}
}
