package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestMdhd(t *testing.T) {

	boxes := []*mp4.MdhdBox{
		{
			Version:          0,
			Flags:            0,
			CreationTime:     12,
			ModificationTime: 13,
			Timescale:        10000,
			Duration:         10000,
			Language:         0, // 16-bit. Set from "eng" later
		},
		{
			Version:          1,
			Flags:            0,
			CreationTime:     12,
			ModificationTime: 13,
			Timescale:        10000,
			Duration:         10000,
			Language:         0, // 16-bit. Set from "eng" later
		},
	}

	for _, mdhd := range boxes {
		language := "eng"
		mdhd.SetLanguage(language)
		boxDiffAfterEncodeAndDecode(t, mdhd)
		outBox := boxAfterEncodeAndDecode(t, mdhd)
		mdhdOut := outBox.(*mp4.MdhdBox)
		gotLanguage := mdhdOut.GetLanguage()
		if gotLanguage != language {
			t.Errorf("Got %q, want %q", gotLanguage, language)
		}
	}
}
