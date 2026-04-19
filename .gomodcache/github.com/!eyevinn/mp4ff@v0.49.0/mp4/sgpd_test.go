package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSgpd(t *testing.T) {

	rollEntry := &mp4.RollSampleGroupEntry{RollDistance: -1}
	rapEntry := &mp4.RapSampleGroupEntry{NumLeadingSamplesKnown: 1, NumLeadingSamples: 12}
	alstEntry := &mp4.AlstSampleGroupEntry{RollCount: 2, FirstOutputSample: 1, SampleOffset: []uint32{7000, 1234}}
	unknownEntry := &mp4.UnknownSampleGroupEntry{Name: "tele", Data: []byte{0x80}}
	unknownEntry2 := &mp4.UnknownSampleGroupEntry{Name: "tele", Data: []byte{0x00}}

	sgpds := []*mp4.SgpdBox{
		{Version: 1, GroupingType: "roll", DefaultLength: 2, SampleGroupEntries: []mp4.SampleGroupEntry{rollEntry}},
		{Version: 1, GroupingType: "rap ", DefaultLength: 1, SampleGroupEntries: []mp4.SampleGroupEntry{rapEntry}},
		{Version: 1, GroupingType: "alst", DefaultLength: 12, SampleGroupEntries: []mp4.SampleGroupEntry{alstEntry}},
		{Version: 1, GroupingType: "tele", DefaultLength: 1, SampleGroupEntries: []mp4.SampleGroupEntry{unknownEntry, unknownEntry2}},
	}

	for _, sgpd := range sgpds {
		boxDiffAfterEncodeAndDecode(t, sgpd)
	}

}
