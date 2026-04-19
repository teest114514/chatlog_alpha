package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSubs(t *testing.T) {

	subs := &mp4.SubsBox{}
	e := mp4.SubsSample{SubsampleSize: 1000, SubsamplePriority: 255, Discardable: 0, CodecSpecificParameters: 0}
	subs.Entries = append(subs.Entries, mp4.SubsEntry{SampleDelta: 100, SubSamples: []mp4.SubsSample{e}})
	boxDiffAfterEncodeAndDecode(t, subs)
}

func TestSubsInfo(t *testing.T) {
	goldenDumpPath := "testdata/golden_subs_dump.txt"
	subs := &mp4.SubsBox{}
	e := mp4.SubsSample{SubsampleSize: 1000, SubsamplePriority: 255, Discardable: 0, CodecSpecificParameters: 0}
	subs.Entries = append(subs.Entries, mp4.SubsEntry{SampleDelta: 100, SubSamples: []mp4.SubsSample{e}})

	err := compareOrUpdateInfo(t, subs, goldenDumpPath)
	if err != nil {
		t.Error(err)
	}
}
