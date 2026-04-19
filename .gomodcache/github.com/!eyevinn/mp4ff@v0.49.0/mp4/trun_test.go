package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

// TestTrunDump versus golden file. Can be regenerated with -update
func TestTrunInfo(t *testing.T) {
	goldenDumpPath := "testdata/golden_trun_dump.txt"
	trun := mp4.CreateTrun(0)
	trun.DataOffset = 314159
	fs := mp4.FullSample{
		Sample: mp4.Sample{
			Flags:                 mp4.SyncSampleFlags,
			Dur:                   1024,
			Size:                  4,
			CompositionTimeOffset: -512,
		},
		DecodeTime: 1024,
		Data:       []byte{0, 1, 2, 3},
	}
	trun.AddFullSample(&fs)

	err := compareOrUpdateInfo(t, trun, goldenDumpPath)
	if err != nil {
		t.Error(err)
	}
}

func TestGetSampleNrForRelativeTime(t *testing.T) {
	trun := mp4.CreateTrun(0)
	trun.AddSamples([]mp4.Sample{
		{0, 1024, 100, 0},
		{0, 1024, 100, 0},
		{0, 1024, 100, 0},
		{0, 1024, 100, 0},
		{0, 1024, 100, 0},
		{0, 1024, 100, 0},
	})
	trun.Flags |= mp4.TrunSampleSizePresentFlag | mp4.TrunSampleDurationPresentFlag

	testCases := []struct {
		sampleTime     uint64
		wantedSampleNr uint32
		trunFlags      uint32
		wantedError    bool
	}{
		{0, 1, 0, false},
		{5 * 1024, 6, 0, false},
		{1023, 0, 0, true},
		{7 * 1024, 0, 0, true},
		{0, 1, mp4.TrunSampleDurationPresentFlag, false},
		{5 * 1024, 6, mp4.TrunSampleDurationPresentFlag, false},
		{1023, 0, mp4.TrunSampleDurationPresentFlag, true},
		{7 * 1024, 0, mp4.TrunSampleDurationPresentFlag, true},
	}

	const defaultSampleDuration = 1024

	for i, tc := range testCases {
		trun.Flags = tc.trunFlags
		gotSampleNr, err := trun.GetSampleNrForRelativeTime(tc.sampleTime, defaultSampleDuration)
		if tc.wantedError {
			if err == nil {
				t.Errorf("case %d: did not get an error", i)
			}
			continue
		}
		if err != nil {
			t.Error(err)
			continue
		}
		if gotSampleNr != tc.wantedSampleNr {
			t.Errorf("case %d: got sample nr %d instead of %d", i, gotSampleNr, tc.wantedSampleNr)
		}
	}
}

func TestGetSampleInterval(t *testing.T) {
	trun := mp4.CreateTrun(0)
	trun.AddSamples([]mp4.Sample{
		{0, 100, 1000, 0},
		{0, 200, 2000, 0},
		{0, 300, 3000, 0},
		{0, 400, 4000, 0},
		{0, 500, 5000, 0},
		{0, 600, 6000, 0},
		{0, 700, 7000, 0},
	})

	// Use lazyMdat since we don't care about the actual data
	raw := []byte{0x00, 0x00, 0x00, 0x0e, 0x6d, 0x64, 0x61, 0x74, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	testSeeker := newTestReadSeeker(raw)
	box, err := mp4.DecodeBoxLazyMdat(4000, testSeeker)
	if err != nil {
		t.Error(err)
	}
	lazyMdat := box.(*mp4.MdatBox)

	testCases := []struct {
		startSampleNr  uint32
		endSampleNr    uint32
		baseDecodeTime uint64
		mdat           *mp4.MdatBox
		offsetInMdat   uint32
		wantedSItvl    mp4.SampleInterval
	}{
		{
			1, 2, 10000, lazyMdat, 0, mp4.SampleInterval{10000, []mp4.Sample{{0, 100, 1000, 0}, {0, 200, 2000, 0}}, 0, 3000, nil},
		},
		{
			3, 4, 10000, lazyMdat, 0, mp4.SampleInterval{10300, []mp4.Sample{{0, 300, 3000, 0}, {0, 400, 4000, 0}}, 3000, 7000, nil},
		},
	}

	for i, tc := range testCases {
		gotSItvl, err := trun.GetSampleInterval(tc.startSampleNr, tc.endSampleNr, tc.baseDecodeTime, tc.mdat, tc.offsetInMdat)
		if err != nil {
			t.Error(err)
		}
		if diff := deep.Equal(gotSItvl, tc.wantedSItvl); diff != nil {
			t.Errorf("case %d: %s", i, diff)
		}
	}
}

func TestFirstSampleFlags(t *testing.T) {
	trun := mp4.CreateTrun(0)
	trun.DataOffset = 314159
	trun.AddSample(mp4.Sample{
		Flags:                 mp4.NonSyncSampleFlags,
		Dur:                   1000,
		Size:                  1000,
		CompositionTimeOffset: 0,
	})
	trun.AddSample(mp4.Sample{
		Flags:                 mp4.NonSyncSampleFlags,
		Dur:                   1000,
		Size:                  1000,
		CompositionTimeOffset: 0,
	})
	_, present := trun.FirstSampleFlags()
	if present {
		t.Error("firstSampleFlags present")
	}
	trun.SetFirstSampleFlags(mp4.SyncSampleFlags)
	gotFirstFlags, present := trun.FirstSampleFlags()
	if !present {
		t.Error("firstSampleFlags absent")
	}
	if gotFirstFlags != mp4.SyncSampleFlags {
		t.Errorf("got firstSampleFlags %02x instead of %02x", gotFirstFlags, mp4.SyncSampleFlags)
	}
	trun.RemoveFirstSampleFlags()
	_, present = trun.FirstSampleFlags()
	if present {
		t.Error("firstSampleFlags present after removal")
	}
}

func TestCommonDuration(t *testing.T) {
	cases := []struct {
		commonDur       uint32
		sampleDurs      []uint32
		wantedCommonDur uint32
	}{
		{
			commonDur:       1024,
			sampleDurs:      []uint32{0, 0},
			wantedCommonDur: 1024,
		},
		{
			commonDur:       0,
			sampleDurs:      []uint32{2048, 2048},
			wantedCommonDur: 2048,
		},
		{
			commonDur:       0,
			sampleDurs:      []uint32{2047, 2049},
			wantedCommonDur: 0,
		},
	}
	for _, c := range cases {
		trun := mp4.CreateTrun(0)
		for _, s := range c.sampleDurs {
			trun.AddSample(mp4.Sample{Dur: s})
		}
		if c.commonDur != 0 {
			trun.Flags &= ^mp4.TrunSampleDurationPresentFlag
		}
		gotCommonDur := trun.CommonSampleDuration(c.commonDur)
		if gotCommonDur != c.wantedCommonDur {
			t.Errorf("got common duration %d instead of %d", gotCommonDur, c.wantedCommonDur)
		}
	}
}
