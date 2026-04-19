package mp4_test

import (
	"os"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestTrakSampleFunctions(t *testing.T) {
	testFile := "testdata/bbb_prog_10s.mp4"
	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mf, err := mp4.DecodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	moov := mf.Moov
	traks := moov.Traks
	if len(traks) != 2 {
		t.Fatalf("expected 2 tracks, got %d", len(traks))
	}
	trak := traks[0]
	if trak.Tkhd.TrackID != 1 {
		t.Fatalf("expected trackID 1, got %d", trak.Tkhd.TrackID)
	}
	first2Samples, err := trak.GetSampleData(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first2Samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(first2Samples))
	}
	ranges, err := trak.GetRangesForSampleInterval(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
}
