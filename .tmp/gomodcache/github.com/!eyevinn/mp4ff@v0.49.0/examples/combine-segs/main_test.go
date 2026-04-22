package main

import "testing"

func TestRunExample(t *testing.T) {
	tmpDir := t.TempDir()
	err := run(tmpDir)
	if err != nil {
		t.Error(err)
	}
}

// TestCombineMediaSegments combines two media segments into a common one with two track IDs.
func TestCombineMediaSegments(t *testing.T) {
	files := []string{
		"./testdata/V300/1.m4s",
		"./testdata/A48/1.m4s",
	}
	trackIDs := []uint32{1, 2}
	combinedMediaSeg, err := combineMediaSegments(files, trackIDs)
	if err != nil {
		t.Error(err)
	}
	nrTracks := len(combinedMediaSeg.Fragments[0].Moof.Trafs)
	if nrTracks != 2 {
		t.Errorf("expected 2 tracks, got %d", nrTracks)
	}
}

// TestCombineInitSegments combines two init segments into a common one with two track IDs.
func TestCombineInitSegments(t *testing.T) {
	files := []string{
		"./testdata/V300/init.mp4",
		"./testdata/A48/init.mp4",
	}
	trackIDs := []uint32{1, 2}

	combinedInit, err := combineInitSegments(files, trackIDs)
	if err != nil {
		t.Error(err)
	}
	nrTracks := len(combinedInit.Moov.Traks)
	if nrTracks != 2 {
		t.Errorf("expected 2 tracks, got %d", nrTracks)
	}
}
