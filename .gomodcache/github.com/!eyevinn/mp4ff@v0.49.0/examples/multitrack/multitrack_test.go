package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

const (
	inMultiTrackMp4File = "testdata/main_1.mp4"
	goldenSampleList    = "testdata/golden_samples.txt"
	goldenScenarist     = "testdata/golden_captions.scc"
)

func TestDecodeEncodeMultiTrack(t *testing.T) {
	ifd, err := os.Open(inMultiTrackMp4File)
	if err != nil {
		t.Error(err)
	}
	defer ifd.Close()

	tracks, err := getTracksAndSamplesFromMultiTrackFragmentedFile(ifd)
	if err != nil {
		t.Error(err)
	}

	var buf bytes.Buffer
	err = writeTrackInfo(&buf, tracks)
	if err != nil {
		t.Error(err)
	}

	err = compareOrUpdateGolden(t, buf.Bytes(), goldenSampleList)
	if err != nil {
		t.Error(err)
	}
}

func TestDecodeClcp(t *testing.T) {
	ifd, err := os.Open(inMultiTrackMp4File)
	if err != nil {
		t.Error(err)
	}
	defer ifd.Close()

	tracks, err := getTracksAndSamplesFromMultiTrackFragmentedFile(ifd)
	if err != nil {
		t.Error(err)
	}

	for _, track := range tracks {
		if track.hdlrType == "clcp" {
			var buf bytes.Buffer
			err = writeScenaristFile(&buf, track)
			if err != nil {
				t.Error(err)
			}
			err = compareOrUpdateGolden(t, buf.Bytes(), goldenScenarist)
			if err != nil {
				t.Error(err)
			}
		}
	}
}

func TestGetMultiTrackSamples(t *testing.T) {
	ifd, err := os.Open(inMultiTrackMp4File)
	if err != nil {
		t.Error(err)
	}
	defer ifd.Close()

	parsedMp4, err := mp4.DecodeFile(ifd)
	if err != nil {
		t.Error(err)
	}

	var buf bytes.Buffer
	parsedMp4.FragEncMode = mp4.EncModeBoxTree
	parsedMp4.EncOptimize = mp4.OptimizeNone
	err = parsedMp4.Encode(&buf)
	if err != nil {
		t.Error(err)
	}

	inFileRaw, err := os.ReadFile(filePath)
	if err != nil {
		t.Error(err)
	}

	diff := deep.Equal(buf.Bytes(), inFileRaw)
	if diff != nil {
		t.Errorf("Encoded multi-track file not same as input for %s", inMultiTrackMp4File)
	}
}
