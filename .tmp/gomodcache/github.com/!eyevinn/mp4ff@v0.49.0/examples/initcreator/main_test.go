package main

import (
	"fmt"
	"os"
	"sort"
	"testing"
)

func TestCreateAllInitSegments(t *testing.T) {
	tmpDir := t.TempDir()
	err := run(tmpDir)
	if err != nil {
		t.Error(err)
	}
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Error(err)
	}
	fileNames := []string{}
	for _, f := range files {
		fileNames = append(fileNames, f.Name())
	}
	sort.Strings(fileNames)
	fmt.Println(fileNames)
	wantedFileNames := []string{
		"audio_aac_init.cmfa",
		"audio_ac3_init.cmfa",
		"audio_ec3_init.cmfa",
		"subtitles_stpp_init.cmft",
		"subtitles_wvtt_init.cmft",
		"video_avc_init.cmfv",
		"video_hevc_init.cmfv",
	}
	if len(fileNames) != len(wantedFileNames) {
		t.Errorf("got %d files, wanted %d", len(fileNames), len(wantedFileNames))
	}
	for i, f := range fileNames {
		if f != wantedFileNames[i] {
			t.Errorf("got %s, wanted %s", f, wantedFileNames[i])
		}
	}
}
