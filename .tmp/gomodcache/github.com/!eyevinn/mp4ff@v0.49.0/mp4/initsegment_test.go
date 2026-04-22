package mp4_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

const sps1nalu = "674d401fe4605017fcb80b4f00000300010000030032e4800753003a9e08200e58e189c0"
const pps1nalu = "685bdf20"

func parseInitFile(fileName string) (*mp4.File, error) {
	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	f, err := mp4.DecodeFile(fd)
	if err != io.EOF && err != nil {
		return nil, err
	}
	if f.IsFragmented() && f.Init.Ftyp == nil {
		return nil, fmt.Errorf("No ftyp present")
	}

	if f.IsFragmented() && len(f.Init.Moov.Traks) != 1 {
		return nil, fmt.Errorf("Not exactly one track")
	}
	return f, nil
}

// InitSegmentParsing - Check  to read a file with moov box.
func TestInitSegmentParsing(t *testing.T) {
	initFile := "testdata/init1.cmfv"
	f, err := parseInitFile(initFile)
	if err != nil {
		t.Error(err)
	}
	url := f.Init.Moov.Trak.Mdia.Minf.Dinf.Dref.Children[0]
	if url.Type() != "url " {
		t.Errorf("Could not find url box")
	}
	avcC := f.Init.Moov.Trak.Mdia.Minf.Stbl.Stsd.AvcX.AvcC

	wanted := byte(31)
	got := avcC.AVCLevelIndication
	if got != wanted {
		t.Errorf("Got level %d insted of %d", got, wanted)
	}

}

func TestMoovParsingWithBtrt(t *testing.T) {
	initFile := "testdata/init_prog.mp4"
	initDumpGoldenPath := "testdata/golden_init_prog_mp4_dump.txt"
	f, err := parseInitFile(initFile)
	if err != nil {
		t.Error(err)
	}
	url := f.Moov.Trak.Mdia.Minf.Dinf.Dref.Children[0]
	if url.Type() != "url " {
		t.Errorf("Could not find url box")
	}
	avcx := f.Moov.Trak.Mdia.Minf.Stbl.Stsd.AvcX
	avcC := avcx.AvcC

	wanted := byte(31)
	got := avcC.AVCLevelIndication
	if got != wanted {
		t.Errorf("Got level %d insted of %d", got, wanted)
	}

	btrt := avcx.Btrt

	if btrt.AvgBitrate != 1384000 {
		t.Errorf("Got averate bitrate %d instead of %d", btrt.AvgBitrate, 1384000)
	}

	var buf bytes.Buffer
	err = f.Encode(&buf)
	if err != nil {
		t.Error(err)
	}
	initFileBytes, err := os.ReadFile(initFile)
	if err != nil {
		t.Error(err)
	}
	if deep.Equal(buf.Bytes(), initFileBytes) != nil {
		tmpOutput := "testdata/init_tmp.mp4"
		err := writeGolden(t, tmpOutput, buf.Bytes())
		if err == nil {
			t.Errorf("Encoded output not same as input for %s. Wrote %s", initFile, tmpOutput)
		} else {
			t.Errorf("Encoded output not same as input for %s, but error %s when writing  %s", initFile, err, tmpOutput)
		}
	}

	err = compareOrUpdateInfo(t, f, initDumpGoldenPath)
	if err != nil {
		t.Error(err)
	}
}

func TestMoovWithCenc(t *testing.T) {
	initFile := "testdata/init_cenc.cmfv"
	initDumpGoldenPath := "testdata/golden_init_cenc_cmfv_dump.txt"
	f, err := parseInitFile(initFile)
	if err != nil {
		t.Error(err)
	}

	var buf bytes.Buffer
	err = f.Encode(&buf)
	if err != nil {
		t.Error(err)
	}
	initFileBytes, err := os.ReadFile(initFile)
	if err != nil {
		t.Error(err)
	}
	if deep.Equal(buf.Bytes(), initFileBytes) != nil {
		tmpOutput := "testdata/cenc_tmp.mp4"
		err := writeGolden(t, tmpOutput, buf.Bytes())
		if err == nil {
			t.Errorf("Encoded output not same as input for %s. Wrote %s", initFile, tmpOutput)
		} else {
			t.Errorf("Encoded output not same as input for %s, but error %s when writing  %s", initFile, err, tmpOutput)
		}
	}

	err = compareOrUpdateInfo(t, f, initDumpGoldenPath)

	if err != nil {
		t.Error(err)
	}
}

func TestGenerateInitSegment(t *testing.T) {
	goldenAssetPath := "testdata/golden_init_video.mp4"
	goldenDumpPath := "testdata/golden_init_video_mp4_dump.txt"
	sps, _ := hex.DecodeString(sps1nalu)
	spsData := [][]byte{sps}
	pps, _ := hex.DecodeString(pps1nalu)
	ppsData := [][]byte{pps}

	init := mp4.CreateEmptyInit()
	init.AddEmptyTrack(180000, "video", "und")
	trak := init.Moov.Trak
	err := trak.SetAVCDescriptor("avc3", spsData, ppsData, true)
	if err != nil {
		t.Error(err)
	}
	width := trak.Mdia.Minf.Stbl.Stsd.AvcX.Width
	height := trak.Mdia.Minf.Stbl.Stsd.AvcX.Height
	if width != 640 || height != 360 {
		t.Errorf("Got %dx%d instead of 640x360", width, height)
	}
	// Write to a buffer so that we can read and check
	var buf bytes.Buffer
	err = init.Encode(&buf)
	if err != nil {
		t.Error(err)
	}

	initRead, err := mp4.DecodeFile(&buf)
	if err != io.EOF && err != nil {
		t.Error(err)
	}
	if initRead.Moov.Size() != init.Moov.Size() {
		t.Errorf("Mismatch generated vs read moov size: %d != %d", init.Moov.Size(), initRead.Moov.Size())
	}

	// Regenerated buf
	err = init.Encode(&buf)
	if err != nil {
		t.Error(err)
	}

	err = compareOrUpdateInfo(t, init, goldenDumpPath)
	if err != nil {
		t.Error(err)
	}
	// Generate or compare with golden files
	if *update {
		err = writeGolden(t, goldenAssetPath, buf.Bytes())
		if err != nil {
			t.Error(err)
		}
		return
	}

	golden, err := os.ReadFile(goldenAssetPath)
	if err != nil {
		t.Error(err)
	}
	diff := deep.Equal(golden, buf.Bytes())
	if diff != nil {
		t.Errorf("Generated init segment different from %s", goldenAssetPath)
	}
}

func TestInitTweakSingleTrakLive(t *testing.T) {
	// Check that mehd box is removed and that multiple tracks is not allowed.
	goldenAssetPath := "testdata/golden_init_video.mp4"
	r, err := os.Open(goldenAssetPath)
	if err != nil {
		t.Error(err)
	}
	f, err := mp4.DecodeFile(r)
	if err != nil {
		t.Error(err)
	}
	moov := f.Init.Moov
	mvex := moov.Mvex
	mehd := mp4.MehdBox{
		FragmentDuration: 1000,
	}
	mvex.AddChild(&mehd)
	err = f.Init.TweakSingleTrakLive()
	if err != nil {
		t.Error(err)
	}
	if mvex.Mehd != nil {
		t.Errorf("Mehd not removed")
	}
	f.Init.AddEmptyTrack(180000, "video", "und")
	err = f.Init.TweakSingleTrakLive()
	wantedErrMsg := "only one track allowed for live"
	if err == nil {
		t.Errorf("Did not get error")
	} else if err.Error() != wantedErrMsg {
		t.Errorf(`Did not get error %q but %q"`, wantedErrMsg, err)
	}
}
