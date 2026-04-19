package mp4_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Eyevinn/mp4ff/aac"
	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	avcSPSnalu  = "67640020accac05005bb0169e0000003002000000c9c4c000432380008647c12401cb1c31380"
	avcPPSnalu  = "68b5df20"
	hevcVPSnalu = "40010c01ffff022000000300b0000003000003007b18b024"
	hevcSPSnalu = "420101022000000300b0000003000003007ba0078200887db6718b92448053888892cf24a69272c9124922dc91aa48fca223ff000100016a02020201"
	hevcPPSnalu = "4401c0252f053240"
)

func TestCreateInitSegments(t *testing.T) {
	init, err := createVideoAVCInitSegment()
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "video" {
		t.Errorf("got %s, wanted video", init.GetMediaType())
	}
	init, err = createVideoHEVCInitSegment()
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "video" {
		t.Errorf("got %s, wanted video", init.GetMediaType())
	}
	init, err = createAudioAACInitSegment(48000, aac.AAClc)
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "audio" {
		t.Errorf("got %s, wanted audio", init.GetMediaType())
	}
	init, err = createAudioAACInitSegment(24000, aac.HEAACv1)
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "audio" {
		t.Errorf("got %s, wanted audio", init.GetMediaType())
	}
	init, err = createAudioAACInitSegment(48000, aac.AAClc)
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "audio" {
		t.Errorf("got %s, wanted audio", init.GetMediaType())
	}
	init, err = createAudioAACInitSegment(24000, aac.HEAACv1)
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "audio" {
		t.Errorf("got %s, wanted audio", init.GetMediaType())
	}
	init, err = createAudioAACInitSegment(24000, aac.HEAACv2)
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "audio" {
		t.Errorf("got %s, wanted audio", init.GetMediaType())
	}

	init, err = createAudioAC3InitSegment()
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "audio" {
		t.Errorf("got %s, wanted audio", init.GetMediaType())
	}
	init, err = createAudioEC3InitSegment()
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "audio" {
		t.Errorf("got %s, wanted audio", init.GetMediaType())
	}
	init, err = createSubtitlesWvttInitSegment()
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "unknown" {
		t.Errorf("got %s, wanted unknown", init.GetMediaType())
	}
	init, err = createSubtitlesStppInitSegment()
	if err != nil {
		t.Error(err)
	}
	if init.GetMediaType() != "unknown" {
		t.Errorf("got %s, wanted unknown", init.GetMediaType())
	}
}

func createVideoAVCInitSegment() (*mp4.InitSegment, error) {
	sps, _ := hex.DecodeString(avcSPSnalu)
	spsNALUs := [][]byte{sps}
	pps, _ := hex.DecodeString(avcPPSnalu)
	ppsNALUs := [][]byte{pps}

	videoTimescale := uint32(180000)
	init := mp4.CreateEmptyInit()
	init.AddEmptyTrack(videoTimescale, "video", "und")
	trak := init.Moov.Trak
	includePS := true
	err := trak.SetAVCDescriptor("avc1", spsNALUs, ppsNALUs, includePS)
	if err != nil {
		return nil, err
	}
	width := trak.Mdia.Minf.Stbl.Stsd.AvcX.Width
	height := trak.Mdia.Minf.Stbl.Stsd.AvcX.Height
	if width != 1280 || height != 720 {
		return nil, fmt.Errorf("got %dx%d instead of 1280x720", width, height)
	}
	return init, nil
}

func createVideoHEVCInitSegment() (*mp4.InitSegment, error) {
	vps, _ := hex.DecodeString(hevcVPSnalu)
	vpsNALUs := [][]byte{vps}
	sps, _ := hex.DecodeString(hevcSPSnalu)
	spsNALUs := [][]byte{sps}
	pps, _ := hex.DecodeString(hevcPPSnalu)
	ppsNALUs := [][]byte{pps}

	videoTimescale := uint32(180000)
	init := mp4.CreateEmptyInit()
	init.AddEmptyTrack(videoTimescale, "video", "und")
	trak := init.Moov.Trak
	err := trak.SetHEVCDescriptor("hvc1", vpsNALUs, spsNALUs, ppsNALUs, nil, true)
	if err != nil {
		return nil, err
	}
	width := trak.Mdia.Minf.Stbl.Stsd.HvcX.Width
	height := trak.Mdia.Minf.Stbl.Stsd.HvcX.Height
	if width != 960 || height != 540 {
		return nil, fmt.Errorf("got %dx%d instead of 960x540", width, height)
	}
	return init, nil
}

func createAudioAACInitSegment(timeScale uint32, objType byte) (*mp4.InitSegment, error) {
	init := mp4.CreateEmptyInit()
	init.AddEmptyTrack(timeScale, "audio", "en")
	trak := init.Moov.Trak
	err := trak.SetAACDescriptor(objType, int(timeScale))
	if err != nil {
		return nil, err
	}
	return init, nil
}

func createAudioAC3InitSegment() (*mp4.InitSegment, error) {
	dac3Hex := "0000000b646163330c3dc0"
	dac3Bytes, err := hex.DecodeString(dac3Hex)
	if err != nil {
		return nil, err
	}
	sr := bits.NewFixedSliceReader(dac3Bytes)
	box, err := mp4.DecodeBoxSR(0, sr)
	if err != nil {
		return nil, err
	}
	dac3 := box.(*mp4.Dac3Box)
	init := mp4.CreateEmptyInit()
	samplingRate := mp4.AC3SampleRates[dac3.FSCod]
	init.AddEmptyTrack(uint32(samplingRate), "audio", "en")
	trak := init.Moov.Trak
	err = trak.SetAC3Descriptor(dac3)
	if err != nil {
		return nil, err
	}
	return init, nil
}

func createAudioEC3InitSegment() (*mp4.InitSegment, error) {
	dec3Hex := "0000000e646563330c00200f0202"
	dec3Bytes, err := hex.DecodeString(dec3Hex)
	if err != nil {
		return nil, err
	}
	sr := bits.NewFixedSliceReader(dec3Bytes)
	box, err := mp4.DecodeBoxSR(0, sr)
	if err != nil {
		return nil, err
	}
	dec3 := box.(*mp4.Dec3Box)
	init := mp4.CreateEmptyInit()
	samplingRate := mp4.AC3SampleRates[dec3.EC3Subs[0].FSCod]
	init.AddEmptyTrack(uint32(samplingRate), "audio", "en")
	trak := init.Moov.Trak
	err = trak.SetEC3Descriptor(dec3)
	if err != nil {
		return nil, err
	}
	return init, err
}

func createSubtitlesWvttInitSegment() (*mp4.InitSegment, error) {
	subtitleTimescale := 1000
	init := mp4.CreateEmptyInit()
	init.AddEmptyTrack(uint32(subtitleTimescale), "wvtt", "en")
	trak := init.Moov.Trak
	err := trak.SetWvttDescriptor("WEBVTT")
	if err != nil {
		return nil, err
	}
	return init, nil
}

func createSubtitlesStppInitSegment() (*mp4.InitSegment, error) {
	subtitleTimescale := 1000
	init := mp4.CreateEmptyInit()
	init.AddEmptyTrack(uint32(subtitleTimescale), "stpp", "en")
	trak := init.Moov.Trak
	schemaLocation := ""
	auxiliaryMimeType := ""
	err := trak.SetStppDescriptor("http://www.w3.org/ns/ttml", schemaLocation, auxiliaryMimeType)
	if err != nil {
		return nil, err
	}
	return init, nil
}
