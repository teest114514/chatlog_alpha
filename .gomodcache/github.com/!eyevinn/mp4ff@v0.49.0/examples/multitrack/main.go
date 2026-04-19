// multitrack - decode example multitrack fragmented file with video and closed caption tracks
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Eyevinn/mp4ff/avc"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	// filePath is start of a track of track v1 from
	// https://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8
	filePath = "testdata/main_1.mp4"
)

// Track - information for an mp4 track
type Track struct {
	trackID   uint32
	hdlrType  string
	timeScale uint64
	trak      *mp4.TrakBox
	trex      *mp4.TrexBox
	samples   []mp4.FullSample
}

func main() {
	ifd, err := os.Open(filePath)
	if err != nil {
		log.Fatalln(err)
	}
	defer ifd.Close()

	tracks, err := getTracksAndSamplesFromMultiTrackFragmentedFile(ifd)
	if err != nil {
		log.Fatalln(err)
	}

	err = writeTrackInfo(os.Stdout, tracks)
	if err != nil {
		log.Fatalln(err)
	}

	for _, track := range tracks {
		if track.hdlrType == "clcp" {
			err = writeScenaristFile(os.Stdout, track)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}
}

func getTracksAndSamplesFromMultiTrackFragmentedFile(ifd io.Reader) (tracks []*Track, err error) {
	parsedMp4, err := mp4.DecodeFile(ifd)
	if err != nil {
		log.Fatalln(err)
	}
	traks := parsedMp4.Moov.Traks

	for _, trak := range traks {
		track := &Track{}
		track.trak = trak
		track.trackID = trak.Tkhd.TrackID
		track.timeScale = uint64(trak.Mdia.Mdhd.Timescale)
		track.hdlrType = trak.Mdia.Hdlr.HandlerType
		for _, trex := range parsedMp4.Moov.Mvex.Trexs {
			if trex.TrackID == track.trackID {
				track.trex = trex
				break
			}
		}
		tracks = append(tracks, track)
	}

	for _, seg := range parsedMp4.Segments {
		for _, frag := range seg.Fragments {
			for _, track := range tracks {
				samples, err := frag.GetFullSamples(track.trex)
				if err != nil {
					log.Fatalln(err)
				}
				track.samples = append(track.samples, samples...)
			}
		}
	}
	return tracks, nil
}

func writeTrackInfo(w io.Writer, tracks []*Track) error {
	for _, track := range tracks {
		fmt.Fprintf(w, "Track %d %s has %d samples and timescale %d\n", track.trackID,
			track.hdlrType, len(track.samples), track.timeScale)
		switch track.hdlrType {
		case "vide":
			for i, sample := range track.samples {
				fmt.Fprintf(w, "%d %d (%dB) %v\n", i+1, sample.PresentationTime(), len(sample.Data),
					avc.FindNaluTypes(sample.Data))
			}
		case "clcp": // Should contain cdat boxes with CEA-608 byte pairs
			for i, sample := range track.samples {
				fmt.Fprintf(w, "%d %d %d %s\n", i+1, sample.PresentationTime(), sample.Dur,
					hex.EncodeToString(sample.Data))
			}
		}
	}
	return nil
}

// writeScenaristFile - write file from clcp track with cdat samples
func writeScenaristFile(w io.Writer, clcpTrack *Track) error {
	_, err := fmt.Fprintf(w, "Scenarist_SCC V1.0\n")
	if err != nil {
		return err
	}
	for _, sample := range clcpTrack.samples {
		tMs := sample.PresentationTime() * 1000 / clcpTrack.timeScale
		msg := timeFromMs(tMs)
		buf := bytes.NewBuffer(sample.Data)
		box, err := mp4.DecodeBox(0, buf)
		if err != nil {
			return err
		}
		cdat, ok := box.(*mp4.CdatBox)
		if !ok {
			return fmt.Errorf("box type is not cdat")
		}
		dataStr := hex.EncodeToString(cdat.Data)
		for i := 0; i < len(dataStr); i += 4 {
			msg += " " + dataStr[i:i+4]
		}
		_, err = fmt.Fprintf(w, "\n%s\n", msg)
		if err != nil {
			return err
		}
	}
	return nil
}

// timeFromMs - return time string hh:mm:ss:fr where fr is frame (~29.97Hz)
func timeFromMs(tMs uint64) string {
	frac := tMs % 1000
	allSecs := (tMs - frac) / 1000
	secs := allSecs % 60
	allMins := (allSecs - secs) / 60
	mins := allMins % 60
	hours := (allMins - mins) / 60
	return fmt.Sprintf("%02d:%02d:%02d:%02d", hours, mins, secs, frac/34)
}
