package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Eyevinn/mp4ff/internal"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	appName = "mp4ff-subslister"
)

var usg = `%s lists and displays content of wvtt or stpp samples.
These corresponds to WebVTT or TTML subtitles in ISOBMFF files.
Uses track with given non-zero track ID or first subtitle track found in an asset.

Usage of %s:
`

type options struct {
	maxNrSamples int
	trackID      int
	version      bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options]\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.IntVar(&opts.maxNrSamples, "m", -1, "Max nr of samples to parse")
	fs.IntVar(&opts.trackID, "t", 0, "trackID to extract (0 is unspecified)")
	fs.BoolVar(&opts.version, "version", false, "Get mp4ff version")

	err := fs.Parse(args[1:])
	return &opts, err
}

func main() {
	if err := run(os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	o, err := parseOptions(fs, args)

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if o.version {
		fmt.Fprintf(stdout, "%s %s\n", appName, internal.GetVersion())
		return nil
	}

	if len(fs.Args()) != 1 {
		fs.Usage()
		return fmt.Errorf("missing input file")
	}

	inFilePath := fs.Arg(0)

	ifd, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer ifd.Close()

	parsedMp4, err := mp4.DecodeFile(ifd, mp4.WithDecodeFlags(mp4.DecISMFlag))
	if err != nil {
		return err
	}

	if !parsedMp4.IsFragmented() { // Progressive file
		err = parseProgressiveMp4(parsedMp4, stdout, uint32(o.trackID), o.maxNrSamples)
		if err != nil {
			return err
		}
		return nil
	}

	// Fragmented file
	err = parseFragmentedMp4(parsedMp4, stdout, uint32(o.trackID), o.maxNrSamples)
	if err != nil {
		return err
	}
	return nil
}

func findTrack(moov *mp4.MoovBox, hdlrType string, trackID uint32) (*mp4.TrakBox, error) {
	for _, inTrak := range moov.Traks {
		if trackID != 0 {
			if inTrak.Tkhd.TrackID != trackID {
				continue
			}
			return inTrak, nil
		}
		if inTrak.Mdia.Hdlr.HandlerType != hdlrType {
			continue
		}
		return inTrak, nil
	}
	return nil, fmt.Errorf("no matching track found")
}

type subtitleTrack struct {
	variant string
	trak    *mp4.TrakBox
}

func parseProgressiveMp4(f *mp4.File, w io.Writer, trackID uint32, maxNrSamples int) error {
	subsTrak, err := findWvttTrack(f.Moov, w, trackID)
	if err != nil {
		subsTrak, err = findStppTrack(f.Moov, w, trackID)
		if err != nil {
			return fmt.Errorf("no subtitle track found: %w", err)
		}
	}
	stbl := subsTrak.trak.Mdia.Minf.Stbl
	nrSamples := stbl.Stsz.SampleNumber
	mdat := f.Mdat
	mdatPayloadStart := mdat.PayloadAbsoluteOffset()
	for sampleNr := 1; sampleNr <= int(nrSamples); sampleNr++ {
		chunkNr, sampleNrAtChunkStart, err := stbl.Stsc.ChunkNrFromSampleNr(sampleNr)
		if err != nil {
			return err
		}
		var offset int64
		if stbl.Stco != nil {
			offset = int64(stbl.Stco.ChunkOffset[chunkNr-1])
		} else if stbl.Co64 != nil {
			offset = int64(stbl.Co64.ChunkOffset[chunkNr-1])
		}
		for sNr := sampleNrAtChunkStart; sNr < sampleNr; sNr++ {
			offset += int64(stbl.Stsz.GetSampleSize(sNr))
		}
		size := stbl.Stsz.GetSampleSize(sampleNr)
		decTime, dur := stbl.Stts.GetDecodeTime(uint32(sampleNr))
		var cto int32 = 0
		if stbl.Ctts != nil {
			cto = stbl.Ctts.GetCompositionTimeOffset(uint32(sampleNr))
		}
		// Next find sample bytes as slice in mdat
		offsetInMdatData := uint64(offset) - mdatPayloadStart
		sample := mdat.Data[offsetInMdatData : offsetInMdatData+uint64(size)]
		switch subsTrak.variant {
		case "wvtt":
			err = printWvttSample(w, sample, sampleNr, decTime+uint64(cto), dur)
		case "stpp":
			err = printStppSample(w, sample, sampleNr, decTime+uint64(cto), dur)
		}
		if err != nil {
			return err
		}
		if sampleNr == maxNrSamples {
			break
		}
	}
	return nil
}

func findWvttTrack(moov *mp4.MoovBox, w io.Writer, trackID uint32) (*subtitleTrack, error) {
	subsTrak, err := findTrack(moov, "text", trackID)
	if err != nil {
		return nil, err
	}

	stbl := subsTrak.Mdia.Minf.Stbl
	if stbl.Stsd.Wvtt == nil {
		return nil, fmt.Errorf("no wvtt track found")
	}

	fmt.Fprintf(w, "Track %d, timescale = %d\n", subsTrak.Tkhd.TrackID, subsTrak.Mdia.Mdhd.Timescale)
	err = stbl.Stsd.Wvtt.VttC.Info(os.Stdout, "", "  ", "  ")
	if err != nil {
		return nil, err
	}
	return &subtitleTrack{
		variant: "wvtt",
		trak:    subsTrak,
	}, nil
}

func findStppTrack(moov *mp4.MoovBox, w io.Writer, trackID uint32) (*subtitleTrack, error) {
	subsTrak, err := findTrack(moov, "subt", trackID)
	if err != nil {
		return nil, err
	}

	stbl := subsTrak.Mdia.Minf.Stbl
	if stbl.Stsd.Stpp == nil {
		return nil, fmt.Errorf("no stpp track found")
	}

	fmt.Fprintf(w, "Track %d, timescale = %d\n", subsTrak.Tkhd.TrackID, subsTrak.Mdia.Mdhd.Timescale)
	err = stbl.Stsd.Stpp.Info(w, "", "  ", "  ")
	if err != nil {
		return nil, err
	}
	return &subtitleTrack{
		variant: "stpp",
		trak:    subsTrak,
	}, nil
}

func parseFragmentedMp4(f *mp4.File, w io.Writer, trackID uint32, maxNrSamples int) error {
	var subsTrex *mp4.TrexBox
	var subsTrak *subtitleTrack
	var err error
	if f.Init != nil { // Print vttC header and timescale if moov-box is present
		subsTrak, err = findWvttTrack(f.Moov, w, trackID)
		if err != nil {
			subsTrak, err = findStppTrack(f.Moov, w, trackID)
			if err != nil {
				return fmt.Errorf("no subtitle track found: %w", err)
			}
		}
		for _, trex := range f.Init.Moov.Mvex.Trexs {
			if trex.TrackID == subsTrak.trak.Tkhd.TrackID {
				subsTrex = trex
			}
		}
	}
	iSamples := make([]mp4.FullSample, 0)
	for _, iSeg := range f.Segments {
		for _, iFrag := range iSeg.Fragments {
			var tfraTime uint64
			if f.Mfra != nil {
				moofOffset := iFrag.Moof.StartPos
				entry := f.Mfra.FindEntry(moofOffset, iFrag.Moof.Traf.Tfhd.TrackID)
				if entry != nil {
					tfraTime = entry.Time
				}
			}
			fSamples, err := iFrag.GetFullSamples(subsTrex)
			if err != nil {
				return err
			}
			if tfraTime != 0 && fSamples[0].DecodeTime == 0 {
				for i := range fSamples {
					fSamples[i].DecodeTime += tfraTime
				}
			}
			iSamples = append(iSamples, fSamples...)
		}
	}
	if subsTrak == nil {
		if len(iSamples) == 0 {
			return fmt.Errorf("no subtitle samples found")
		}
		variant := "stpp"
		if iSamples[0].Data[0] == 0 { // Only wvtt start with a length field.
			variant = "wvtt"
		}

		subsTrak = &subtitleTrack{
			variant: variant,
		}
	}
	for i, sample := range iSamples {
		switch subsTrak.variant {
		case "wvtt":
			err = printWvttSample(w, sample.Data, i+1, sample.PresentationTime(), sample.Dur)
		case "stpp":
			err = printStppSample(w, sample.Data, i+1, sample.PresentationTime(), sample.Dur)
		default:
			return fmt.Errorf("unknown subtitle track type")
		}

		if err != nil {
			return err
		}
		if i+1 == maxNrSamples {
			break
		}
	}
	return nil
}

func printWvttSample(w io.Writer, sample []byte, nr int, pts uint64, dur uint32) error {
	fmt.Fprintf(w, "Sample %d, pts=%d, dur=%d\n", nr, pts, dur)
	buf := bytes.NewBuffer(sample)
	pos := 0
	for {
		box, err := mp4.DecodeBox(uint64(pos), buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		err = box.Info(w, "  ", "", "  ")
		if err != nil {
			return err
		}
		pos += int(box.Size())
		if pos >= len(sample) {
			break
		}
	}
	return nil
}

func printStppSample(w io.Writer, sample []byte, nr int, pts uint64, dur uint32) error {
	fmt.Fprintf(w, "Sample %d, pts=%d, dur=%d\n", nr, pts, dur)
	_, err := w.Write(sample)
	return err
}
