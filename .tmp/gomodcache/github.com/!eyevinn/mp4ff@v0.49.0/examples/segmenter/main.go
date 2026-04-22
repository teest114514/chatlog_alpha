package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	appName = "segmenter"
)

var usg = `%s segments a progressive mp4 file into init and media segments.

The output is either single-track segments, or muxed multi-track segments.
With the -lazy mode, mdat is read and written lazily. The lazy write
is only for single-track segments, to provide a comparison with the multi-track
implementation.
There should be at most one audio and one video track in the input.
The output files will be named as
init segments: <output>_a.mp4 and <output>_v.mp4
media segments: <output>_a_<n>.m4s and <output>_v_<n>.m4s where n >= 1
or init.mp4 and media_<n>.m4s

Codecs supported are AVC and HEVC for video and AAC and AC-3 for audio.

Usage of %s:
`

type options struct {
	chunkDurMS uint64
	multipex   bool
	lazy       bool
	verbose    bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] infile outfilePrefix\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.Uint64Var(&opts.chunkDurMS, "d", 0,
		"Required: segment duration (milliseconds). The segments will start at syncSamples with decoded time >= n*segDur")
	fs.BoolVar(&opts.multipex, "m", false, "Output multiplexed segments")
	fs.BoolVar(&opts.lazy, "lazy", false, "Read/write mdat lazily")
	fs.BoolVar(&opts.verbose, "v", false, "Verbose output")

	err := fs.Parse(args[1:])
	return &opts, err
}

func main() {
	if err := run(os.Args, "."); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, outDir string) error {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	o, err := parseOptions(fs, args)

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if len(fs.Args()) != 2 {
		fs.Usage()
		return fmt.Errorf("infile and outfilePrefix must be set")
	}

	if o.chunkDurMS == 0 {
		fs.Usage()
		return fmt.Errorf("segment duration must be set (and positive)")
	}

	ifd, err := os.Open(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer ifd.Close()

	outfilePrefix := path.Join(outDir, fs.Arg(1))

	var parsedMp4 *mp4.File
	if o.lazy {
		parsedMp4, err = mp4.DecodeFile(ifd, mp4.WithDecodeMode(mp4.DecModeLazyMdat))
	} else {
		parsedMp4, err = mp4.DecodeFile(ifd)
	}
	if err != nil {
		return fmt.Errorf("error decoding file: %w", err)
	}
	segmenter, err := NewSegmenter(parsedMp4)
	if err != nil {
		return fmt.Errorf("error creating segmenter: %w", err)
	}
	syncTimescale, segmentStarts := getSegmentStartsFromVideo(parsedMp4, uint32(o.chunkDurMS))
	fmt.Printf("segment starts in timescale %d: %v\n", syncTimescale, segmentStarts)
	err = segmenter.SetTargetSegmentation(syncTimescale, segmentStarts)
	if err != nil {
		return fmt.Errorf("error setting target segmentation: %w", err)
	}
	if o.multipex {
		err = makeMultiTrackSegments(segmenter, parsedMp4, ifd, outfilePrefix)
	} else {
		if o.lazy {
			err = makeSingleTrackSegmentsLazyWrite(segmenter, parsedMp4, ifd, outfilePrefix)
		} else {
			err = makeSingleTrackSegments(segmenter, parsedMp4, nil, outfilePrefix)
		}
	}
	if err != nil {
		return err
	}
	return nil
}
