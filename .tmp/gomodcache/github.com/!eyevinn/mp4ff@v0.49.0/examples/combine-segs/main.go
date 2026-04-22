package main

import (
	"fmt"
	"io"
	"os"
	"path"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

func main() {
	if err := run("."); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	trackIDs := []uint32{1, 2}
	initSegFiles := []string{"testdata/V300/init.mp4", "testdata/A48/init.mp4"}
	combinedInitSeg, err := combineInitSegments(initSegFiles, trackIDs)
	if err != nil {
		return err
	}
	err = writeSeg(combinedInitSeg, path.Join(outDir, "combined-init.mp4"))
	if err != nil {
		return err
	}

	mediaSegFiles := []string{"testdata/V300/1.m4s", "testdata/A48/1.m4s"}
	combinedMediaSeg, err := combineMediaSegments(mediaSegFiles, trackIDs)
	if err != nil {
		return err
	}
	return writeSeg(combinedMediaSeg, path.Join(outDir, "combined-1.m4s"))
}

func combineInitSegments(files []string, newTrackIDs []uint32) (*mp4.InitSegment, error) {
	var combinedInit *mp4.InitSegment
	for i := 0; i < len(files); i++ {
		data, err := os.ReadFile(files[i])
		if err != nil {
			return nil, fmt.Errorf("failed to read init segment: %w", err)
		}
		sr := bits.NewFixedSliceReader(data)
		f, err := mp4.DecodeFileSR(sr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode init segment: %w", err)
		}
		init := f.Init
		if len(init.Moov.Traks) != 1 {
			return nil, fmt.Errorf("expected exactly one track per init file")
		}
		init.Moov.Trak.Tkhd.TrackID = newTrackIDs[i]
		if init.Moov.Mvex != nil && init.Moov.Mvex.Trex != nil {
			init.Moov.Mvex.Trex.TrackID = newTrackIDs[i]
		}
		if i == 0 {
			combinedInit = init
		} else {
			combinedInit.Moov.AddChild(init.Moov.Trak)
			if init.Moov.Mvex != nil {
				if init.Moov.Mvex.Trex != nil {
					combinedInit.Moov.Mvex.AddChild(init.Moov.Mvex.Trex)
				}
				if init.Moov.Mvex.Mehd != nil {
					combinedInit.Moov.Mvex.AddChild(init.Moov.Mvex.Mehd)
				}
			}
		}
	}
	return combinedInit, nil
}

func combineMediaSegments(files []string, newTrackIDs []uint32) (*mp4.MediaSegment, error) {
	var combinedSeg *mp4.MediaSegment
	var outFrag *mp4.Fragment
	for i := 0; i < len(files); i++ {
		data, err := os.ReadFile(files[i])
		if err != nil {
			return nil, fmt.Errorf("failed to read media segment: %w", err)
		}
		sr := bits.NewFixedSliceReader(data)
		f, err := mp4.DecodeFileSR(sr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode media segment: %w", err)
		}
		if len(f.Segments) != 1 {
			return nil, fmt.Errorf("expected exactly one media segment per file")
		}
		seg := f.Segments[0]

		if i == 0 {
			if seg.Styp != nil {
				combinedSeg = mp4.NewMediaSegmentWithStyp(seg.Styp)
			} else {
				combinedSeg = mp4.NewMediaSegmentWithoutStyp()
			}
		}
		if len(seg.Fragments) != 1 {
			return nil, fmt.Errorf("expected exactly one fragment per media segment")
		}
		frag := seg.Fragments[0]
		if len(frag.Moof.Trafs) != 1 {
			return nil, fmt.Errorf("expected exactly one traf per fragment")
		}
		if i == 0 {
			seqNr := frag.Moof.Mfhd.SequenceNumber
			outFrag, err = mp4.CreateMultiTrackFragment(seqNr, newTrackIDs)
			if err != nil {
				return nil, fmt.Errorf("failed to create fragment: %w", err)
			}
			combinedSeg.AddFragment(outFrag)
		}
		var trex *mp4.TrexBox = nil // Here we should have the trex from the corresponding init segment
		fss, err := frag.GetFullSamples(trex)
		if err != nil {
			return nil, fmt.Errorf("failed to get full samples: %w", err)
		}
		for _, fs := range fss {
			_ = outFrag.AddFullSampleToTrack(fs, newTrackIDs[i])
		}
	}
	return combinedSeg, nil
}

func writeSeg(seg encoder, filename string) error {
	ofh, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer ofh.Close()
	err = seg.Encode(ofh)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", filename)
	return nil
}

type encoder interface {
	Encode(w io.Writer) error
}
