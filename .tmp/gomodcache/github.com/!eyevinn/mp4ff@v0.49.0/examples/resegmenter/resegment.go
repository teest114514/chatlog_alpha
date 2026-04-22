package main

import (
	"fmt"
	"io"

	"github.com/Eyevinn/mp4ff/mp4"
)

// Resegment file into multiple segments
func Resegment(w io.Writer, in *mp4.File, chunkDur uint64, verbose bool) (*mp4.File, error) {
	if !in.IsFragmented() {
		return nil, fmt.Errorf("input file is not fragmented")
	}

	nrSamples := 0
	for _, iSeg := range in.Segments {
		for _, iFrag := range iSeg.Fragments {
			trun := iFrag.Moof.Traf.Trun
			nrSamples += int(trun.SampleCount())
		}
	}
	inSamples := make([]mp4.FullSample, 0, nrSamples)

	var trex *mp4.TrexBox
	if in.Init != nil {
		trex = in.Init.Moov.Mvex.Trex
	}
	for _, iSeg := range in.Segments {
		for _, iFrag := range iSeg.Fragments {
			fSamples, err := iFrag.GetFullSamples(trex)
			if err != nil {
				return nil, err
			}
			inSamples = append(inSamples, fSamples...)
		}
	}
	inStyp := in.Segments[0].Styp
	inMoof := in.Segments[0].Fragments[0].Moof
	trackID := inMoof.Traf.Tfhd.TrackID

	nrChunksOut := uint64(nrSamples)*uint64(inSamples[0].Dur)/chunkDur + 1 // approximative, but good for allocation

	oFile := mp4.NewFile()
	oFile.Children = make([]mp4.Box, 0, 2+nrChunksOut*3) //  ftyp + moov + (styp+moof+mdat for each segment)
	if in.Init != nil {
		oFile.AddChild(in.Ftyp, 0)
		oFile.AddChild(in.Moov, 0)
	}

	currOutSeqNr := uint32(1)
	frag, err := addNewSegment(oFile, inStyp, currOutSeqNr, trackID)
	if err != nil {
		return nil, err
	}
	if verbose {
		fmt.Fprintf(w, "Started segment %d at dts=%d pts=%d\n", 1, inSamples[0].DecodeTime, inSamples[0].PresentationTime())
	}
	nextSampleNrToWrite := 1

	for nr, s := range inSamples {
		if verbose && s.IsSync() {
			fmt.Fprintf(w, "%4d DTS %d PTS %d\n", nr, s.DecodeTime, s.PresentationTime())
		}
		if s.PresentationTime() >= chunkDur*uint64(currOutSeqNr) && s.IsSync() {
			err = addSamplesToFrag(frag, inSamples, nextSampleNrToWrite, nr+1, trackID)
			if err != nil {
				return nil, err
			}
			nextSampleNrToWrite = nr + 1
			currOutSeqNr++
			frag, err = addNewSegment(oFile, inStyp, currOutSeqNr, trackID)
			if err != nil {
				return nil, err
			}
			if verbose {
				fmt.Fprintf(w, "Started segment %d at dts=%d pts=%d\n", currOutSeqNr, s.DecodeTime, s.PresentationTime())
			}
		}
	}
	err = addSamplesToFrag(frag, inSamples, nextSampleNrToWrite, len(inSamples)+1, trackID)
	if err != nil {
		return nil, err
	}

	return oFile, nil
}

func addSamplesToFrag(frag *mp4.Fragment, samples []mp4.FullSample, nextSampleNrToWrite, stopNr int, trackID uint32) error {
	totSize := uint64(0)
	for nr := nextSampleNrToWrite; nr < stopNr; nr++ {
		totSize += uint64(samples[nr-1].Size)
	}
	frag.Mdat.Data = make([]byte, 0, totSize)
	frag.Moof.Traf.Trun.Samples = make([]mp4.Sample, 0, stopNr-nextSampleNrToWrite+2)
	for nr := nextSampleNrToWrite; nr < stopNr; nr++ {
		err := frag.AddFullSampleToTrack(samples[nr-1], trackID)
		if err != nil {
			return err
		}
	}
	return nil
}

func addNewSegment(oFile *mp4.File, styp *mp4.StypBox, seqNr, trackID uint32) (*mp4.Fragment, error) {
	oFile.AddChild(styp, 0)
	frag, err := mp4.CreateFragment(seqNr, trackID)
	if err != nil {
		return nil, err
	}
	for _, box := range frag.GetChildren() {
		oFile.AddChild(box, 0)
	}
	return frag, nil
}
