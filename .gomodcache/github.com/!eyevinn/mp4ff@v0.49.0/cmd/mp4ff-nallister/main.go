package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Eyevinn/mp4ff/avc"
	"github.com/Eyevinn/mp4ff/hevc"
	"github.com/Eyevinn/mp4ff/internal"
	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/Eyevinn/mp4ff/sei"
)

const (
	appName = "mp4ff-nallister"
)

var usg = `%s lists NAL units and slice types of AVC or HEVC tracks of an mp4 (ISOBMFF) file
or a file containing a byte stream in Annex B format.

Takes first video track in a progressive file and the first track in a fragmented file.
It can also output information about SEI NAL units.

The parameter-sets can be further analyzed using mp4ff-pslister.

Usage of %s:
`

type options struct {
	maxNrSamples int
	codec        string
	seiLevel     int
	printRaw     int
	annexB       bool
	printPsHex   bool
	version      bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] infile\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.IntVar(&opts.maxNrSamples, "m", -1, "Max nr of samples to parse")
	fs.StringVar(&opts.codec, "c", "avc", "Codec to parse (avc or hevc)")
	fs.IntVar(&opts.seiLevel, "sei", 0, "Level of SEI information (1 is interpret, 2 is dump hex)")
	fs.IntVar(&opts.printRaw, "raw", 0, "nr raw NAL unit bytes to print")
	fs.BoolVar(&opts.annexB, "annexb", false, "Input is Annex B stream file")
	fs.BoolVar(&opts.printPsHex, "ps", false, "Print parameter sets in hex")
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
		return fmt.Errorf("need input file")
	}
	inFilePath := fs.Arg(0)

	// First try to handle Annex B file
	if o.annexB {
		data, err := os.ReadFile(inFilePath)
		if err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}
		sampleData := avc.ConvertByteStreamToNaluSample(data)
		nalus, err := avc.GetNalusFromSample(sampleData)
		if err != nil {
			return fmt.Errorf("error getting NAL units: %w", err)
		}
		frames, err := findAnnexBFrames(nalus, o.codec)
		if err != nil {
			return fmt.Errorf("error finding frames: %w", err)
		}
		var avcSPS *avc.SPS
		for i, frame := range frames {
			if o.codec == "avc" {
				if avcSPS == nil {
					for _, nalu := range frame {
						if avc.GetNaluType(nalu[0]) == avc.NALU_SPS {
							avcSPS, err = avc.ParseSPSNALUnit(nalu, true)
							if err != nil {
								return fmt.Errorf("error parsing SPS: %w", err)
							}
						}
					}
				}
				err = printAVCNalus(stdout, avcSPS, frame, i+1, 0, o.seiLevel, o.printPsHex, o.printRaw)
			} else {
				err = printHEVCNalus(stdout, frame, i+1, 0, o.seiLevel, o.printPsHex, o.printRaw)
			}
			if err != nil {
				return fmt.Errorf("printing error: %w", err)
			}
		}
		return nil
	}

	ifd, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("could not open input file: %w", err)
	}
	defer ifd.Close()
	parsedMp4, err := mp4.DecodeFile(ifd)
	if err != nil {
		return fmt.Errorf("error parsing file: %w", err)
	}

	// Need to handle progressive files as well as fragmented files

	if !parsedMp4.IsFragmented() {
		err = parseProgressiveMp4(stdout, parsedMp4, o.maxNrSamples, o.codec, o.seiLevel, o.printPsHex, o.printRaw)
		if err != nil {
			return fmt.Errorf("error parsing progressive file: %w", err)
		}
		return nil
	}
	err = parseFragmentedMp4(stdout, parsedMp4, o.maxNrSamples, o.codec, o.seiLevel, o.printPsHex, o.printRaw)
	if err != nil {
		return fmt.Errorf("error parsing fragmented file: %w", err)
	}
	return nil
}

func parseProgressiveMp4(w io.Writer, f *mp4.File, maxNrSamples int, codec string, seiLevel int, parameterSets bool, nrRaw int) error {
	videoTrak, ok := findFirstVideoTrak(f.Moov)
	if !ok {
		return fmt.Errorf("no video track found")
	}

	var avcSPS *avc.SPS
	var err error
	stbl := videoTrak.Mdia.Minf.Stbl
	if stbl.Stsd.AvcX != nil {
		codec = "avc"
		if stbl.Stsd.AvcX.AvcC != nil {
			avcSPS, err = avc.ParseSPSNALUnit(stbl.Stsd.AvcX.AvcC.SPSnalus[0], true)
			if err != nil {
				return fmt.Errorf("error parsing SPS: %s", err)
			}
		}
	} else if stbl.Stsd.HvcX != nil {
		codec = "hevc"
	}
	nrSamples := stbl.Stsz.SampleNumber
	mdat := f.Mdat
	mdatPayloadStart := mdat.PayloadAbsoluteOffset()

	for sampleNr := 1; sampleNr <= int(nrSamples); sampleNr++ {
		chunkNr, sampleNrAtChunkStart, err := stbl.Stsc.ChunkNrFromSampleNr(sampleNr)
		if err != nil {
			return err
		}
		offset, err := getChunkOffset(stbl, chunkNr)
		if err != nil {
			return err
		}
		for sNr := sampleNrAtChunkStart; sNr < sampleNr; sNr++ {
			offset += int64(stbl.Stsz.GetSampleSize(sNr))
		}
		size := stbl.Stsz.GetSampleSize(sampleNr)
		decTime, _ := stbl.Stts.GetDecodeTime(uint32(sampleNr))
		var cto int32 = 0
		if stbl.Ctts != nil {
			cto = stbl.Ctts.GetCompositionTimeOffset(uint32(sampleNr))
		}
		// Next find sample bytes as slice in mdat
		offsetInMdatData := uint64(offset) - mdatPayloadStart
		sample := mdat.Data[offsetInMdatData : offsetInMdatData+uint64(size)]
		nalus, err := avc.GetNalusFromSample(sample)
		if err != nil {
			return err
		}
		switch codec {
		case "avc", "h.264", "h264":
			if avcSPS == nil {
				for _, nalu := range nalus {
					if avc.GetNaluType(nalu[0]) == avc.NALU_SPS {
						avcSPS, err = avc.ParseSPSNALUnit(nalu, true)
						if err != nil {
							return fmt.Errorf("error parsing SPS: %s", err)
						}
					}
				}
			}
			err = printAVCNalus(w, avcSPS, nalus, sampleNr, decTime+uint64(cto), seiLevel, parameterSets, nrRaw)
		case "hevc", "h.265", "h265":
			err = printHEVCNalus(w, nalus, sampleNr, decTime+uint64(cto), seiLevel, parameterSets, nrRaw)
		default:
			return fmt.Errorf("unknown codec: %s", codec)
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

func findFirstVideoTrak(moov *mp4.MoovBox) (*mp4.TrakBox, bool) {
	for _, inTrak := range moov.Traks {
		hdlrType := inTrak.Mdia.Hdlr.HandlerType
		if hdlrType != "vide" {
			continue
		}
		return inTrak, true
	}
	return nil, false
}

func getChunkOffset(stbl *mp4.StblBox, chunkNr int) (int64, error) {
	if stbl.Stco != nil {
		return int64(stbl.Stco.ChunkOffset[chunkNr-1]), nil
	}
	if stbl.Co64 != nil {
		return int64(stbl.Co64.ChunkOffset[chunkNr-1]), nil
	}
	return 0, fmt.Errorf("neither stco nor co64 is present")
}

func parseFragmentedMp4(w io.Writer, f *mp4.File, maxNrSamples int, codec string, seiLevel int, parameterSets bool, nrRaw int) error {
	var trex *mp4.TrexBox
	var avcSPS *avc.SPS
	var err error
	if f.Init != nil { // Auto-detect codec if moov box is there
		moov := f.Init.Moov
		videoTrak, ok := findFirstVideoTrak(moov)
		if !ok {
			return fmt.Errorf("no video track found")
		}
		stbl := videoTrak.Mdia.Minf.Stbl
		if stbl.Stsd.AvcX != nil {
			codec = "avc"
			if stbl.Stsd.AvcX.AvcC != nil {
				avcSPS, err = avc.ParseSPSNALUnit(stbl.Stsd.AvcX.AvcC.SPSnalus[0], true)
				if err != nil {
					return fmt.Errorf("error parsing SPS: %s", err)
				}
			}
		} else if stbl.Stsd.HvcX != nil {
			codec = "hevc"
		}
		trex, _ = moov.Mvex.GetTrex(videoTrak.Tkhd.TrackID)
	}
	iSamples := make([]mp4.FullSample, 0)
	for _, iSeg := range f.Segments {
		for _, iFrag := range iSeg.Fragments {
			fSamples, err := iFrag.GetFullSamples(trex)
			if err != nil {
				return err
			}
			iSamples = append(iSamples, fSamples...)
		}
	}
	for i, s := range iSamples {
		nalus, err := avc.GetNalusFromSample(s.Data)
		if err != nil {
			return err
		}
		switch codec {
		case "avc", "h.264", "h264":
			err = printAVCNalus(w, avcSPS, nalus, i+1, s.PresentationTime(), seiLevel, parameterSets, nrRaw)
		case "hevc", "h.265", "h265":
			err = printHEVCNalus(w, nalus, i+1, s.PresentationTime(), seiLevel, parameterSets, nrRaw)
		default:
			return fmt.Errorf("unknown codec: %s", codec)
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

func printAVCNalus(w io.Writer, avcSPS *avc.SPS, nalus [][]byte, nr int, pts uint64, seiLevel int, parameterSets bool, nrRaw int) error {
	msg := ""
	var seiNALUs [][]byte
	totLen := 0
	for i, nalu := range nalus {
		totLen += 4 + len(nalu)
		if i > 0 {
			msg += ","
		}
		naluType := avc.GetNaluType(nalu[0])
		imgType := ""
		var err error
		switch naluType {
		case avc.NALU_SPS:
			avcSPS, err = avc.ParseSPSNALUnit(nalu, true)
			if err != nil {
				return fmt.Errorf("error parsing SPS: %s", err)
			}
		case avc.NALU_NON_IDR, avc.NALU_IDR:
			sliceType, err := avc.GetSliceTypeFromNALU(nalu)
			if err == nil {
				imgType = fmt.Sprintf("[%s] ", sliceType)
			}
		case avc.NALU_SEI:
			if seiLevel > 0 {
				seiNALUs = append(seiNALUs, nalu)
			}
		}
		if nrRaw > 0 {
			msg += fmt.Sprintf("\n %s %s(%dB)", naluType, imgType, len(nalu))
			msg += fmt.Sprintf(" raw: %s", bytesToStringN(nalu, nrRaw))
		} else {
			msg += fmt.Sprintf(" %s %s(%dB)", naluType, imgType, len(nalu))
		}
	}
	fmt.Fprintf(w, "Sample %d, pts=%d (%dB):%s\n", nr, pts, totLen, msg)
	printSEINALus(w, seiNALUs, "avc", seiLevel, avcSPS)
	if parameterSets {
		for _, nalu := range nalus {
			naluType := avc.GetNaluType(nalu[0])
			switch naluType {
			case avc.NALU_SPS:
				fmt.Fprintf(w, "  SPS: %s\n", hex.EncodeToString(nalu))
			case avc.NALU_PPS:
				fmt.Fprintf(w, "  PPS: %s\n", hex.EncodeToString(nalu))
			}
		}
	}
	return nil
}

func printHEVCNalus(w io.Writer, nalus [][]byte, nr int, pts uint64, seiLevel int, parameterSets bool, nrRaw int) error {
	msg := ""
	var seiNALUs [][]byte
	totLen := 0
	for i, nalu := range nalus {
		totLen += 4 + len(nalu)
		if i > 0 {
			msg += ","
		}
		naluType := hevc.GetNaluType(nalu[0])
		if nrRaw > 0 {
			msg += fmt.Sprintf("\n %s (%dB)", naluType, len(nalu))
			msg += fmt.Sprintf(" raw: %s", bytesToStringN(nalu, nrRaw))
		} else {
			msg += fmt.Sprintf(" %s (%dB)", naluType, len(nalu))
		}
		if seiLevel > 0 && (naluType == hevc.NALU_SEI_PREFIX || naluType == hevc.NALU_SEI_SUFFIX) {
			seiNALUs = append(seiNALUs, nalu)
		}
	}
	fmt.Fprintf(w, "Sample %d, pts=%d (%dB):%s\n", nr, pts, totLen, msg)
	printSEINALus(w, seiNALUs, "hevc", seiLevel, nil)
	if parameterSets {
		for _, nalu := range nalus {
			naluType := hevc.GetNaluType(nalu[0])
			switch naluType {
			case hevc.NALU_VPS:
				fmt.Fprintf(w, "  VPS: %s\n", hex.EncodeToString(nalu))
			case hevc.NALU_SPS:
				fmt.Fprintf(w, "  SPS: %s\n", hex.EncodeToString(nalu))
			case hevc.NALU_PPS:
				fmt.Fprintf(w, "  PPS: %s\n", hex.EncodeToString(nalu))
			}
		}
	}
	return nil
}

// printSEINALus - print interpreted information if seiLevel is >= 1. Add hex dump if seiLevel >= 2
func printSEINALus(w io.Writer, seiNALUs [][]byte, codec string, seiLevel int, avcSPS *avc.SPS) {
	if seiLevel < 1 {
		return
	}
	var hdrLen int
	var seiCodec sei.Codec
	switch codec {
	case "avc":
		seiCodec = sei.AVC
		hdrLen = 1
	case "hevc":
		seiCodec = sei.HEVC
		hdrLen = 2
	}
	if len(seiNALUs) > 0 {
		for _, seiNALU := range seiNALUs {
			if seiLevel >= 2 {
				fmt.Fprintf(w, "  SEI raw: %s\n", hex.EncodeToString(seiNALU))
			}
			seiBytes := seiNALU[hdrLen:]
			buf := bytes.NewReader(seiBytes)
			seiDatas, err := sei.ExtractSEIData(buf)
			if err != nil {
				fmt.Fprintf(w, "  SEI: Got error %q\n", err)
				if err != sei.ErrRbspTrailingBitsMissing {
					continue
				}
			}
			var seiMsg sei.SEIMessage
			for _, seiData := range seiDatas {
				switch {
				case codec == "avc" && seiData.Type() == sei.SEIPicTimingType && avcSPS != nil && avcSPS.VUI != nil:
					var cbpDbpDelay *sei.CbpDbpDelay
					var timeOffsetLen byte = 0
					hrdParams := avcSPS.VUI.VclHrdParameters
					if hrdParams == nil {
						hrdParams = avcSPS.VUI.NalHrdParameters
					}
					if hrdParams != nil {
						cbpDbpDelay = &sei.CbpDbpDelay{
							CpbRemovalDelayLengthMinus1: byte(hrdParams.CpbRemovalDelayLengthMinus1),
							DpbOutputDelayLengthMinus1:  byte(hrdParams.DpbOutputDelayLengthMinus1),
						}
						timeOffsetLen = byte(hrdParams.TimeOffsetLength)
					}
					seiMsg, err = sei.DecodePicTimingAvcSEIHRD(&seiData, cbpDbpDelay, timeOffsetLen)
				default:
					seiMsg, err = sei.DecodeSEIMessage(&seiData, seiCodec)
				}

				if err != nil {
					fmt.Fprintf(w, "  SEI: Got error %q\n", err)
					continue
				}
				fmt.Fprintf(w, "  * %s\n", seiMsg.String())
			}
		}
	}
}

func bytesToStringN(data []byte, maxNrBytes int) string {
	if len(data) > maxNrBytes {
		return hex.EncodeToString(data[:maxNrBytes]) + "..."
	}
	return hex.EncodeToString(data)
}

func findAnnexBFrames(nalus [][]byte, codec string) ([][][]byte, error) {
	var isAUD func([]byte) bool
	switch codec {
	case "avc":
		isAUD = isAvcAudNalu
	case "hevc":
		isAUD = isHEVCAudNalu
	default:
		return nil, fmt.Errorf("unknown codec: %s", codec)
	}
	var frames [][][]byte
	frameStart := 0
	for i, nalu := range nalus {
		if isAUD(nalu) {
			if i > frameStart {
				frames = append(frames, nalus[frameStart:i])
				frameStart = i
			}
		}
	}
	if frameStart < len(nalus) {
		frames = append(frames, nalus[frameStart:])
	}
	return frames, nil
}

func isAvcAudNalu(nalu []byte) bool {
	return avc.GetNaluType(nalu[0]) == avc.NALU_AUD
}

func isHEVCAudNalu(nalu []byte) bool {
	return hevc.GetNaluType(nalu[0]) == hevc.NALU_AUD
}
