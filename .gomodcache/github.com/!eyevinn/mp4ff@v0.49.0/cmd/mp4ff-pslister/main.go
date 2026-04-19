package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Eyevinn/mp4ff/avc"
	"github.com/Eyevinn/mp4ff/hevc"
	"github.com/Eyevinn/mp4ff/internal"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	appName = "mp4ff-pslister"
)

var usg = `%s lists parameter sets for AVC/H.264 or HEVC/H.265 from mp4 sample description, bytestream, or hex input.

It prints them as hex and in verbose mode it also prints details in JSON format.
Usage of %s:
`

type options struct {
	inFile  string
	vpsHex  string
	spsHex  string
	ppsHex  string
	codec   string
	verbose bool
	version bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options]\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.StringVar(&opts.inFile, "i", "", "Input file (mp4 or byte stream) (alternative to sps and pps in hex format)")
	fs.StringVar(&opts.codec, "c", "avc", "Codec to parse (avc or hevc)")
	fs.StringVar(&opts.vpsHex, "vps", "", "VPS in hex format (HEVC only)")
	fs.StringVar(&opts.spsHex, "sps", "", "SPS in hex format, alternative to infile")
	fs.StringVar(&opts.ppsHex, "pps", "", "PPS in hex format")
	fs.BoolVar(&opts.verbose, "v", false, "Verbose output -> details. On for hex input")
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

	if o.inFile == "" && o.spsHex == "" {
		fs.Usage()
		return fmt.Errorf("must specify infile or sps in hex format")
	}

	if o.vpsHex != "" {
		o.codec = "hevc"
	}

	if o.spsHex != "" {
		// Don't just print hex again
		o.verbose = true
	}

	var vpsNalus [][]byte
	var spsNalus [][]byte
	var ppsNalus [][]byte

	if o.inFile != "" {
		ifd, err := os.Open(o.inFile)
		if err != nil {
			return fmt.Errorf("could not open file %s: %w", o.inFile, err)
		}
		defer ifd.Close()
		mp4Extensions := []string{".mp4", ".m4v", ".cmfv", ".m4s"}
		for _, ext := range mp4Extensions {
			if strings.HasSuffix(o.inFile, ext) {
				return parseMp4File(stdout, ifd, o.codec, o.verbose)
			}
		}
		// Assume bytestream,AnnexB
		nalus, err := getNalusFromBytestream(ifd)
		if err != nil {
			return err
		}
		if o.codec == "avc" {
			for _, nalu := range nalus {
				switch avc.GetNaluType(nalu[0]) {
				case avc.NALU_SPS:
					if len(ppsNalus) > 0 {
						break // SPS coming back again
					}
					spsNalus = append(spsNalus, nalu)
				case avc.NALU_PPS:
					ppsNalus = append(ppsNalus, nalu)
				}
			}
			return printAvcPS(stdout, spsNalus, ppsNalus, o.verbose)
		}

		// hevc
		for _, nalu := range nalus {
			switch naluType := hevc.GetNaluType(nalu[0]); naluType {
			case hevc.NALU_VPS:
				if len(spsNalus) > 0 {
					break // VPS coming back again
				}
				vpsNalus = append(vpsNalus, nalu)
			case hevc.NALU_SPS:
				spsNalus = append(spsNalus, nalu)
			case hevc.NALU_PPS:
				ppsNalus = append(ppsNalus, nalu)
			default:
				// Ignore other NALUs
			}
		}
		return printHevcPS(stdout, vpsNalus, spsNalus, ppsNalus, o.verbose)
	}
	// Now we have hex case left
	switch o.codec {
	case "avc":
		spsNalu, err := hex.DecodeString(o.spsHex)
		if err != nil {
			return err
		}
		spsNalus = append(spsNalus, spsNalu)
		if o.ppsHex != "" {
			ppsNalu, err := hex.DecodeString(o.ppsHex)
			if err != nil {
				return err
			}
			ppsNalus = append(ppsNalus, ppsNalu)
		}
		return printAvcPS(stdout, spsNalus, ppsNalus, o.verbose)
	case "hevc":
		vpsNalu, err := hex.DecodeString(o.vpsHex)
		if err != nil {
			return err
		}
		vpsNalus = append(vpsNalus, vpsNalu)
		spsNalu, err := hex.DecodeString(o.spsHex)
		if err != nil {
			return err
		}
		if len(spsNalu) > 0 {
			spsNalus = append(spsNalus, spsNalu)
		}
		ppsNalu, err := hex.DecodeString(o.ppsHex)
		if err != nil {
			return err
		}
		if len(ppsNalu) > 0 {
			ppsNalus = append(ppsNalus, ppsNalu)
		}
		return printHevcPS(stdout, vpsNalus, spsNalus, ppsNalus, o.verbose)
	default:
		return fmt.Errorf("unknown codec %s", o.codec)
	}
}

func getNalusFromBytestream(f io.Reader) ([][]byte, error) {
	fullRaw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	nalus := avc.ExtractNalusFromByteStream(fullRaw)
	return nalus, nil
}

func parseMp4File(w io.Writer, r io.Reader, codec string, verbose bool) error {
	parsedMp4, err := mp4.DecodeFile(r)
	if err != nil {
		return fmt.Errorf("DecodeFile: %w", err)
	}

	var trackID uint32
	if parsedMp4.Moov != nil {
		foundPS := false
		foundCodec := ""
		trackID, foundCodec, foundPS, err = parseMp4Init(w, parsedMp4, verbose)
		if err != nil {
			return fmt.Errorf("parseMp4Init: %w", err)
		}
		codec = foundCodec
		if foundPS {
			return nil
		}
	}
	if parsedMp4.IsFragmented() {
		err = parseMp4Fragment(w, parsedMp4, trackID, codec, verbose)
		if err != nil {
			return fmt.Errorf("parseMp4Fragment: %w", err)
		}
		return nil
	}
	// Non-fragmented mp4 file with PS in samples
	for _, trak := range parsedMp4.Moov.Traks {
		if trak.Tkhd.TrackID == trackID {
			stbl := trak.Mdia.Minf.Stbl
			var offset int64
			if stbl.Stco != nil {
				offset = int64(stbl.Stco.ChunkOffset[0])
			} else if stbl.Co64 != nil {
				offset = int64(stbl.Co64.ChunkOffset[0])
			}
			size := stbl.Stsz.GetSampleSize(1)
			// Next find bytes as slice in mdat
			mdat := parsedMp4.Mdat
			mdatPayloadStart := mdat.PayloadAbsoluteOffset()
			offsetInMdatData := uint64(offset) - mdatPayloadStart
			sampleData := mdat.Data[offsetInMdatData : offsetInMdatData+uint64(size)]
			switch codec {
			case "avc":
				spsNalus, ppsNalus := avc.GetParameterSets(sampleData)
				if len(spsNalus) == 0 {
					return fmt.Errorf("no AVC SPS found")
				}
				return printAvcPS(w, spsNalus, ppsNalus, verbose)
			case "hevc":
				vpsNalus, spsNalus, ppsNalus := hevc.GetParameterSets(sampleData)
				if len(spsNalus) == 0 {
					return fmt.Errorf("no HEVC SPS found")
				}
				return printHevcPS(w, vpsNalus, spsNalus, ppsNalus, verbose)
			default:
				return fmt.Errorf("unknown codec: %s", codec)
			}
		}
	}
	return nil
}

func parseMp4Init(w io.Writer, parsedMp4 *mp4.File, verbose bool) (trackID uint32, codec string, foundPS bool, err error) {
	for _, trak := range parsedMp4.Moov.Traks {
		if trak.Mdia.Hdlr.HandlerType == "vide" {
			stsd := trak.Mdia.Minf.Stbl.Stsd
			if stsd.AvcX != nil {
				codec = "avc"
			} else if stsd.HvcX != nil {
				codec = "hevc"
			} else {
				continue
			}
			trackID = trak.Tkhd.TrackID
			if verbose {
				fmt.Fprintf(w, "Video %s track ID=%d\n", codec, trackID)
			}
			switch codec {
			case "avc":
				spsNalus := stsd.AvcX.AvcC.SPSnalus
				ppsNalus := stsd.AvcX.AvcC.PPSnalus
				if len(spsNalus) == 0 {
					return trackID, codec, false, nil
				}
				err := printAvcPS(w, spsNalus, ppsNalus, verbose)
				return trackID, codec, true, err
			case "hevc":
				vpsNalus := stsd.HvcX.HvcC.GetNalusForType(hevc.NALU_VPS)
				spsNalus := stsd.HvcX.HvcC.GetNalusForType(hevc.NALU_SPS)
				ppsNalus := stsd.HvcX.HvcC.GetNalusForType(hevc.NALU_PPS)
				if len(vpsNalus) == 0 {
					return trackID, codec, false, nil
				}
				if stsd.HvcX.Type() == "hev1" {
					fmt.Fprintf(w, "Warning: found parameter set nalus although there none in sample descriptor hev1\n")
				}
				err := printHevcPS(w, vpsNalus, spsNalus, ppsNalus, verbose)
				return trackID, codec, true, err
			}
		}
	}
	return 0, codec, false, fmt.Errorf("no parsable video track found")
}

func parseMp4Fragment(w io.Writer, parsedMp4 *mp4.File, trackID uint32, codec string, verbose bool) error {
	if len(parsedMp4.Segments) == 0 || len(parsedMp4.Segments[0].Fragments) == 0 {
		return fmt.Errorf("no moov or fragment found in mp4 file")
	}
	frag := parsedMp4.Segments[0].Fragments[0]
	trex := mp4.TrexBox{
		TrackID: trackID,
	}
	samples, err := frag.GetFullSamples(&trex)
	if err != nil {
		return fmt.Errorf("GetFullSamples: %w", err)
	}
	if len(samples) == 0 {
		return fmt.Errorf("no samples in fragment")
	}
	fs := samples[0]
	switch codec {
	case "avc":
		spsNalus, ppsNalus := avc.GetParameterSets(fs.Data)
		return printAvcPS(w, spsNalus, ppsNalus, verbose)
	case "hevc":
		vpsNalus, spsNalus, ppsNalus := hevc.GetParameterSets(fs.Data)
		return printHevcPS(w, vpsNalus, spsNalus, ppsNalus, verbose)
	default:
		return fmt.Errorf("unknown codec: %s", codec)
	}
}

func printAvcPS(w io.Writer, spsNalus, ppsNalus [][]byte, verbose bool) error {
	if len(spsNalus) == 0 {
		return fmt.Errorf("no AVC SPS found")
	}
	spsMap := make(map[uint32]*avc.SPS)
	for i, spsNalu := range spsNalus {
		sps, err := avc.ParseSPSNALUnit(spsNalu, true /*fullVui*/)
		if err != nil {
			return fmt.Errorf("ParseSPSNALUnit: %w", err)
		}
		printPS(w, "SPS", i+1, spsNalu, sps, verbose)
		spsMap[sps.ParameterID] = sps
	}
	for i, ppsNalu := range ppsNalus {
		ppsInfo, err := avc.ParsePPSNALUnit(ppsNalu, spsMap)
		if err != nil {
			return fmt.Errorf("ParsePPSNALUnit: %w", err)
		}
		printPS(w, "PPS", i+1, ppsNalu, ppsInfo, verbose)
	}
	sps, _ := avc.ParseSPSNALUnit(spsNalus[0], true /*fullVui*/)
	fmt.Fprintf(w, "Codecs parameter (assuming avc1) from SPS id %d: %s\n", sps.ParameterID, avc.CodecString("avc1", sps))
	return nil
}

func printHevcPS(w io.Writer, vpsNalus, spsNalus, ppsNalus [][]byte, verbose bool) error {
	for i, vps := range vpsNalus {
		printPS(w, "VPS", i+1, vps, nil, false)
	}
	spsMap := make(map[uint32]*hevc.SPS)
	for i, sps := range spsNalus {
		spsInfo, err := hevc.ParseSPSNALUnit(sps)
		if err != nil {
			return fmt.Errorf("ParseSPSNALUnit: %w", err)
		}
		printPS(w, "SPS", i+1, sps, spsInfo, verbose)
		spsMap[uint32(spsInfo.SpsID)] = spsInfo
	}
	for i, pps := range ppsNalus {
		ppsInfo, err := hevc.ParsePPSNALUnit(pps, spsMap)
		if err != nil {
			return fmt.Errorf("ParsePPSNALUnit: %w", err)
		}
		printPS(w, "PPS", i+1, pps, ppsInfo, verbose)
	}

	if len(spsNalus) > 0 {
		sps, _ := hevc.ParseSPSNALUnit(spsNalus[0])
		fmt.Fprintf(w, "Codecs parameter (assuming hvc1) from SPS id %d: %s\n", sps.SpsID, hevc.CodecString("hvc1", sps))
	}
	return nil
}

func printPS(w io.Writer, name string, nr int, ps []byte, psInfo interface{}, verbose bool) {
	hexStr := hex.EncodeToString(ps)
	length := len(hexStr) / 2
	fmt.Fprintf(w, "%s %d len %dB: %+v\n", name, nr, length, hexStr)
	if verbose && psInfo != nil {
		jsonPS, _ := json.MarshalIndent(psInfo, "", "  ")
		fmt.Fprintf(w, "%s\n", string(jsonPS))
	}
}
