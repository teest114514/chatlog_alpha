package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Eyevinn/mp4ff/internal"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	appName = "mp4ff-encrypt"
)

var usg = `%s encrypts a fragmented mp4 file using Common Encryption with cenc or cbcs scheme.
A combined fragmented file with init segment and media segment(s) will be encrypted.
For a pure media segment, an init segment with encryption information is needed.
For video, only AVC with avc1 and HEVC with hvc1 sample entries are currently supported.
For audio, all supported audio codecs should work.

Usage of %s:
`

type options struct {
	initFile string
	kidStr   string
	keyStr   string
	ivHex    string
	scheme   string
	psshFile string
	version  bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] infile outfile\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.StringVar(&opts.initFile, "init", "", "Path to init file with encryption info (scheme, kid, pssh)")
	fs.StringVar(&opts.kidStr, "kid", "", "key id (32 hex or 24 base64 chars). Required if initFilePath empty")
	fs.StringVar(&opts.keyStr, "key", "", "Required: key (32 hex or 24 base64 chars)")
	fs.StringVar(&opts.ivHex, "iv", "", "Required: iv (16 or 32 hex chars)")
	fs.StringVar(&opts.scheme, "scheme", "cenc", "cenc or cbcs. Required if initFilePath empty")
	fs.StringVar(&opts.psshFile, "pssh", "", "file with one or more pssh box(es) in binary format. Will be added at end of moov box")
	fs.BoolVar(&opts.version, "version", false, "Get mp4ff version")

	err := fs.Parse(args[1:])
	return &opts, err
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	opts, err := parseOptions(fs, args)

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if opts.version {
		fmt.Printf("%s %s\n", appName, internal.GetVersion())
		return nil
	}

	if len(fs.Args()) != 2 {
		fs.Usage()
		return fmt.Errorf("need input and output file")
	}

	var inFilePath = fs.Arg(0)
	var outFilePath = fs.Arg(1)

	if opts.keyStr == "" || opts.ivHex == "" {
		fs.Usage()
		return fmt.Errorf("need both key and iv")
	}

	ifh, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("could not open input file: %w", err)
	}
	defer ifh.Close()

	ofh, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("could not create output file: %w", err)
	}
	defer ofh.Close()

	var initSeg *mp4.InitSegment
	if opts.initFile != "" {
		inith, err := os.Open(opts.initFile)
		if err != nil {
			return fmt.Errorf("could not open init file: %w", err)
		}
		defer inith.Close()
		insegFile, err := mp4.DecodeFile(inith)
		if err != nil {
			return fmt.Errorf("could not decode init file: %w", err)
		}
		initSeg = insegFile.Init
		if initSeg == nil {
			return fmt.Errorf("no init segment found in init file")
		}
	}

	var psshData []byte
	if opts.psshFile != "" {
		psshData, err = os.ReadFile(opts.psshFile)
		if err != nil {
			return fmt.Errorf("could not read pssh data from file: %w", err)
		}
	}

	err = encryptFile(ifh, ofh, initSeg, opts.scheme, opts.kidStr, opts.keyStr, opts.ivHex, psshData)
	if err != nil {
		return fmt.Errorf("encryptFile: %w", err)
	}
	return nil
}

func encryptFile(ifh io.Reader, ofh io.Writer, initSeg *mp4.InitSegment,
	scheme, kidStr, keyStr, ivHex string, psshData []byte) error {

	if len(ivHex) != 32 && len(ivHex) != 16 {
		return fmt.Errorf("hex iv must have length 16 or 32 chars; %d", len(ivHex))
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return fmt.Errorf("invalid iv %s", ivHex)
	}

	if len(keyStr) != 32 {
		return fmt.Errorf("hex key must have length 32 chars: %d", len(keyStr))
	}
	key, err := mp4.UnpackKey(keyStr)
	if err != nil {
		return fmt.Errorf("invalid key %s, %w", keyStr, err)
	}

	var kidUUID mp4.UUID
	if initSeg == nil {
		kid, err := mp4.UnpackKey(kidStr)
		if err != nil {
			return fmt.Errorf("invalid key ID %s: %w", kidStr, err)
		}
		kidHex := hex.EncodeToString(kid)
		kidUUID, _ = mp4.NewUUIDFromString(kidHex)
		if scheme != "cenc" && scheme != "cbcs" {
			return fmt.Errorf("scheme must be cenc or cbcs: %s", scheme)
		}
	}
	inFile, err := mp4.DecodeFile(ifh)
	if err != nil {
		return fmt.Errorf("decode file: %w", err)
	}

	var ipd *mp4.InitProtectData
	if inFile.Init != nil {
		psshBoxes, err := mp4.PsshBoxesFromBytes(psshData)
		if err != nil {
			return fmt.Errorf("pssh boxes from data: %w", err)
		}
		ipd, err = mp4.InitProtect(inFile.Init, key, iv, scheme, kidUUID, psshBoxes)
		if err != nil {
			return fmt.Errorf("init protect: %w", err)
		}
	}
	if ipd == nil && initSeg == nil {
		return fmt.Errorf("no init protect data available)")
	}
	if ipd == nil {
		ipd, err = mp4.ExtractInitProtectData(initSeg)
		if err != nil {
			return fmt.Errorf("extract init protect data: %w", err)
		}
	}

	for _, s := range inFile.Segments {
		for _, f := range s.Fragments {
			err = mp4.EncryptFragment(f, key, iv, ipd)
			if err != nil {
				return fmt.Errorf("encrypt fragment: %w", err)
			}
		}
	}
	return inFile.Encode(ofh)
}
