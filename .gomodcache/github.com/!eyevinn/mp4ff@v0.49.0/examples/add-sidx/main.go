package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Eyevinn/mp4ff/internal"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	appName = "add-sidx"
)

var usg = `%s shows how to add a top-level sidx box to a fragmented file provided it does not exist.
Segments are identified by styp boxes if they exist, otherwise by
the start of moof or emsg boxes. It is possible to interpret
every moof box as the start of a new segment, by specifying the "-startSegOnMoof" option.
One can further remove unused encryption boxes with the "-removeEnc" option.

Usage of %s:
`

type options struct {
	removeEncBoxes bool
	nonZeroEPT     bool
	segOnMoof      bool
	version        bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] infile outfile\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.BoolVar(&opts.removeEncBoxes, "removeEnc", false, "Remove unused encryption boxes")
	fs.BoolVar(&opts.nonZeroEPT, "nzEPT", false, "Use non-zero earliestPresentationTime")
	fs.BoolVar(&opts.segOnMoof, "startSegOnMoof", false, "Start a new segment on every moof")
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

	if len(fs.Args()) != 2 {
		fs.Usage()
		return fmt.Errorf("missing input or output file")
	}

	inFilePath := fs.Arg(0)
	outFilePath := fs.Arg(1)

	ifd, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer ifd.Close()
	ofd, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer ofd.Close()

	var flags mp4.DecFileFlags
	if o.segOnMoof {
		flags |= mp4.DecStartOnMoof
	}
	mp4Root, err := mp4.DecodeFile(ifd, mp4.WithDecodeFlags(flags))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "creating sidx with %d segment(s)\n", len(mp4Root.Segments))

	if o.removeEncBoxes {
		removeEncryptionBoxes(mp4Root)
	}

	addIfNotExists := true
	err = mp4Root.UpdateSidx(addIfNotExists, o.nonZeroEPT)
	if err != nil {
		return fmt.Errorf("addSidx failed: %w", err)
	}

	return mp4Root.Encode(ofd)
}

func removeEncryptionBoxes(inFile *mp4.File) {
	for _, seg := range inFile.Segments {
		for _, frag := range seg.Fragments {
			bytesRemoved := uint64(0)
			for _, traf := range frag.Moof.Trafs {
				bytesRemoved += traf.RemoveEncryptionBoxes()
			}
			for _, traf := range frag.Moof.Trafs {
				for _, trun := range traf.Truns {
					trun.DataOffset -= int32(bytesRemoved)
				}
			}
		}
	}
}
