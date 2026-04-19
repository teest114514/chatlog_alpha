package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	appName = "resegmenter"
)

var usg = `%s is an example on how to resegment a fragmented file to a new target segment duration.
The duration is given in ticks (in the track timescale).

If no init segment in the input, the trex defaults will not be known which may cause an issue.
The  input must be a fragmented file.

Usage of %s:
`

type options struct {
	chunkDur uint64
	verbose  bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] infile outfile\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.Uint64Var(&opts.chunkDur, "d", 0, "Required: chunk duration (ticks)")
	fs.BoolVar(&opts.verbose, "v", false, "Verbose output")

	err := fs.Parse(args[1:])
	return &opts, err
}

func main() {
	if err := run(os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, w io.Writer) error {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	o, err := parseOptions(fs, args)

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if o.chunkDur == 0 {
		fs.Usage()
		return fmt.Errorf("chunk duration must be set (and positive)")
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
	parsedMp4, err := mp4.DecodeFile(ifd)
	if err != nil {
		return fmt.Errorf("error decoding file: %w", err)
	}
	newMp4, err := Resegment(w, parsedMp4, o.chunkDur, o.verbose)
	if err != nil {
		return fmt.Errorf("error resegmenting: %w", err)
	}
	ofd, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer ofd.Close()
	return newMp4.Encode(ofd)
}
