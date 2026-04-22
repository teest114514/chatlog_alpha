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
	appName = "mp4ff-info"
)

var usg = `%s prints the box tree of input mp4 (ISOBMFF) file.

Usage of %s:
`

type options struct {
	levels  string
	version bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] infile\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.StringVar(&opts.levels, "l", "", "level of details, e.g. all:1 or trun:1,subs:1")
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

func run(args []string, w io.Writer) error {
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

	if len(fs.Args()) != 1 {
		fs.Usage()
		return fmt.Errorf("need input file")
	}
	inFilePath := fs.Arg(0)

	ifd, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("could not open input file: %w", err)
	}
	defer ifd.Close()
	parsedMp4, parseErr := mp4.DecodeFile(ifd, mp4.WithDecodeMode(mp4.DecModeLazyMdat))
	if parseErr != nil {
		if parsedMp4 == nil {
			return fmt.Errorf("could not parse input file: %w", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Warning: could not parse input file completely: %v\n", parseErr)
	}
	err = parsedMp4.Info(w, opts.levels, "", "  ")
	if err != nil {
		return fmt.Errorf("could not print info: %w", err)
	}
	return parseErr
}
