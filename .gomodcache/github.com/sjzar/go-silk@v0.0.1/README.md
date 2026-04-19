# go-silk

This project integrates the **SKP Silk** source code directly into Go, providing a Go-native solution for decoding Silk audio and WeChat voice messages. By embedding the Silk library, it removes the need for external dynamic library dependencies, offering a self-contained and portable implementation.

Key Features:

- Direct integration of SKP Silk with Go.
- No reliance on external dynamic libraries.
- Support for decoding Silk audio files.
- Built-in compatibility for decoding **WeChat voice messages**.
- Ideal for developers seeking a lightweight and efficient approach to handling Silk audio formats in Go applications.

Example:

```Go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/git-jiadong/go-lame"
	"github.com/git-jiadong/go-silk"
)

func main() {
	inputFile := "input.amr"
	f, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	amrReader := bufio.NewReader(f)

	pcmFile, err := os.Create(inputFile + ".pcm")
	if err != nil {
		panic(err)
	}
	defer pcmFile.Close()

	var pcmBuffer bytes.Buffer
	multiWrite := io.MultiWriter(&pcmBuffer, pcmFile)

	sr := silk.NewWriter(multiWrite)
	sr.Decoder.SetSampleRate(24000)
	amrReader.WriteTo(sr)
	sr.Close()

	if pcmBuffer.Len() == 0 {
		fmt.Println("silk decode failed")
		return
	}

	outputFile := inputFile + ".mp3"

	of, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}
	defer of.Close()
	wr := lame.NewWriter(of)
	wr.Encoder.SetInSamplerate(24000)
	wr.Encoder.SetOutSamplerate(24000)
	wr.Encoder.SetNumChannels(1)
	wr.Encoder.SetBitrate(16)
	// IMPORTANT!
	wr.Encoder.InitParams()

	pcmBuffer.WriteTo(wr)
	wr.Close()
}

```

## reference
[silk-v3-decoder](https://github.com/kn007/silk-v3-decoder)