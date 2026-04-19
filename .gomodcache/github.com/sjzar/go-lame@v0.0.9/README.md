# Go-LAME Wrapper
====


This project integrates the libmp3lame source code directly into Go, providing a set of Go-native interfaces for MP3 encoding. By embedding the LAME library, the project eliminates the need for external dynamic library dependencies, offering a seamless, standalone solution for developers working with MP3 encoding in Go.

Key Features:

- Direct integration of libmp3lame with Go.
- No external dependencies or dynamic libraries required.
- Simple and efficient Go-native interfaces for MP3 encoding tasks.
- Perfect for applications where portability and simplicity are critical.

Example:

```Go
package main

import (
	"bufio"
	"os"

	"github.com/git-jiadong/go-lame"
)

func main() {

	//input.raw: 44100 rate 2 channel 16bits pcm
	//output.mp3: 16000 rate 2 channel 16bits mp3
	f, err := os.Open("input.raw")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)

	of, err := os.Create("output.mp3")
	if err != nil {
		panic(err)
	}
	defer of.Close()

	wr := lame.NewWriter(of)
	wr.Encoder.SetInSamplerate(44100)
	wr.Encoder.SetOutSamplerate(16000)
	wr.Encoder.SetNumChannels(2)
	wr.Encoder.SetQuality(5)
	// IMPORTANT!
	wr.Encoder.InitParams()
	reader.WriteTo(wr)
	wr.Close()
}
```
