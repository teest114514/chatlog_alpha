//go:build go1.18
// +build go1.18

package mp4_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

func monitorMemory(ctx context.Context, t *testing.T, memoryLimit int) {
	go func() {
		timer := time.NewTicker(500 * time.Millisecond)
		defer timer.Stop()
		var m runtime.MemStats

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				runtime.ReadMemStats(&m)
				if m.Alloc > uint64(memoryLimit) {
					t.Logf("memory limit exceeded: %d > %d", m.Alloc, memoryLimit)
					t.Fail()
					return
				}
			}
		}
	}()
}

func FuzzDecodeBox(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatal(err)
	}

	validExts := map[string]bool{
		".mp4":  true,
		".m4s":  true,
		".cmfv": true,
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if validExts[filepath.Ext(entry.Name())] {
			testData, err := os.ReadFile("testdata/" + entry.Name())
			if err != nil {
				f.Fatal(err)
			}
			f.Add(testData)
		}
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		monitorMemory(ctx, t, 500*1024*1024) // 500MB

		r := bytes.NewReader(b)
		var pos uint64 = 0
		for {
			box, err := mp4.DecodeBox(pos, r)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				}
			}
			if box == nil {
				break
			}
			pos += box.Size()
		}

		pos = 0
		sr := bits.NewFixedSliceReader(b)
		for {
			box, err := mp4.DecodeBoxSR(pos, sr)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				}
			}
			if box == nil {
				break
			}
			pos += box.Size()
		}
	})
}
