package mp4_test

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestGenericContainer(t *testing.T) {
	// Just check that it doesn't crash
	c := mp4.NewGenericContainerBox("test")
	c.AddChild(&mp4.VsidBox{SourceID: 42})
	w := bytes.Buffer{}
	err := c.Encode(&w)
	if err != nil {
		t.Error(err)
	}
	err = c.Info(&w, "", "", "  ")
	if err != nil {
		t.Error(err)
	}
}
