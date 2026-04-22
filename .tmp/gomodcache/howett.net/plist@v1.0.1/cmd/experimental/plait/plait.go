package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"syscall/js"

	"howett.net/plist"
)

const JSONFormat int = 100

var nameFormatMap = map[string]int{
	"xml":      plist.XMLFormat,
	"binary":   plist.BinaryFormat,
	"openstep": plist.OpenStepFormat,
	"gnustep":  plist.GNUStepFormat,
	"json":     JSONFormat,
}

func main() {
	convert := os.Args[1]
	format, ok := nameFormatMap[convert]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown output format %s\n", convert)
		return
	}

	jsConverter := js.Global().Get("ply")
	jsDocumentLength := jsConverter.Call("readDocument").Int()
	document := make([]byte, jsDocumentLength)
	jsDocumentTemp := js.TypedArrayOf(document)
	jsConverter.Call("readDocument", jsDocumentTemp, jsDocumentLength)
	jsDocumentTemp.Release()

	file := bytes.NewReader(document)
	outfile := &bytes.Buffer{}

	var val interface{}
	dec := plist.NewDecoder(file)
	err := dec.Decode(&val)

	if err != nil {
		bail(err)
	}

	if format == JSONFormat {
		enc := json.NewEncoder(outfile)
		enc.SetIndent("", "\t")
		err = enc.Encode(val)
	} else {
		enc := plist.NewEncoderForFormat(outfile, format)
		enc.Indent("\t")
		err = enc.Encode(val)
	}

	if err != nil {
		bail(err)
	}

	a := js.TypedArrayOf(outfile.Bytes())
	jsConverter.Call("writeDocument", a)
	a.Release()
}

func bail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
