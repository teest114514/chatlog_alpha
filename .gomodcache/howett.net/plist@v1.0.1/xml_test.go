package plist

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func BenchmarkXMLGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		d := newXMLPlistGenerator(ioutil.Discard)
		d.generateDocument(plistValueTree)
	}
}

func BenchmarkXMLParse(b *testing.B) {
	buf := bytes.NewReader([]byte(plistValueTreeAsXML))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		d := newXMLPlistParser(buf)
		d.parseDocument()
		b.StopTimer()
		buf.Seek(0, 0)
	}
}

var InvalidXMLPlists = []string{
	`<plist version="1.0"><integer>0x</integer></plist>`,
	"<plist><doct><key>helo</key><string></string></doct></plist>",
	"<plist><dict><string>helo</string></dict></plist>",
	"<plist><dict><key>helo</key></dict></plist>",
	"<plist><integer>helo</integer></plist>",
	"<plist><integer></integer></plist>",
	"<plist><real>helo</real></plist>",
	"<plist><data>*@&amp;%#helo</data></plist>",
	"<plist><date>*@&amp;%#helo</date></plist>",
	"<plist><date>*@&amp;%#helo</date></plist>",
	"<plist><integer>10</plist>",
	"<plist><real>10</plist>",
	"<plist><string>10</plist>",
	"<plist><dict>10</plist>",
	"<plist><dict><key>10</plist>",
	"<plist>",
	"<plist><data>",
	"<plist><date>",
	"<plist><array>",
	"<plist/>",
	"<pl",
	"bplist00",
}

func TestVariousIllegalXMLPlists(t *testing.T) {
	for _, plist := range InvalidXMLPlists {
		buf := bytes.NewReader([]byte(plist))
		d := newXMLPlistParser(buf)
		obj, err := d.parseDocument()
		t.Logf("Error: %v", err)
		if obj != nil && err == nil {
			t.Error("Expected error, received nothing.")
		}
	}
}
