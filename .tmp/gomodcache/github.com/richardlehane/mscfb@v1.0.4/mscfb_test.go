package mscfb

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

var (
	novPapPlan  = "test/novpapplan.doc"
	testDoc     = "test/test.doc"
	testXls     = "test/test.xls"
	testPpt     = "test/test.ppt"
	testMsg     = "test/test.msg"
	testEntries = []*File{
		&File{Name: "Root Node",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: 1},
		},
		&File{Name: "Alpha",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: 2, childID: noStream},
		},
		&File{Name: "Bravo",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: 3, childID: 5},
		},
		&File{Name: "Charlie",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: 7},
		},
		&File{Name: "Delta",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: noStream},
		},
		&File{Name: "Echo",
			directoryEntryFields: &directoryEntryFields{leftSibID: 4, rightSibID: 6, childID: 9},
		},
		&File{Name: "Foxtrot",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: noStream},
		},
		&File{Name: "Golf",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: 10},
		},
		&File{Name: "Hotel",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: noStream},
		},
		&File{Name: "Indigo",
			directoryEntryFields: &directoryEntryFields{leftSibID: 8, rightSibID: noStream, childID: 11},
		},
		&File{Name: "Jello",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: noStream},
		},
		&File{Name: "Kilo",
			directoryEntryFields: &directoryEntryFields{leftSibID: noStream, rightSibID: noStream, childID: noStream},
		},
	}
)

func equals(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func empty(sl []byte) bool {
	for _, v := range sl {
		if v != 0 {
			return false
		}
	}
	return true
}

func testFile(t *testing.T, path string) {
	file, _ := os.Open(path)
	defer file.Close()
	doc, err := New(file)
	if err != nil {
		t.Fatalf("Error opening file; Returns error: %v", err)
	}
	if len(doc.File) < 3 {
		t.Fatalf("Expecting several directory entries, only got %d", len(doc.File))
	}
	buf := make([]byte, 512)
	for entry, _ := doc.Next(); entry != nil; entry, _ = doc.Next() {
		_, err := doc.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("Error reading entry name, %v", entry.Name)
		}
		if len(entry.Name) < 1 {
			t.Errorf("Error reading entry name")
		}
	}
}

func TestTraverse(t *testing.T) {
	r := new(Reader)
	r.direntries = testEntries
	if r.traverse() != nil {
		t.Error("Error traversing")
	}
	expect := []int{0, 1, 2, 4, 5, 8, 9, 11, 6, 3, 7, 10}
	if len(r.File) != len(expect) {
		t.Fatalf("Error traversing: expecting %d entries, got %d", len(expect), len(r.File))
	}
	for i, v := range r.File {
		if v != testEntries[expect[i]] {
			t.Errorf("Error traversing: expecting %d at index %d; got %v", expect[i], i, v)
		}
	}
	if len(r.File[len(r.File)-1].Path) != 2 {
		t.Fatalf("Error traversing: expecting a path length of %d, got %d", 2, len(r.File[len(r.File)-1].Path))
	}
	if r.File[len(r.File)-1].Path[0] != "Charlie" {
		t.Errorf("Error traversing: expecting Charlie got %s", r.File[expect[10]].Path[0])
	}
	if r.File[len(r.File)-1].Path[1] != "Golf" {
		t.Errorf("Error traversing: expecting Golf got %s", r.File[expect[10]].Path[1])
	}
}

func TestNovPapPlan(t *testing.T) {
	testFile(t, novPapPlan)
}

func TestWord(t *testing.T) {
	testFile(t, testDoc)
}

func TestMsg(t *testing.T) {
	testFile(t, testMsg)
}

func TestPpt(t *testing.T) {
	testFile(t, testPpt)
}

func TestXls(t *testing.T) {
	testFile(t, testXls)
}

func TestSeek(t *testing.T) {
	file, _ := os.Open(testXls)
	defer file.Close()
	doc, _ := New(file)
	// the third entry in the XLS file is 2719 bytes
	f := doc.File[3]
	if f.Size != 2719 {
		t.Fatalf("Expecting the third entry of the XLS file to be 2719 bytes long; it is %d", f.Size)
	}
	buf := make([]byte, 2719)
	i, err := f.Read(buf)
	if i != 2719 || err != nil {
		t.Fatalf("Expecting 2719 length and no error; got %d and %v", i, err)
	}
	s, err := f.Seek(50, 1)
	if s != 2719 || err == nil {
		t.Fatalf("%v, %d", err, s)
	}
	s, err = f.Seek(1500, 0)
	if s != 1500 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	nbuf := make([]byte, 475)
	i, err = f.Read(nbuf)
	if i != 475 || err != nil {
		t.Fatalf("Expecting 475 length and no error; got %d and %v", i, err)
	}
	if !bytes.Equal(buf[1500:1975], nbuf) {
		t.Fatalf("Slices not equal: %s, %s", string(buf[1500:1975]), string(nbuf))
	}
	s, err = f.Seek(5, 1)
	if s != 1980 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	i, err = f.Read(nbuf[:5])
	if i != 5 || err != nil {
		t.Fatalf("Expecting 5 length, and no error; got %d and %v", i, err)
	}
	if !bytes.Equal(buf[1980:1985], nbuf[:5]) {
		t.Fatalf("Slices not equal: %s, %s", string(buf[1980:1985]), string(nbuf[:5]))
	}
	s, err = f.Seek(30, 2)
	if s != 2689 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	i, err = f.Read(nbuf[:30])
	if i != 30 || err != nil {
		t.Fatalf("Expecting 30 length, and no error; got %d and %v", i, err)
	}
	if !bytes.Equal(buf[2689:], nbuf[:30]) {
		t.Fatalf("Slices not equal: %d, %s, %s", len(buf[2688:]), string(buf[2688:]), string(nbuf[:30]))
	}
}

func TestWrite(t *testing.T) {
	file, err := os.OpenFile(testXls, os.O_RDWR, 0666)
	if err != nil {
		t.Fatalf("error opening file for read/write %v", err)
	}
	defer file.Close()
	doc, err := New(file)
	if err != nil {
		t.Fatalf("Error opening file; Returns error: %v", err)
	}
	// the third entry in the XLS file is 2719 bytes
	f := doc.File[3]
	s, err := f.Seek(30, 0)
	if s != 30 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	orig := make([]byte, 4)
	i, err := f.Read(orig)
	if i != 4 || err != nil {
		t.Fatalf("Expecting read length 4, and no error, got %d %v", i, err)
	}
	s, err = f.Seek(30, 0)
	if s != 30 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	i, err = f.Write([]byte("test"))
	if i != 4 || err != nil {
		t.Errorf("error writing, got %d %v", i, err)
	}
	s, err = f.Seek(30, 0)
	if s != 30 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	res := make([]byte, 4)
	i, err = f.Read(res)
	if i != 4 || err != nil {
		t.Errorf("error reading, got %d %v", i, err)
	}
	if string(res) != "test" {
		t.Errorf("expecting test, got %s", string(res))
	}
	s, err = f.Seek(30, 0)
	if s != 30 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	i, err = f.Write(orig)
	if i != 4 || err != nil {
		t.Errorf("error writing, got %d %v", i, err)
	}
	s, err = f.Seek(30, 0)
	if s != 30 || err != nil {
		t.Fatalf("Seek error: %v, %d", err, s)
	}
	i, err = f.Read(res)
	if i != 4 || err != nil {
		t.Errorf("error reading, got %d %v", i, err)
	}
	if string(res) != string(orig) {
		t.Errorf("bad result, expected %s, got %s", string(orig), string(res))
	}
	i, err = f.WriteAt([]byte("test"), 30)
	if i != 4 || err != nil {
		t.Errorf("error writing, got %d %v", i, err)
	}
	i, err = f.ReadAt(res, 30)
	if i != 4 || err != nil {
		t.Errorf("error reading, got %d %v", i, err)
	}
	if string(res) != "test" {
		t.Errorf("expecting test, got %s", string(res))
	}
	i, err = f.WriteAt(orig, 30)
	if i != 4 || err != nil {
		t.Errorf("error writing, got %d %v", i, err)
	}
	i, err = f.ReadAt(res, 30)
	if i != 4 || err != nil {
		t.Errorf("error reading, got %d %v", i, err)
	}
	if string(res) != string(orig) {
		t.Errorf("bad result, expected %s, got %s", string(orig), string(res))
	}
}

func benchFile(b *testing.B, path string) {
	b.StopTimer()
	buf, _ := ioutil.ReadFile(path)
	entrybuf := make([]byte, 32000)
	b.StartTimer()
	rdr := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		doc, _ := New(rdr)
		for entry, _ := doc.Next(); entry != nil; entry, _ = doc.Next() {
			doc.Read(entrybuf)
		}
	}
}

func BenchmarkNovPapPlan(b *testing.B) {
	benchFile(b, novPapPlan)
}

func BenchmarkWord(b *testing.B) {
	benchFile(b, testDoc)
}

func BenchmarkMsg(b *testing.B) {
	benchFile(b, testMsg)
}

func BenchmarkPpt(b *testing.B) {
	benchFile(b, testPpt)
}

func BenchmarkXls(b *testing.B) {
	benchFile(b, testXls)
}

/*
22/12
	BenchmarkNovPapPlan	   50000	     31676 ns/op
	BenchmarkWord	   20000	     65693 ns/op
	BenchmarkMsg	   10000	    198380 ns/op
	BenchmarkPpt	   50000	     30156 ns/op
	BenchmarkXls	  100000	     20327 ns/op
*/
