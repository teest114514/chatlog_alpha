package msoleps

import (
	"os"
	"sync"
	"testing"
)

var (
	testDocSum = "test/DocumentSummaryInformation"
	testSum    = "test/SummaryInformation"
	testSum1   = "test/SummaryInformation1"
)

func testFile(t *testing.T, path string) *Reader {
	file, _ := os.Open(path)
	defer file.Close()
	doc, err := NewFrom(file)
	if err != nil {
		t.Errorf("Error opening file; Returns error: %v", err)
	}
	return doc
}

func TestReader_concurrency(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = testFile(t, testDocSum)
	}()
	go func() {
		defer wg.Done()
		_ = testFile(t, testDocSum)
	}()
	wg.Wait()
}

func TestDocSum(t *testing.T) {
	doc := testFile(t, testDocSum)
	if len(doc.Property) != 12 {
		t.Errorf("Expecting 12 properties, got %d", len(doc.Property))
	}
	if doc.Property[1].String() != "Australian Broadcasting Corporation" {
		t.Errorf("Expecting 'ABC' as second property, got %s", doc.Property[1])
	}
}

func TestSum(t *testing.T) {
	doc := testFile(t, testSum)
	if len(doc.Property) != 17 {
		t.Errorf("Expecting 17 properties, got %d", len(doc.Property))
	}
	if doc.Property[5].String() != "Normal" {
		t.Errorf("Expecting 'Normal' as sixth property, got %s", doc.Property[5])
	}
}

func TestSum1(t *testing.T) {
	doc := testFile(t, testSum1)
	if len(doc.Property) != 3 {
		t.Errorf("Expecting 3 properties, got %d", len(doc.Property))
	}
	if doc.Property[0].String() != "Mail" {
		t.Errorf("Expecting 'Mail' as first property, got %s", doc.Property[0])
	}
}
