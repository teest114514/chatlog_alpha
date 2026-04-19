//go:build go1.18
// +build go1.18

package efp_test

import (
	"testing"

	"github.com/xuri/efp"
)

func FuzzParse(f *testing.F) {
	f.Add("=0")
	f.Add("=SUM(A3+B9*2)/2")
	f.Fuzz(func(t *testing.T, formula string) {
		p := efp.ExcelParser()
		tokens := p.Parse(formula)
		_ = tokens
		if p.InError {
			t.Skip()
		}
		t.Log(p.Render())
	})
}
