package urn

import (
	"fmt"
	"testing"
)

var benchs = []testCase{
	urn2141OnlyTestCases[14],
	urn2141OnlyTestCases[2],
	urn2141OnlyTestCases[6],
	urn2141OnlyTestCases[10],
	urn2141OnlyTestCases[11],
	urn2141OnlyTestCases[13],
	urn2141OnlyTestCases[20],
	urn2141OnlyTestCases[23],
	urn2141OnlyTestCases[33],
	urn2141OnlyTestCases[45],
	urn2141OnlyTestCases[47],
	urn2141OnlyTestCases[48],
	urn2141OnlyTestCases[50],
	urn2141OnlyTestCases[52],
	urn2141OnlyTestCases[53],
	urn2141OnlyTestCases[57],
	urn2141OnlyTestCases[62],
	urn2141OnlyTestCases[63],
	urn2141OnlyTestCases[67],
	urn2141OnlyTestCases[60],
}

// This is here to avoid compiler optimizations that
// could remove the actual call we are benchmarking
// during benchmarks
var benchParseResult *URN

func BenchmarkParse(b *testing.B) {
	for ii, tt := range benchs {
		tt := tt
		outcome := (map[bool]string{true: "ok", false: "no"})[tt.ok]
		b.Run(
			fmt.Sprintf("%s/%02d/%s/", outcome, ii, rxpad(string(tt.in), 45)),
			func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					benchParseResult, _ = Parse(tt.in)
				}
			},
		)
	}
}
