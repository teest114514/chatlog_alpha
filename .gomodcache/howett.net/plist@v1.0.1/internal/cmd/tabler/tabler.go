package main

import (
	"fmt"
	"os"
)

var usage = `Usage: tabler <var> <charset>

Produces a text_tables.go-compatible character table with the given
variable name.`

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}

	nam := os.Args[1]
	arg := os.Args[2]
	var vals [4]uint64
	for _, v := range arg {
		bucket := uint(v) / 64
		pos := uint(v) % 64
		vals[bucket] = vals[bucket] | (1 << pos)
	}
	fmt.Printf("var %s = characterSet{\n", nam)
	for _, v := range vals {
		fmt.Printf("\t0x%16.016x,\n", v)
	}
	fmt.Printf("}\n")
}
