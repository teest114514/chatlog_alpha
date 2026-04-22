// Copyright 2018 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"regexp"
	"runtime"
)

func gensysconf(in, out, goos, goarch string) error {
	if _, err := os.Stat(in); err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return err
		}
	}

	cmd := exec.Command("go", "tool", "cgo", "-godefs", in)
	defer os.RemoveAll("_obj")
	b, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, string(b))
		return err
	}

	goBuild := goos
	if goarch != "" {
		goBuild = fmt.Sprintf("%s && %s", goos, goarch)
	}

	r := fmt.Sprintf(`$1

//go:build %s`, goBuild)
	cgoCommandRegex := regexp.MustCompile(`(cgo -godefs .*)`)
	b = cgoCommandRegex.ReplaceAll(b, []byte(r))

	b, err = format.Source(b)
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0644)
}

func main() {
	goos := os.Getenv("GOOS_TARGET")
	if goos == "" {
		goos = runtime.GOOS
		if goos == "illumos" {
			goos = "solaris"
		}
	}
	goarch := os.Getenv("GOARCH_TARGET")
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	defs := fmt.Sprintf("sysconf_defs_%s.go", goos)
	if err := gensysconf(defs, "z"+defs, goos, ""); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	vals := fmt.Sprintf("sysconf_values_%s.go", goos)
	// sysconf variable values are GOARCH-specific, thus write per GOARCH
	zvals := fmt.Sprintf("zsysconf_values_%s_%s.go", goos, goarch)
	if err := gensysconf(vals, zvals, goos, goarch); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
