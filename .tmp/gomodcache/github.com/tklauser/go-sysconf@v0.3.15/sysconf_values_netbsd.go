// Copyright 2022 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package sysconf

/*
#include <limits.h>
*/
import "C"

const (
	_LONG_MAX = C.LONG_MAX
)
