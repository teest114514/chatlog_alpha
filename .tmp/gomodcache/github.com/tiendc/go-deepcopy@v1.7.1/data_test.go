package deepcopy

import (
	"errors"
	"reflect"
)

type errorCopier struct {
}

func (c *errorCopier) Copy(dst, src reflect.Value) error {
	return errTest
}

type StrT string
type IntT int

func ptrOf[T any](v T) *T {
	return &v
}

var (
	errTest = errors.New("err test")
)

type srcStruct2 struct {
	S string
	I int
	U uint32
	F float64
	B bool

	Method int
}

type dstStruct2 struct {
	S string
	I int
	U uint32
	F float64
	B bool

	MethodVal int `copy:"Method"`
}

func (d *dstStruct2) CopyMethod(v int) error {
	d.MethodVal = v * 2
	return nil
}

func (d *dstStruct2) EqualSrcStruct2(s *srcStruct2) bool {
	return d.S == s.S && d.I == s.I && d.U == s.U && d.F == s.F && d.B == s.B && d.MethodVal == s.Method*2
}

type srcStruct1 struct {
	S string
	I int
	U uint32
	F float64
	B bool

	II []int
	UU []uint
	SS []string
	V  srcStruct2
	VV []srcStruct2

	M1 map[int]string
	M2 *map[int8]int8
	M3 map[int]int
	M4 map[[3]int]*srcStruct2

	NilP2V *int
	P2V    *int
	V2P    int
	S2A    []string

	MatchedX   string `copy:"Matched"`
	UnmatchedX string `copy:"UnmatchedX"`
}

type dstStruct1 struct {
	S StrT
	I int
	U uint32
	F float64
	B *bool

	II []int
	UU []uint
	SS []*StrT
	V  dstStruct2
	VV []dstStruct2

	M1 map[int]string
	M2 map[int8]int8
	M3 *map[int]IntT
	M4 map[[3]int]*dstStruct2

	NilP2V int
	P2V    int
	V2P    *int
	S2A    [3]string

	MatchedY   string `copy:"Matched"`
	UnmatchedY string `copy:"UnmatchedY"`
}

var (
	srcStructA = srcStruct2{
		S: "string",
		I: 10,
		U: 100,
		F: 1.234,
		B: true,

		Method: 1234,
	}

	srcStructB = srcStruct2{
		S: "string",
		I: 10,
		U: 100,
		F: 1.234,
		B: true,

		Method: 4321,
	}

	p2v = 1234
	//nolint
	srcStruct = srcStruct1{
		S: "string",
		I: 10,
		U: 10,
		F: 1.234,
		B: true,

		II: []int{1, 2, 3},
		UU: nil,
		SS: []string{"string1", "string2", "", "string4", "string5"},
		V:  srcStructA,
		VV: []srcStruct2{srcStructA, srcStructB, srcStructA, srcStructB, srcStructA},

		M1: map[int]string{1: "11", 2: "22", 3: "33"},
		M2: nil,
		M3: map[int]int{7: 77, 8: 88, 9: 99},
		M4: map[[3]int]*srcStruct2{
			[3]int{1, 1, 1}: &srcStructA,
			[3]int{2, 2, 2}: &srcStructB,
		},

		NilP2V: nil,
		P2V:    &p2v,
		V2P:    123,
		S2A:    []string{"1", "2", "3", "4"},

		MatchedX:   "MatchedX",
		UnmatchedX: "UnmatchedX",
	}
)
