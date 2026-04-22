package deepcopy

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func Test_Copy_structToMap(t *testing.T) {
	t.Run("#1: simple case", func(t *testing.T) {
		type SS struct {
			I int
			U uint
		}

		var s SS = SS{I: 1, U: 2}
		var d map[string]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"I": 1, "U": 2}, d)

		var dd map[string]any
		err = Copy(&dd, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]any{"I": int(1), "U": uint(2)}, dd)
	})

	t.Run("#2: with copy key", func(t *testing.T) {
		type SS struct {
			I int `copy:"i"`
			U uint
		}

		var s SS = SS{I: 1, U: 2}
		var d map[string]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"i": 1, "U": 2}, d)
	})

	t.Run("#3: with custom map key/value type", func(t *testing.T) {
		type SS struct {
			I int `copy:"i"`
			U uint
		}
		type MapKey string
		type MapValue int8

		var s SS = SS{I: 1, U: 2}
		var d map[MapKey]MapValue
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[MapKey]MapValue{"i": 1, "U": 2}, d)
	})

	t.Run("#4: with lossy conversion (int -> int8)", func(t *testing.T) {
		type SS struct {
			I int `copy:"i"`
			U uint
		}
		type MapKey string
		type MapValue int8

		var s SS = SS{I: 1, U: 128}
		var d map[MapKey]MapValue
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[MapKey]MapValue{"i": 1, "U": -128}, d)
	})

	t.Run("#5: with int -> float conversion", func(t *testing.T) {
		type SS struct {
			I int `copy:"i"`
			U uint
		}

		var s SS = SS{I: 1, U: 2}
		var d map[string]float32
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]float32{"i": 1, "U": 2}, d)
	})

	t.Run("#6: with ptr -> value conversion", func(t *testing.T) {
		type SS struct {
			I *int `copy:"i"`
			U uint
		}

		var s SS = SS{I: ptrOf(1), U: 2}
		var d map[string]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"i": 1, "U": 2}, d)

		s = SS{I: nil, U: 2}
		d = map[string]int{}
		err = Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"i": 0, "U": 2}, d)
	})

	t.Run("#7: with value -> ptr conversion", func(t *testing.T) {
		type SS struct {
			I int `copy:"i"`
			U uint
		}

		var s SS = SS{I: 1, U: 2}
		var d map[string]*int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]*int{"i": ptrOf(1), "U": ptrOf(2)}, d)
	})

	t.Run("#8: with struct field has type 'any'", func(t *testing.T) {
		type SS struct {
			I int `copy:"i"`
			U any
		}

		var s SS = SS{I: 1, U: 2}
		var d map[string]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"i": 1, "U": 2}, d)
	})

	t.Run("#9: with map value has type slice", func(t *testing.T) {
		type SS struct {
			I []int `copy:"i"`
			U []uint
		}

		var s SS = SS{I: []int{1, 2}, U: []uint{11, 22}}
		var d map[string][]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string][]int{"i": {1, 2}, "U": {11, 22}}, d)
	})

	t.Run("#10: with struct field is ignored", func(t *testing.T) {
		type SS struct {
			I []int `copy:"-"`
			U uint
		}

		var s SS = SS{I: []int{1, 2}, U: 22}
		var d map[string]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"U": 22}, d)
	})

	t.Run("#11: cyclic reference", func(t *testing.T) {
		type SS struct {
			Ref *SS
		}
		var d map[string]*SS

		var s SS = SS{Ref: &SS{Ref: &SS{}}}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]*SS{"Ref": {Ref: &SS{}}}, d)
	})

	t.Run("#12: map key type is not string, but ignore error NonCopyable", func(t *testing.T) {
		type SS struct {
			I int
		}

		var s SS = SS{I: 1}
		var d map[int]int
		err := Copy(&d, &s, IgnoreNonCopyableTypes(true))
		assert.Nil(t, err)
		assert.Equal(t, map[int]int{}, d)
	})

	t.Run("#13: type is non-copyable and struct field is unexported, but not required (ignored)", func(t *testing.T) {
		type SS struct {
			i float32
		}

		var s SS = SS{i: 1}
		var d map[string]string
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]string{}, d)
	})

	t.Run("#14: deep embedded struct field", func(t *testing.T) {
		type SS3 struct {
			I int `copy:"i"`
		}
		type SS2 struct {
			SS3
		}
		type SS struct {
			SS2
		}

		var s SS = SS{SS2: SS2{SS3: SS3{I: 1}}}
		var d map[string]int
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"i": 1}, d)
	})

	t.Run("#15: deep embedded struct field, but nil ptr", func(t *testing.T) {
		type SS3 struct {
			I int `copy:"i"`
		}
		type SS2 struct {
			*SS3
		}
		type SS struct {
			SS2
		}

		var s SS = SS{SS2: SS2{SS3: nil}}
		var d map[string]int
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{}, d)
	})
}

func Test_Copy_structToMap_error(t *testing.T) {
	t.Run("#1: with struct fields have different types", func(t *testing.T) {
		type SS struct {
			I int
			S string
		}
		var s SS = SS{I: 1, S: "abc"}
		var d map[string]int
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#2: with struct fields have different types", func(t *testing.T) {
		type SS struct {
			I int
			S any
		}
		var s SS = SS{I: 1, S: "abc"}
		var d map[string]int
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#3: with non-copyable type", func(t *testing.T) {
		type SS struct {
			P unsafe.Pointer // unsafe.Pointer is not copyable for now
		}

		var s SS = SS{P: nil}
		var d map[string]int
		err := Copy(&d, &s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#4: map key type is not string", func(t *testing.T) {
		type SS struct {
			I int
		}

		var s SS = SS{I: 1}
		var d map[int]int
		err := Copy(&d, &s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#5: non-copyable, but field requires copying", func(t *testing.T) {
		type SS struct {
			P unsafe.Pointer `copy:",required"`
		}

		s := SS{P: nil}
		var d map[string]unsafe.Pointer
		err := Copy(&d, &s, IgnoreNonCopyableTypes(true))
		assert.ErrorIs(t, err, ErrFieldRequireCopying)
	})
}

func Test_Copy_structToMap_unexported(t *testing.T) {
	t.Run("#1: struct field unexported, but required", func(t *testing.T) {
		type SS struct {
			I int
			u uint `copy:"u,required"`
		}

		var s SS = SS{I: 1, u: 2}
		var d map[string]int
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"I": 1, "u": 2}, d)
	})

	t.Run("#2: struct field unexported, but non-required", func(t *testing.T) {
		type SS struct {
			I int
			u uint `copy:"u"`
		}

		var s SS = SS{I: 1, u: 2}
		var d map[string]int
		err := Copy(&d, s) // NOTE: pass src as value to cause Unaddressable error
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"I": 1}, d)
	})

	t.Run("#3: struct field unexported", func(t *testing.T) {
		type SS struct {
			I int
			u uint
		}

		var s SS = SS{I: 1, u: 2}
		var d map[string]int
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, map[string]int{"I": 1, "u": 2}, d)
	})
}

func Test_Copy_structToMap_unexported_error(t *testing.T) {
	t.Run("#1: unaddressable field causes failure of copying unexported field", func(t *testing.T) {
		type SS struct {
			i int `copy:"i,required"`
			S any
		}
		var s SS = SS{i: 1, S: 2}
		var d map[string]int
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrValueUnaddressable)
	})
}

type testDstMap1 map[string]int

func (d testDstMap1) CopyI1(i1 int) error {
	d["x1"] = i1 * 2
	return nil
}
func (d testDstMap1) CopyI2(i2 int) { // incorrect method prototype (no return error)
	d["x2"] = i2 * 2
}
func (d testDstMap1) CopyI3(i3 int, v string) error { // incorrect method prototype (2 input args)
	d["x3"] = i3 * 2
	return nil
}
func (d testDstMap1) CopyI4(i4 uint) error { // incorrect method prototype (unmatched input type)
	d["x4"] = int(i4 * 2) //nolint:gosec
	return nil
}
func (d testDstMap1) CopyI5(i5 int) string { // incorrect method prototype (not return error type)
	return ""
}
func (d testDstMap1) CopyI6(i6 int) error { // incorrect method prototype (unmatched input type)
	return errTest
}
func (d testDstMap1) NotCopy(i6 int) error { // not a copying method
	return errTest
}

func Test_Copy_structToMap_method(t *testing.T) {
	t.Run("#1: field -> dst method", func(t *testing.T) {
		type SS struct {
			I1 int
			U  uint
		}

		var s SS = SS{I1: 1, U: 2}
		var d testDstMap1
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testDstMap1{"x1": 2, "U": 2}, d)
	})

	t.Run("#2: unexported field -> dst method", func(t *testing.T) {
		type SS struct {
			i1 int `copy:"I1,required"`
			U  uint
		}

		var s SS = SS{i1: 1, U: 2}
		var d testDstMap1
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, testDstMap1{"x1": 2, "U": 2}, d)
	})

	t.Run("#3: incorrect method prototype (CopyI2())", func(t *testing.T) {
		type SS struct {
			I2 int
			U  uint
		}

		var s SS = SS{I2: 1, U: 2}
		var d testDstMap1
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testDstMap1{"I2": 1, "U": 2}, d) // CopyI2 is not called
	})

	t.Run("#4: not allow copying from field -> method", func(t *testing.T) {
		type SS struct {
			I1 int
			U  uint
		}

		var s SS = SS{I1: 1, U: 2}
		var d testDstMap1
		err := Copy(&d, s, CopyBetweenStructFieldAndMethod(false))
		assert.Nil(t, err)
		assert.Equal(t, testDstMap1{"I1": 1, "U": 2}, d)
	})

	t.Run("#5: copy from src embedded field", func(t *testing.T) {
		type SBase struct {
			I1 int
		}
		type SS struct {
			SBase
			U uint
		}

		var s SS = SS{U: 2, SBase: SBase{I1: 123}}
		var d testDstMap1
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testDstMap1{"U": 2, "x1": 246}, d)
	})

	t.Run("#6: copy from src embedded field, but field value can't be retrieved due to nil ptr", func(t *testing.T) {
		type SBase struct {
			I1 int
		}
		type SS struct {
			*SBase
			U uint
		}

		var s SS = SS{U: 2}
		var d testDstMap1
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testDstMap1{"U": 2}, d)
	})
}

func Test_Copy_structToMap_method_error(t *testing.T) {
	t.Run("#1: unexported field -> dst method", func(t *testing.T) {
		type SS struct {
			i1 int `copy:"I1,required"`
			U  uint
		}

		var s SS = SS{i1: 1, U: 2}
		var d testDstMap1
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrValueUnaddressable)
	})

	t.Run("#2: incorrect method prototype (CopyI4())", func(t *testing.T) {
		type SS struct {
			I4 int `copy:",required"`
			U  uint
		}

		var s SS = SS{I4: 1, U: 2}
		var d testDstMap1
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrMethodInvalid)
	})

	t.Run("#3: copy method return error (CopyI6())", func(t *testing.T) {
		type SS struct {
			I6 int `copy:",required"`
			U  uint
		}

		var s SS = SS{I6: 1, U: 2}
		var d testDstMap1
		err := Copy(&d, s)
		assert.ErrorIs(t, err, errTest)
	})
}

type testSrc2 struct {
	I int
	U uint
}

type testDstMap2 map[string]int

func (d testDstMap2) PostCopy(src any) error {
	testSrc2, _ := src.(testSrc2)
	if testSrc2.I == 100 {
		return errTest
	}
	d["I"] *= 2
	d["U"] *= 2
	return nil
}

type testDstMap3 struct {
	I int
	U uint
}

func (d testDstMap3) PostCopy(src any) any {
	d.I *= 2
	d.U *= 2
	return nil
}

func Test_Copy_structToMap_with_post_copy_event(t *testing.T) {
	t.Run("#1: success without error", func(t *testing.T) {
		s := testSrc2{I: 1, U: 2}
		var d testDstMap2
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testDstMap2{"I": 2, "U": 4}, d)
	})

	t.Run("#2: PostCopy returns error", func(t *testing.T) {
		s := testSrc2{I: 100, U: 2} // When testSrc2.I == 100, PostCopy returns error
		d := testDstMap2{}
		err := Copy(&d, s)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("#3: dstStruct.PostCopy not satisfied", func(t *testing.T) {
		s := testSrc2{I: 1, U: 2}
		d := testDstMap3{}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testDstMap3{I: 1, U: 2}, d)
	})
}
