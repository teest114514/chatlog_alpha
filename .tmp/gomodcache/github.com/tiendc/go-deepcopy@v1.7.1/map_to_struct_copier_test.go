package deepcopy

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func Test_Copy_mapToStruct(t *testing.T) {
	t.Run("#1: simple case", func(t *testing.T) {
		type DD struct {
			I int
			U uint
		}

		s := map[string]int{"I": 1, "U": 2}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, U: 2}, d)
	})

	t.Run("#2: with copy key", func(t *testing.T) {
		type DD struct {
			I int `copy:"i"`
			U uint
		}

		s := map[string]int{"i": 1, "U": 2}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, U: 2}, d)
	})

	t.Run("#3: with custom map key/value type", func(t *testing.T) {
		type DD struct {
			I int `copy:"i"`
			U uint
		}
		type MapKey string
		type MapValue int8

		s := map[MapKey]MapValue{"i": 1, "U": 2}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, U: 2}, d)
	})

	t.Run("#4: with lossy conversion (int -> int8)", func(t *testing.T) {
		type DD struct {
			I int8 `copy:"i"`
			U uint
		}

		s := map[string]int{"i": 128, "U": 222}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: -128, U: 222}, d)
	})

	t.Run("#5: with int -> float conversion", func(t *testing.T) {
		type DD struct {
			I float32 `copy:"i"`
			U uint
		}

		s := map[string]int{"i": 1, "U": 2}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, U: 2}, d)
	})

	t.Run("#6: with ptr -> value conversion", func(t *testing.T) {
		type DD struct {
			I int `copy:"i"`
			S string
		}

		s := map[string]any{"i": ptrOf(1), "S": ptrOf("abc")}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, S: "abc"}, d)
	})

	t.Run("#7: with value -> ptr conversion", func(t *testing.T) {
		type DD struct {
			I *int `copy:"i"`
			S *string
		}

		s := map[string]any{"i": 1, "S": "abc"}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: ptrOf(1), S: ptrOf("abc")}, d)
	})

	t.Run("#8: with struct field has type 'any'", func(t *testing.T) {
		type DD struct {
			I any `copy:"i"`
			S any
		}

		s := map[string]any{"i": 1, "S": ptrOf("abc")}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, S: ptrOf("abc")}, d)
	})

	t.Run("#9: with map value has type slice", func(t *testing.T) {
		type DD struct {
			I []int `copy:"i"`
			S []string
		}

		s := map[string]any{"i": []int{1, 2}, "S": []string{"aa", "bb"}}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: []int{1, 2}, S: []string{"aa", "bb"}}, d)
	})

	t.Run("#10: with struct field is ignored", func(t *testing.T) {
		type DD struct {
			I int `copy:"-"`
			S string
		}

		s := map[string]any{"i": ptrOf(1), "S": ptrOf("abc")}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 0, S: "abc"}, d)
	})

	t.Run("#11: cyclic reference", func(t *testing.T) {
		type DD struct {
			I   int
			Ref *DD
		}

		s := map[string]any{"Ref": &DD{I: 1}}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{Ref: &DD{I: 1}}, d)
	})

	t.Run("#12: map key type is not string, but ignore error NonCopyable", func(t *testing.T) {
		type DD struct {
			I int
		}

		s := map[int]string{1: "a"}
		var d DD
		err := Copy(&d, &s, IgnoreNonCopyableTypes(true))
		assert.Nil(t, err)
		assert.Equal(t, DD{}, d)
	})

	t.Run("#13: type is non-copyable and struct field is unexported, but not required (ignored)", func(t *testing.T) {
		type DD struct {
			i int
		}

		s := map[string]string{"i": "1"}
		var d DD
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{}, d)
	})

	t.Run("#14: deep embedded struct field", func(t *testing.T) {
		type DD3 struct {
			I int `copy:"i"`
		}
		type DD2 struct {
			DD3
		}
		type DD struct {
			DD2
		}

		s := map[string]any{"i": 1}
		var d DD
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{DD2: DD2{DD3: DD3{I: 1}}}, d)
	})

	t.Run("#15: deep embedded struct field, but use ptr", func(t *testing.T) {
		type DD3 struct {
			I int `copy:"i"`
		}
		type DD2 struct {
			*DD3
		}
		type DD struct {
			DD2
		}

		s := map[string]any{"i": 1}
		var d DD
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{DD2: DD2{DD3: &DD3{I: 1}}}, d)
	})

	t.Run("#16: src map is nil", func(t *testing.T) {
		type DD struct {
			I int
		}

		var s map[string]int
		d := DD{I: 1}
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1}, d)
	})

	t.Run("#17: set destination field nil when it's zero", func(t *testing.T) {
		type DD struct {
			I *int `copy:",nilonzero"`
		}

		s := map[string]int{"I": 0}
		var d DD
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: nil}, d)
	})

	t.Run("#18: map-in-map", func(t *testing.T) {
		type DD2 struct {
			I int
		}
		type DD struct {
			DD2 DD2
		}

		s := map[string]map[string]any{"DD2": {"I": 1}}
		var d DD
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{DD2: DD2{I: 1}}, d)
	})
}

func Test_Copy_mapToStruct_error(t *testing.T) {
	t.Run("#1: with struct fields have different types", func(t *testing.T) {
		type DD struct {
			I int
			U uint
		}
		s := map[string]any{"I": 1, "U": "a"}
		var d DD
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#2: with non-copyable type", func(t *testing.T) {
		type DD struct {
			P uint
		}

		s := map[string]any{"P": (unsafe.Pointer)(ptrOf(111))}
		var d DD
		err := Copy(&d, &s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#3: map key type is not string", func(t *testing.T) {
		type DD struct {
			I int
		}

		s := map[int]any{1: 1, 2: "a"}
		var d DD
		err := Copy(&d, &s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#4: field requires copying", func(t *testing.T) {
		type DD struct {
			I int `copy:",required"`
		}

		s := map[string]any{"A": 123}
		var d DD
		err := Copy(&d, &s)
		assert.ErrorIs(t, err, ErrFieldRequireCopying)
	})

	t.Run("#5: non-copyable, but field requires copying", func(t *testing.T) {
		type DD struct {
			P unsafe.Pointer `copy:",required"`
		}

		s := map[string]unsafe.Pointer{"P": nil}
		var d DD
		err := Copy(&d, &s, IgnoreNonCopyableTypes(true))
		assert.ErrorIs(t, err, ErrFieldRequireCopying)
	})
}

func Test_Copy_mapToStruct_unexported(t *testing.T) {
	t.Run("#1: struct field unexported", func(t *testing.T) {
		type DD struct {
			I int
			u uint
		}

		s := map[string]any{"I": 1, "u": 2}
		var d DD
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, u: 2}, d)
	})

	t.Run("#2: struct field unexported, but required", func(t *testing.T) {
		type DD struct {
			I int
			u uint `copy:"u,required"`
		}

		s := map[string]any{"I": 1, "u": 2}
		var d DD
		err := Copy(&d, &s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, u: 2}, d)
	})
}

func Test_Copy_mapToStruct_unexported_error(t *testing.T) {
	t.Run("#1: struct field unexported, but required", func(t *testing.T) {
		type DD struct {
			I int
			u uint `copy:"u,required"`
		}

		s := map[string]any{"I": 1}
		var d DD
		err := Copy(&d, &s)
		assert.ErrorIs(t, err, ErrFieldRequireCopying)
	})
}

type testD3 struct {
	x1 int
	x2 int
	U  uint
}

func (d *testD3) CopyI1(i1 int) error {
	d.x1 = i1 * 2
	return nil
}
func (d *testD3) CopyI2(i2 int) { // incorrect method prototype (no return error)
	d.x2 = i2 * 2
}

type testD4 struct {
	x4 int `copy:",required"`
	U  uint
}

func (d *testD4) CopyI4(i4 int, v string) error { // incorrect method prototype (2 input args)
	d.x4 = i4 * 2
	return nil
}

type testD5 struct {
	x5 int `copy:",required"`
	U  uint
}

func (d *testD5) CopyI5(i5 int) string { // incorrect method prototype (not return error type)
	return ""
}

type testD6 struct {
	x6 int `copy:",required"`
	U  uint
}

func (d *testD6) CopyI6(i6 int) error { // incorrect method prototype (unmatched input type)
	return errTest
}

func Test_Copy_mapToStruct_method(t *testing.T) {
	t.Run("#1: map entry -> dst method", func(t *testing.T) {
		s := map[string]int{"I1": 1, "U": 2}
		var d testD3
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testD3{x1: 2, U: 2}, d)
	})

	t.Run("#2: incorrect method prototype (CopyI2())", func(t *testing.T) {
		s := map[string]int{"I2": 1, "U": 2}
		var d testD3
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testD3{U: 2}, d)
	})

	t.Run("#3: not allow copying via method", func(t *testing.T) {
		s := map[string]int{"I1": 1, "U": 2}
		var d testD3
		err := Copy(&d, s, CopyBetweenStructFieldAndMethod(false))
		assert.Nil(t, err)
		assert.Equal(t, testD3{U: 2}, d)
	})
}

func Test_Copy_mapToStruct_method_error(t *testing.T) {
	t.Run("#1: unmatched method arg type (CopyI1())", func(t *testing.T) {
		s := map[string]string{"I1": "a"}
		var d testD3
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrMethodInvalid)
	})

	t.Run("#2: incorrect method prototype (CopyI4())", func(t *testing.T) {
		s := map[string]int{"I4": 1, "U": 2}
		var d testD4
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrFieldRequireCopying)
	})

	t.Run("#3: incorrect method prototype (CopyI5())", func(t *testing.T) {
		s := map[string]int{"I5": 1, "U": 2}
		var d testD5
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrFieldRequireCopying)
	})

	t.Run("#4: copying method returns error (CopyI6())", func(t *testing.T) {
		s := map[string]int{"I6": 1, "U": 2}
		var d testD6
		err := Copy(&d, s)
		assert.ErrorIs(t, err, errTest)
	})
}

type testD7 struct {
	I int
	U uint
}

func (d *testD7) PostCopy(src any) error {
	srcMap, _ := src.(map[string]int)
	if srcMap["I"] == 100 {
		return errTest
	}
	d.I *= 2
	d.U *= 2
	return nil
}

type testD8 struct {
	I int
	U uint
}

func (d *testD8) PostCopy(src any) int { // has incorrect method prototype
	d.I *= 2
	d.U *= 2
	return 0
}

func Test_Copy_mapToStruct_with_post_copy_event(t *testing.T) {
	t.Run("#1: success without error", func(t *testing.T) {
		s := map[string]int{"I": 1, "U": 2}
		var d testD7
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testD7{I: 2, U: 4}, d)
	})

	t.Run("#2: PostCopy returns error", func(t *testing.T) {
		s := map[string]int{"I": 100, "U": 2} // When map["I"] == 100, PostCopy returns error
		var d testD7
		err := Copy(&d, s)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("#3: PostCopy not satisfied", func(t *testing.T) {
		s := map[string]int{"I": 1, "U": 2}
		var d testD8
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, testD8{I: 1, U: 2}, d)
	})
}
