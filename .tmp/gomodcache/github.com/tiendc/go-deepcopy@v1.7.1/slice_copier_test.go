package deepcopy

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Copy_slice(t *testing.T) {
	t.Run("#1: nil slice", func(t *testing.T) {
		var d []int
		err := Copy(&d, ([]int)(nil))
		assert.Nil(t, err)
		assert.Nil(t, d)
	})

	t.Run("#2: slice of int -> slice of int", func(t *testing.T) {
		var s []int = []int{1, 2, 3}
		var d []int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []int{1, 2, 3}, d)
	})

	t.Run("#3: slice of int -> slice of int (dst has filled)", func(t *testing.T) {
		var s []int = []int{1, 2, 3}
		var d []int = []int{1, 1, 1, 2, 2, 2}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []int{1, 2, 3}, d)
	})

	t.Run("#4: empty slice of str -> slice of str (dst has filled)", func(t *testing.T) {
		var s []string = []string{}
		var d []string = []string{"1", "2", "3"}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []string{}, d)
	})

	t.Run("#5: slice of str -> slice of str-ptr", func(t *testing.T) {
		var s []string = []string{"1", "2", "3"}
		var d []*string
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []*string{ptrOf("1"), ptrOf("2"), ptrOf("3")}, d)
	})

	t.Run("#6: slice of str -> slice of str-derived-type", func(t *testing.T) {
		var s []string = []string{"1", "2", "3"}
		var d []StrT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []StrT{"1", "2", "3"}, d)
	})
}

func Test_Copy_slice_error(t *testing.T) {
	t.Run("#1: dst is not pointer", func(t *testing.T) {
		var s []int = []int{1, 2, 3}
		var d []int
		err := Copy(d, s)
		assert.ErrorIs(t, err, ErrTypeInvalid)
	})

	t.Run("#2: slice -> map (error)", func(t *testing.T) {
		var s []string = []string{"1", "2", "3"}
		var d map[int]string
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#3: slice of int -> slice of struct", func(t *testing.T) {
		type DD struct {
			I int
		}
		var s []int = []int{1, 2, 3}
		var d []DD
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#4: slice item copier returns error", func(t *testing.T) {
		var s []int = []int{1, 2, 3}
		var d []int
		cp := &sliceCopier{ctx: defaultContext(), itemCopier: &errorCopier{}}
		err := cp.Copy(reflect.ValueOf(&d).Elem(), reflect.ValueOf(s))
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("#5: array item copier returns error", func(t *testing.T) {
		var s [3]int = [3]int{1, 2, 3}
		var d [3]int
		cp := &sliceCopier{ctx: defaultContext(), itemCopier: &errorCopier{}}
		err := cp.Copy(reflect.ValueOf(&d).Elem(), reflect.ValueOf(s))
		assert.ErrorIs(t, err, errTest)
	})
}

func Test_Copy_array(t *testing.T) {
	t.Run("#1: array of int -> array of int", func(t *testing.T) {
		var s [3]int = [3]int{1, 2, 3}
		var d [3]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, [3]int{1, 2, 3}, d)
	})

	t.Run("#2: array of int -> array of int (dst has filled)", func(t *testing.T) {
		var s [3]int = [3]int{1, 2, 3}
		var d [6]int = [6]int{1, 1, 1, 2, 2, 2}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, [6]int{1, 2, 3, 0, 0, 0}, d)
	})

	t.Run("#3: array of str -> slice of str", func(t *testing.T) {
		var s [3]string = [3]string{"1", "2", "3"}
		var d []string
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []string{"1", "2", "3"}, d)
	})

	t.Run("#4: array of str -> slice of str (dst has filled less)", func(t *testing.T) {
		var s [3]string = [3]string{"1", "2", "3"}
		var d []string = []string{"1", "2"}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []string{"1", "2", "3"}, d)
	})

	t.Run("#5: array of str -> slice of str (dst has filled more)", func(t *testing.T) {
		var s [3]string = [3]string{"1", "2", "3"}
		var d []string = []string{"1", "2", "3", "4", "5"}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []string{"1", "2", "3"}, d)
	})

	t.Run("#6: slice of str -> array of str (dst has filled less)", func(t *testing.T) {
		var s []string = []string{"1", "2", "3"}
		var d [2]string = [2]string{"x", "x"}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, [2]string{"1", "2"}, d)
	})

	t.Run("#7: slice of str -> array of str (dst has filled more)", func(t *testing.T) {
		var s []string = []string{"1", "2", "3"}
		var d [5]string = [5]string{"1", "2", "3", "4", "5"}
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, [5]string{"1", "2", "3", "", ""}, d)
	})
}

func Test_Copy_array_error(t *testing.T) {
	t.Run("#1: array -> map (error)", func(t *testing.T) {
		var s [3]string = [3]string{"1", "2", "3"}
		var d map[int]string
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#2: array of int -> slice of struct", func(t *testing.T) {
		type DD struct {
			I int
		}
		var s [3]int = [3]int{1, 2, 3}
		var d []DD
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})
}
