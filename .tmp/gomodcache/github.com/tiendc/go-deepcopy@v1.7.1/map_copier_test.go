package deepcopy

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Copy_map(t *testing.T) {
	t.Run("#1: nil map", func(t *testing.T) {
		var s map[int]int
		var d map[int]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Nil(t, d)
	})

	t.Run("#2: map of (int,int) -> map of (int,int)", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d map[int]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]int{1: 11, 2: 22, 3: 33}, d)
	})

	t.Run("#3: map of (int,int) -> map of (int,IntT)", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d map[int]IntT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]IntT{1: 11, 2: 22, 3: 33}, d)
	})

	t.Run("#4: map of (int,int) -> map of (int,float32)", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d map[int]float32
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]float32{1: 11, 2: 22, 3: 33}, d)
	})

	t.Run("#5: map of (int,float32) -> map of (int,int)", func(t *testing.T) {
		var s map[int]float32 = map[int]float32{1: 11.11, 2: 22.22, 3: 33.22}
		var d map[int]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]int{1: 11, 2: 22, 3: 33}, d)
	})

	t.Run("#6: map of (int,struct) -> map of (int,struct)", func(t *testing.T) {
		type SS struct {
			I int
			U uint
		}
		type DD struct {
			I int
			U uint
		}

		var s map[int]SS = map[int]SS{1: {1, 11}, 2: {2, 22}, 3: {3, 33}}
		var d map[int]DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]DD{1: {1, 11}, 2: {2, 22}, 3: {3, 33}}, d)
	})

	t.Run("#7: map of (int,*struct) -> map of (int,*struct)", func(t *testing.T) {
		type SS struct {
			I int
			U uint
		}
		type DD struct {
			I int
			U uint
		}

		var s map[int]*SS = map[int]*SS{1: {1, 11}, 2: {2, 22}, 3: {3, 33}}
		var d map[int]*DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]*DD{1: {1, 11}, 2: {2, 22}, 3: {3, 33}}, d)
	})

	t.Run("#8: map of (int,slice) -> map of (int,array)", func(t *testing.T) {
		var s map[int][]int = map[int][]int{1: {1, 11}, 2: {2, 22}, 3: {3, 33}}
		var d map[int][3]int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int][3]int{1: {1, 11, 0}, 2: {2, 22, 0}, 3: {3, 33, 0}}, d)
	})

	t.Run("#9: map of (IntT,int) -> map of (int,IntT)", func(t *testing.T) {
		var s map[IntT]int = map[IntT]int{1: 11, 2: 22, 3: 33}
		var d map[int]IntT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]IntT{1: 11, 2: 22, 3: 33}, d)
	})

	t.Run("#10: map of (int,iface) -> map of (int,int)", func(t *testing.T) {
		var s map[int]any = map[int]any{1: 11, 2: 22, 3: 33}
		var d map[int]IntT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, map[int]IntT{1: 11, 2: 22, 3: 33}, d)
	})

	t.Run("#11: map of (int,int) -> map-derived-type of (int,int)", func(t *testing.T) {
		type MapT map[int]int

		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d MapT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, MapT{1: 11, 2: 22, 3: 33}, d)
	})

	t.Run("#12: map of (int,int) -> map-derived-type of (int,float32)", func(t *testing.T) {
		type MapT map[int]float32

		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d MapT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, MapT{1: 11, 2: 22, 3: 33}, d)
	})
}

func Test_Copy_map_error(t *testing.T) {
	t.Run("#1: map of (int,iface-of-int) -> map of (int,bool)", func(t *testing.T) {
		var s map[int]any = map[int]any{1: 11, 2: 22, 3: 33}
		var d map[int]bool
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#2: map of (int,int) -> map of (int,string)", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d map[int][]int
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#3: map of (int,int) -> map of ([3]int,int)", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d map[[3]int]int
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#4: map -> slice (error)", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 11, 2: 22, 3: 33}
		var d []int
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#5: key copier returns error", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 1, 2: 2}
		var d map[int]int
		cp := &mapCopier{
			ctx:       defaultContext(),
			keyCopier: &mapItemCopier{copier: &errorCopier{}, dstType: reflect.TypeOf(0)},
		}
		err := cp.Copy(reflect.ValueOf(&d).Elem(), reflect.ValueOf(s))
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("#6: value copier returns error", func(t *testing.T) {
		var s map[int]int = map[int]int{1: 1, 2: 2}
		var d map[int]int
		cp := &mapCopier{
			ctx:         defaultContext(),
			valueCopier: &mapItemCopier{copier: &errorCopier{}, dstType: reflect.TypeOf(0)},
		}
		err := cp.Copy(reflect.ValueOf(&d).Elem(), reflect.ValueOf(s))
		assert.ErrorIs(t, err, errTest)
	})
}
