package deepcopy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Copy(t *testing.T) {
	src := &srcStruct
	var dst dstStruct1
	err := Copy(&dst, src)
	assert.Nil(t, err)

	// Common fields
	assert.Equal(t, StrT(src.S), dst.S)
	assert.Equal(t, src.I, dst.I)
	assert.Equal(t, src.U, dst.U)
	assert.Equal(t, src.F, dst.F)
	assert.Equal(t, src.B, *dst.B)

	assert.True(t, dst.V.EqualSrcStruct2(&src.V))

	// Slice/Array fields
	assert.Equal(t, src.II, dst.II)
	assert.Equal(t, src.UU, dst.UU)
	for i := range dst.SS {
		assert.Equal(t, StrT(src.SS[i]), *dst.SS[i])
	}
	for i := range dst.VV {
		assert.True(t, dst.VV[i].EqualSrcStruct2(&src.VV[i]))
	}

	assert.Equal(t, 0, dst.NilP2V)
	assert.Equal(t, *src.P2V, dst.P2V)
	assert.Equal(t, src.V2P, *dst.V2P)

	// Map fields
	assert.Equal(t, src.M1, dst.M1)
	assert.True(t, src.M2 == nil && dst.M2 == nil)
	assert.Equal(t, len(src.M3), len(*dst.M3))
	for k, v := range *dst.M3 {
		assert.Equal(t, IntT(src.M3[k]), v)
	}
	assert.Equal(t, len(src.M4), len(dst.M4))
	for k, v := range dst.M4 {
		assert.True(t, v.EqualSrcStruct2(src.M4[k]))
	}

	// Slice to Array
	assert.Equal(t, 3, len(dst.S2A))
	for i := range dst.S2A {
		assert.Equal(t, src.S2A[i], dst.S2A[i])
	}

	// Copy key matching
	assert.Equal(t, src.MatchedX, dst.MatchedY)
	assert.NotEqual(t, src.UnmatchedX, dst.UnmatchedY)
}

func Test_ClearCache(t *testing.T) {
	ClearCache()
	assert.Equal(t, 0, len(copierCacheMap))
}

func Test_ConfigOption(t *testing.T) {
	ctx := defaultContext()

	CopyBetweenPtrAndValue(false)(ctx)
	assert.Equal(t, false, ctx.CopyBetweenPtrAndValue)
	CopyBetweenPtrAndValue(true)(ctx)
	assert.Equal(t, true, ctx.CopyBetweenPtrAndValue)

	CopyViaCopyingMethod(false)(ctx)
	assert.Equal(t, false, ctx.CopyViaCopyingMethod)
	CopyViaCopyingMethod(true)(ctx)
	assert.Equal(t, true, ctx.CopyViaCopyingMethod)

	IgnoreNonCopyableTypes(false)(ctx)
	assert.Equal(t, false, ctx.IgnoreNonCopyableTypes)
	IgnoreNonCopyableTypes(true)(ctx)
	assert.Equal(t, true, ctx.IgnoreNonCopyableTypes)

	UseGlobalCache(false)(ctx)
	assert.Equal(t, false, ctx.UseGlobalCache)
	UseGlobalCache(true)(ctx)
	assert.Equal(t, true, ctx.UseGlobalCache)
}

func Test_SetDefaultTagName(t *testing.T) {
	assert.Equal(t, DefaultTagName, defaultTagName)
	// Invalid one
	SetDefaultTagName(" abc")
	assert.Equal(t, DefaultTagName, defaultTagName)
	// Valid one
	SetDefaultTagName("abc")
	assert.Equal(t, "abc", defaultTagName)
	// Restore the tag
	SetDefaultTagName(DefaultTagName)
}
