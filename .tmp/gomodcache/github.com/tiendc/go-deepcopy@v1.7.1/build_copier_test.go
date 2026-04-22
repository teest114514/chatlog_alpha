package deepcopy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Ctx_prepare(t *testing.T) {
	ctx := defaultContext()

	CopyBetweenPtrAndValue(false)(ctx)
	CopyBetweenStructFieldAndMethod(false)(ctx)
	IgnoreNonCopyableTypes(false)(ctx)
	ctx.prepare()
	assert.Equal(t, uint8(0), ctx.flags)

	UseGlobalCache(false)(ctx)
	ctx.prepare()
	assert.True(t, &copierCacheMap != &ctx.copierCacheMap)
	assert.True(t, &mu != ctx.mu)

	UseGlobalCache(true)(ctx)
	ctx.prepare()
	ctx.copierCacheMap[cacheKey{flags: 1}] = nil
	copierCacheMap[cacheKey{flags: 2}] = nil
	assert.Equal(t, copierCacheMap, ctx.copierCacheMap)
	assert.True(t, &mu == ctx.mu)
}
