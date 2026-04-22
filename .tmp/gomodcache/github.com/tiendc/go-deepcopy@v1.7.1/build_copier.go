package deepcopy

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// cacheKey key data structure of cached copiers
type cacheKey struct {
	dstType reflect.Type
	srcType reflect.Type
	flags   uint8
}

var (
	// copierCacheMap global cache for any parsed type
	copierCacheMap = make(map[cacheKey]copier, 10) //nolint:mnd

	// mu read/write cache lock
	mu sync.RWMutex

	// simpleKindMask mask for checking basic kinds such as int, string, ...
	simpleKindMask = func() uint32 {
		n := uint32(0)
		n |= 1 << reflect.Bool
		n |= 1 << reflect.String
		n |= 1 << reflect.Int
		n |= 1 << reflect.Int8
		n |= 1 << reflect.Int16
		n |= 1 << reflect.Int32
		n |= 1 << reflect.Int64
		n |= 1 << reflect.Uint
		n |= 1 << reflect.Uint8
		n |= 1 << reflect.Uint16
		n |= 1 << reflect.Uint32
		n |= 1 << reflect.Uint64
		n |= 1 << reflect.Float32
		n |= 1 << reflect.Float64
		n |= 1 << reflect.Complex64
		n |= 1 << reflect.Complex128
		n |= 1 << reflect.Uintptr
		n |= 1 << reflect.Func
		return n
	}()
)

const (
	// flagCopyBetweenPtrAndValue indicates copying will be performed between `pointers` and `values`
	flagCopyBetweenPtrAndValue = 1
	// flagCopyViaCopyingMethod indicates copying will be performed via copying methods of destination types
	flagCopyViaCopyingMethod = 2
	// flagIgnoreNonCopyableTypes indicates copying will skip copying non-copyable types without raising errors
	flagIgnoreNonCopyableTypes = 3
)

// prepare prepares context for copiers
func (ctx *Context) prepare() {
	if ctx.UseGlobalCache {
		ctx.copierCacheMap = copierCacheMap
		ctx.mu = &mu
	} else {
		ctx.copierCacheMap = make(map[cacheKey]copier, 5) //nolint:mnd
		ctx.mu = &sync.RWMutex{}
	}

	// Recalculate the flags
	ctx.flags = 0
	if ctx.CopyBetweenPtrAndValue {
		ctx.flags |= 1 << flagCopyBetweenPtrAndValue
	}
	if ctx.CopyViaCopyingMethod {
		ctx.flags |= 1 << flagCopyViaCopyingMethod
	}
	if ctx.IgnoreNonCopyableTypes {
		ctx.flags |= 1 << flagIgnoreNonCopyableTypes
	}
}

// createCacheKey creates and returns  key for caching a copier
func (ctx *Context) createCacheKey(dstType, srcType reflect.Type) *cacheKey {
	return &cacheKey{
		dstType: dstType,
		srcType: srcType,
		flags:   ctx.flags,
	}
}

// defaultContext creates a default context
func defaultContext() *Context {
	return &Context{
		CopyBetweenPtrAndValue: true,
		CopyViaCopyingMethod:   true,
		UseGlobalCache:         true,
	}
}

// buildCopier build copier for handling copy from `srcType` to `dstType`
//
//nolint:gocognit,gocyclo,funlen
func buildCopier(ctx *Context, dstType, srcType reflect.Type) (copier copier, err error) {
	// Finds cached copier, returns it if found
	cacheKey := ctx.createCacheKey(dstType, srcType)
	ctx.mu.RLock()
	cachedCopier, cachedCopierFound := ctx.copierCacheMap[*cacheKey]
	ctx.mu.RUnlock()
	if cachedCopier != nil {
		return cachedCopier, nil
	}

	dstKind, srcKind := dstType.Kind(), srcType.Kind()

	// Trivial case
	if simpleKindMask&(1<<srcKind) > 0 {
		if dstType == srcType {
			copier = defaultDirectCopier
			goto OnComplete
		}
		if srcType.ConvertibleTo(dstType) {
			copier = defaultConvCopier
			goto OnComplete
		}
	}

	if dstKind == reflect.Interface {
		cp := &toIfaceCopier{ctx: ctx}
		copier, err = cp, cp.init(dstType, srcType)
		goto OnComplete
	}
	if srcKind == reflect.Interface {
		cp := &fromIfaceCopier{ctx: ctx}
		copier, err = cp, cp.init(dstType, srcType)
		goto OnComplete
	}

	//nolint:nestif
	if srcKind == reflect.Pointer {
		if dstKind == reflect.Pointer { // ptr -> ptr
			cp := &ptr2PtrCopier{ctx: ctx}
			copier, err = cp, cp.init(dstType, srcType)
			goto OnComplete
		} else { // ptr -> value
			if !ctx.CopyBetweenPtrAndValue {
				goto OnNonCopyable
			}
			cp := &ptr2ValueCopier{ctx: ctx}
			copier, err = cp, cp.init(dstType, srcType)
			goto OnComplete
		}
	} else {
		if dstKind == reflect.Pointer { // value -> ptr
			if !ctx.CopyBetweenPtrAndValue {
				goto OnNonCopyable
			}
			cp := &value2PtrCopier{ctx: ctx}
			copier, err = cp, cp.init(dstType, srcType)
			goto OnComplete
		}
	}

	// Both are not Pointers
	if srcKind == reflect.Slice || srcKind == reflect.Array {
		if dstKind != reflect.Slice && dstKind != reflect.Array {
			goto OnNonCopyable
		}
		cp := &sliceCopier{ctx: ctx}
		copier, err = cp, cp.init(dstType, srcType)
		goto OnComplete
	}

	//nolint:nestif
	if srcKind == reflect.Struct {
		if dstKind == reflect.Struct {
			// Build a special copier for Go standard types such as time.Time, unique.Handle
			copier = buildCopierForStandardStructs(dstType, srcType)
			if copier != nil {
				goto OnComplete
			}

			// At this point, cached copier should not exist in the cache map.
			// If it exists, seems like a circular reference occurs, use an inline copier.
			if cachedCopierFound {
				return &inlineCopier{ctx: ctx, dstType: dstType, srcType: srcType}, nil
			}
			// Circular reference can happen via struct field reference.
			// Put a `nil` copier to the cache to mark that the copier building for the struct types is in-progress.
			setCachedCopier(ctx, cacheKey, nil)

			cp := &structCopier{ctx: ctx}
			copier, err = cp, cp.init(dstType, srcType)
			if err != nil {
				deleteCachedCopier(ctx, cacheKey)
			}
			goto OnComplete
		}
		if dstKind == reflect.Map {
			cp := &structToMapCopier{ctx: ctx}
			copier, err = cp, cp.init(dstType, srcType)
			goto OnComplete
		}
		goto OnNonCopyable
	}

	if srcKind == reflect.Map {
		if dstKind == reflect.Map {
			cp := &mapCopier{ctx: ctx}
			copier, err = cp, cp.init(dstType, srcType)
			goto OnComplete
		}
		if dstKind == reflect.Struct {
			cp := &mapToStructCopier{ctx: ctx}
			copier, err = cp, cp.init(dstType, srcType)
			goto OnComplete
		}
		goto OnNonCopyable
	}

OnComplete:
	if err == nil {
		if copier != nil {
			setCachedCopier(ctx, cacheKey, copier)
			return copier, err
		}
	} else {
		return nil, err
	}

OnNonCopyable:
	if ctx.IgnoreNonCopyableTypes {
		return defaultNopCopier, nil
	}
	return nil, fmt.Errorf("%w: %v -> %v", ErrTypeNonCopyable, srcType, dstType)
}

func buildCopierForStandardStructs(dstType, srcType reflect.Type) copier {
	switch srcType.PkgPath() {
	// When copy time.Time -> time.Time or derived type
	case "time":
		if srcType.Name() == "Time" {
			if dstType == srcType {
				return defaultDirectCopier
			}
			if dstType.ConvertibleTo(srcType) {
				return defaultConvCopier
			}
		}
	// When copy unique.Handle[T] -> unique.Handle[T] or derived type
	case "unique":
		if strings.HasPrefix(srcType.Name(), "Handle[") {
			if dstType == srcType {
				return defaultDirectCopier
			}
			if dstType.ConvertibleTo(srcType) {
				return defaultConvCopier
			}
		}
	}
	return nil
}

func setCachedCopier(ctx *Context, cacheKey *cacheKey, cp copier) {
	ctx.mu.Lock()
	ctx.copierCacheMap[*cacheKey] = cp
	ctx.mu.Unlock()
}

func deleteCachedCopier(ctx *Context, cacheKey *cacheKey) {
	ctx.mu.Lock()
	delete(ctx.copierCacheMap, *cacheKey)
	ctx.mu.Unlock()
}
