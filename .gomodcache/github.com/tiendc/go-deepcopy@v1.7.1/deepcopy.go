package deepcopy

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

const (
	DefaultTagName = "copy"
)

var (
	// defaultTagName default tag name for the program to parse input struct tags
	// to build copier configuration.
	defaultTagName = DefaultTagName
)

// Context copier context
type Context struct {
	// CopyBetweenPtrAndValue allow or not copying between pointers and values (default is `true`)
	CopyBetweenPtrAndValue bool

	// CopyViaCopyingMethod allow or not copying via destination type copying methods (default is `true`)
	CopyViaCopyingMethod bool

	// IgnoreNonCopyableTypes ignore non-copyable types (default is `false`)
	IgnoreNonCopyableTypes bool

	// UseGlobalCache if false not use global cache (default is `true`)
	UseGlobalCache bool

	// copierCacheMap cache to speed up parsing types
	copierCacheMap map[cacheKey]copier
	mu             *sync.RWMutex
	flags          uint8
}

// Option configuration option function provided as extra arguments of copying function
type Option func(ctx *Context)

// CopyBetweenPtrAndValue config function for setting flag `CopyBetweenPtrAndValue`
func CopyBetweenPtrAndValue(flag bool) Option {
	return func(ctx *Context) {
		ctx.CopyBetweenPtrAndValue = flag
	}
}

// CopyBetweenStructFieldAndMethod config function for setting flag `CopyViaCopyingMethod`
// Deprecated: use CopyViaCopyingMethod instead
func CopyBetweenStructFieldAndMethod(flag bool) Option {
	return func(ctx *Context) {
		ctx.CopyViaCopyingMethod = flag
	}
}

// CopyViaCopyingMethod config function for setting flag `CopyViaCopyingMethod`
func CopyViaCopyingMethod(flag bool) Option {
	return func(ctx *Context) {
		ctx.CopyViaCopyingMethod = flag
	}
}

// IgnoreNonCopyableTypes config function for setting flag `IgnoreNonCopyableTypes`
func IgnoreNonCopyableTypes(flag bool) Option {
	return func(ctx *Context) {
		ctx.IgnoreNonCopyableTypes = flag
	}
}

// UseGlobalCache config function for setting flag `UseGlobalCache`
func UseGlobalCache(flag bool) Option {
	return func(ctx *Context) {
		ctx.UseGlobalCache = flag
	}
}

// Copy performs deep copy from `src` to `dst`.
//
// `dst` must be a pointer to the output var, `src` can be either value or pointer.
// In case you want to copy unexported struct fields within `src`, `src` must be a pointer.
func Copy(dst, src any, options ...Option) (err error) {
	if src == nil || dst == nil {
		return fmt.Errorf("%w: source and destination must be non-nil", ErrValueInvalid)
	}
	dstVal, srcVal := reflect.ValueOf(dst), reflect.ValueOf(src)
	dstType, srcType := dstVal.Type(), srcVal.Type()
	if dstType.Kind() != reflect.Pointer {
		return fmt.Errorf("%w: destination must be pointer", ErrTypeInvalid)
	}
	dstVal, dstType = dstVal.Elem(), dstType.Elem()
	if !dstVal.IsValid() {
		return fmt.Errorf("%w: destination must be non-nil", ErrValueInvalid)
	}

	ctx := defaultContext()
	for _, opt := range options {
		opt(ctx)
	}
	ctx.prepare()

	cp, err := buildCopier(ctx, dstType, srcType)
	if err != nil {
		return err
	}
	return cp.Copy(dstVal, srcVal)
}

// ClearCache clears global cache of previously used copiers
func ClearCache() {
	mu.Lock()
	copierCacheMap = map[cacheKey]copier{}
	mu.Unlock()
}

// SetDefaultTagName overwrites the default tag name.
// This function should only be called once at program startup.
func SetDefaultTagName(tag string) {
	tagName := strings.TrimSpace(tag)
	if tagName != "" && tagName == tag {
		defaultTagName = tagName
	}
}
