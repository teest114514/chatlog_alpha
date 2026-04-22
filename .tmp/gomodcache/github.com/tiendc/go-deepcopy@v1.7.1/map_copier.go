package deepcopy

import (
	"reflect"
)

// mapCopier data structure of copier that copies from a `map`
type mapCopier struct {
	ctx         *Context
	keyCopier   *mapItemCopier
	valueCopier *mapItemCopier
}

// Copy implementation of Copy function for map copier
func (c *mapCopier) Copy(dst, src reflect.Value) (err error) {
	if src.IsNil() {
		dst.Set(reflect.Zero(dst.Type())) // NOTE: Go1.18 has no SetZero
		return nil
	}
	if dst.IsNil() {
		dst.Set(reflect.MakeMapWithSize(dst.Type(), src.Len()))
	}
	iter := src.MapRange()
	for iter.Next() {
		k := iter.Key()
		v := iter.Value()
		if c.keyCopier != nil {
			if k, err = c.keyCopier.Copy(k); err != nil {
				return err
			}
		}
		if c.valueCopier != nil {
			if v, err = c.valueCopier.Copy(v); err != nil {
				return err
			}
		}
		dst.SetMapIndex(k, v)
	}
	return nil
}

func (c *mapCopier) init(dstType, srcType reflect.Type) error {
	srcKeyType, srcValType := srcType.Key(), srcType.Elem()
	dstKeyType, dstValType := dstType.Key(), dstType.Elem()
	buildKeyCopier, buildValCopier := true, true

	// OPTIMIZATION: buildCopier() can handle this nicely
	if simpleKindMask&(1<<srcKeyType.Kind()) > 0 {
		if srcKeyType == dstKeyType {
			// Just keep c.keyCopier = nil
			buildKeyCopier = false
		} else if srcKeyType.ConvertibleTo(dstKeyType) {
			c.keyCopier = &mapItemCopier{dstType: dstKeyType, copier: defaultConvCopier}
			buildKeyCopier = false
		}
	}

	// OPTIMIZATION: buildCopier() can handle this nicely
	if simpleKindMask&(1<<srcValType.Kind()) > 0 {
		if srcValType == dstValType {
			// Just keep c.valueCopier = nil
			buildValCopier = false
		} else if srcValType.ConvertibleTo(dstValType) {
			c.valueCopier = &mapItemCopier{dstType: dstValType, copier: defaultConvCopier}
			buildValCopier = false
		}
	}

	if buildKeyCopier {
		cp, err := buildCopier(c.ctx, dstKeyType, srcKeyType)
		if err != nil {
			return err
		}
		c.keyCopier = &mapItemCopier{dstType: dstKeyType, copier: cp}
	}
	if buildValCopier {
		cp, err := buildCopier(c.ctx, dstValType, srcValType)
		if err != nil {
			return err
		}
		c.valueCopier = &mapItemCopier{dstType: dstValType, copier: cp}
	}
	return nil
}

// mapItemCopier data structure of copier that copies from a map's key or value
type mapItemCopier struct {
	dstType reflect.Type
	copier  copier
}

// Copy implementation of Copy function for map item copier
func (c *mapItemCopier) Copy(src reflect.Value) (reflect.Value, error) {
	dst := reflect.New(c.dstType).Elem()
	err := c.copier.Copy(dst, src)
	return dst, err
}
