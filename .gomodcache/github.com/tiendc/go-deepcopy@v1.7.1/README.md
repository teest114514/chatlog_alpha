[![Go Version][gover-img]][gover] [![GoDoc][doc-img]][doc] [![Build Status][ci-img]][ci] [![Coverage Status][cov-img]][cov] [![GoReport][rpt-img]][rpt]

# Fast deep-copy library for Go

## Functionalities

- True deep copy
- Very fast (see [benchmarks](#benchmarks) section)
- Ability to copy almost all Go types (number, string, bool, function, slice, map, struct)
- Ability to copy data between convertible types (for example: copy from `int` to `float`)
- Ability to copy between `pointers` and `values` (for example: copy from `*int` to `int`)
- Ability to copy values via copying methods of destination types
- Ability to copy inherited fields from embedded structs
- Ability to set a destination struct field as `nil` if it is `zero`
- Ability to copy unexported struct fields
- Ability to copy with extra configuration settings

## Installation

```shell
go get github.com/tiendc/go-deepcopy
```

## Usage

- [First example](#first-example)
- [Copy between struct fields with different names](#copy-between-struct-fields-with-different-names)
- [Skip copying struct fields](#skip-copying-struct-fields)
- [Require copying for struct fields](#require-copying-for-struct-fields)
- [Copy struct fields via struct methods](#copy-struct-fields-via-struct-methods)
- [Copy inherited fields from embedded structs](#copy-inherited-fields-from-embedded-structs)
- [Set destination struct fields as `nil` on `zero`](#set-destination-struct-fields-as-nil-on-zero)
- [PostCopy event method for structs](#postcopy-event-method-for-structs)
- [Copy between structs and maps](#copy-between-structs-and-maps)
- [Configure extra copying behaviors](#configure-extra-copying-behaviors)

### First example

  [Playground](https://go.dev/play/p/CrP_rZlkNzm)

```go
    type SS struct {
        B bool
    }
    type S struct {
        I  int
        U  uint
        St string
        V  SS
    }
    type DD struct {
        B bool
    }
    type D struct {
        I int
        U uint
        X string
        V DD
    }
    src := []S{{I: 1, U: 2, St: "3", V: SS{B: true}}, {I: 11, U: 22, St: "33", V: SS{B: false}}}
    var dst []D
    _ = deepcopy.Copy(&dst, &src) // NOTE: it is recommended that you always pass address of `src` to the function
                                  // when copy structs having unexported fields such as `time.Time`.
    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {I:1 U:2 X: V:{B:true}}
    // {I:11 U:22 X: V:{B:false}}
```

### Copy between struct fields with different names

  [Playground](https://go.dev/play/p/WchsGRns0O-)

```go
    type S struct {
        X  int    `copy:"Key"` // 'Key' is used to match the fields
        U  uint
        St string
    }
    type D struct {
        Y int     `copy:"Key"`
        U uint
    }
    src := []S{{X: 1, U: 2, St: "3"}, {X: 11, U: 22, St: "33"}}
    var dst []D
    _ = deepcopy.Copy(&dst, &src)

    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {Y:1 U:2}
    // {Y:11 U:22}
```

### Skip copying struct fields

- By default, matching fields will be copied. If you don't want to copy a field, use tag value `-`.

  [Playground](https://go.dev/play/p/8KPe1Susjp1)

```go
    // S and D both have `I` field, but we don't want to copy it
    // Tag `-` can be used in both struct definitions or just in one
    type S struct {
        I  int
        U  uint
        St string
    }
    type D struct {
        I int `copy:"-"`
        U uint
    }
    src := []S{{I: 1, U: 2, St: "3"}, {I: 11, U: 22, St: "33"}}
    var dst []D
    _ = deepcopy.Copy(&dst, &src)

    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {I:0 U:2}
    // {I:0 U:22}
```

### Require copying for struct fields

  [Playground](https://go.dev/play/p/yDlLsv1wBnf)

```go
    type S struct {
        U  uint
        St string
    }
    type D struct {
        I int `copy:",required"`
        U uint
    }
    src := []S{{U: 2, St: "3"}, {U: 22, St: "33"}}
    var dst []D
    err := deepcopy.Copy(&dst, &src)
    if err != nil {
        fmt.Println("error:", err)
    }

    // Output:
    // error: ErrFieldRequireCopying: struct field 'main.D[I]' requires copying
```

### Copy struct fields via struct methods

- **Note**: If a copying method is defined within a struct, it will have higher priority than matching fields.

  [Playground 1](https://go.dev/play/p/rCawGa5AZh3) /
  [Playground 2](https://go.dev/play/p/vDOhHXyUoyD)

```go
type S struct {
    X  int
    U  uint
    St string
}

type D struct {
    x string
    U uint
}

// Copy method should be in form of `Copy<source-field>` (or key) and return `error` type
func (d *D) CopyX(i int) error {
    d.x = fmt.Sprintf("%d", i)
    return nil
}
```
```go
    src := []S{{X: 1, U: 2, St: "3"}, {X: 11, U: 22, St: "33"}}
    var dst []D
    _ = deepcopy.Copy(&dst, &src)

    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {x:1 U:2}
    // {x:11 U:22}
```

### Copy inherited fields from embedded structs

- This is default behaviour from v1, for lower versions, you can use custom copying function
to achieve the same result.

  [Playground 1](https://go.dev/play/p/Zjj12AMRYXt) /
  [Playground 2](https://go.dev/play/p/cJGLqpPVHXI)

```go
    type SBase struct {
        St string
    }
    // Source struct has an embedded one
    type S struct {
        SBase
        I int
    }
    // but destination struct doesn't
    type D struct {
        I  int
        St string
    }

    src := []S{{I: 1, SBase: SBase{"abc"}}, {I: 11, SBase: SBase{"xyz"}}}
    var dst []D
    _ = deepcopy.Copy(&dst, &src)

    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {I:1 St:abc}
    // {I:11 St:xyz}
```

### Set destination struct fields as `nil` on `zero`

- This is a new feature from v1.5.0. This applies to destination fields of type `pointer`, `interface`,
`slice`, and `map`. When their values are zero after copying, they will be set as `nil`. This is very
convenient when you don't want to send something like a date of `0001-01-01` to client, you want to send
`null` instead.

[Playground 1](https://go.dev/play/p/GO6VExVOLei) /
[Playground 2](https://go.dev/play/p/u0zMHx9UWjA) /
[Playground 3](https://go.dev/play/p/ZpA8DkQ9-7f)

```go
    // Source struct has a time.Time field
    type S struct {
        I    int
        Time time.Time
    }
    // Destination field must be a nullable value such as `*time.Time` or `interface{}`
    type D struct {
        I    int
        Time *time.Time `copy:",nilonzero"` // make sure to use this tag
    }

    src := []S{{I: 1, Time: time.Time{}}, {I: 11, Time: time.Now()}}
    var dst []D
    _ = deepcopy.Copy(&dst, &src)

    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {I:1 Time:<nil>} (source is a zero time value, destination becomes `nil`)
    // {I:11 Time:2025-02-08 12:31:11...} (source is not zero, so be the destination)
```

### `PostCopy` event method for structs

- This is a new feature from v1.5.0. If a destination struct has PostCopy() method, it will be called after copying.

  [Playground](https://go.dev/play/p/fGhGZumaRUD)

```go
    type S struct {
        I  int
        St string
    }
    type D struct {
        I  int
        St string
    }
    // PostCopy must be defined on struct pointer, not value
    func (d *D) PostCopy(src any) error {
        d.I *= 2
        d.St += d.St
        return nil
    }

    src := []S{{I: 1, St: "a"}, {I: 11, St: "aa"}}
    var dst []D
    _ = deepcopy.Copy(&dst, &src)

    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {I:2 St:aa}
    // {I:22 St:aaaa}
```

### Copy between structs and maps

  [Playground](https://go.dev/play/p/eS8RWB8dKmL)

```go
    type D struct {
        I int  `copy:"i"`
        U uint `copy:"u"`
    }

    src := map[string]any{"i": 1, "u": 2, "s": "abc"}
    var dst D
    err := deepcopy.Copy(&dst, &src)
    if err != nil {
        fmt.Println("error:", err)
    }
    fmt.Printf("Result struct: %+v\n", dst)

    src2 := D{I: 11, U: 22}
    dst2 := map[string]any{}
    err = deepcopy.Copy(&dst2, &src2)
    if err != nil {
        fmt.Println("error:", err)
    }
    fmt.Printf("Result map: %+v\n", dst2)

    // Output:
    // Result struct: {I:1 U:2}
    // Result map: map[i:11 u:22]
```

### Configure extra copying behaviors

- Not allow to copy between `ptr` type and `value` (default is `allow`)

  [Playground](https://go.dev/play/p/ZYzGaCNwp2i)

```go
    type S struct {
        I  int
        U  uint
    }
    type D struct {
        I *int
        U uint
    }
    src := []S{{I: 1, U: 2}, {I: 11, U: 22}}
    var dst []D
    err := deepcopy.Copy(&dst, &src, deepcopy.CopyBetweenPtrAndValue(false))
    fmt.Println("error:", err)

    // Output:
    // error: ErrTypeNonCopyable: int -> *int
```

- Ignore ErrTypeNonCopyable, the process will not return that kind of error, but some copyings won't be performed.
  
  [Playground 1](https://go.dev/play/p/YPz49D_oiTY) /
  [Playground 2](https://go.dev/play/p/DNrBJUP-rrM)

```go
    type S struct {
        I []int
        U uint
    }
    type D struct {
        I int
        U uint
    }
    src := []S{{I: []int{1, 2, 3}, U: 2}, {I: []int{1, 2, 3}, U: 22}}
    var dst []D
    // The copy will succeed with ignoring copy of field `I`
    _ = deepcopy.Copy(&dst, &src, deepcopy.IgnoreNonCopyableTypes(true))

    for _, d := range dst {
        fmt.Printf("%+v\n", d)
    }

    // Output:
    // {I:0 U:2}
    // {I:0 U:22}
```

## Benchmarks

### Go-DeepCopy vs ManualCopy vs Other Libs

This benchmark is done on go-deepcopy v1.6.0 using Go 1.24.2

**Copy between 2 different struct types** 
  [Benchmark code](https://gist.github.com/tiendc/0a739fd880b9aac5373de95458d54808)

```
Go-DeepCopy
Go-DeepCopy-10         	 1734240	       682.3 ns/op	     344 B/op	       4 allocs/op
ManualCopy
ManualCopy-10          	32983267	        35.59 ns/op	      80 B/op	       1 allocs/op
JinzhuCopier
JinzhuCopier-10        	  146428	      8138 ns/op	     912 B/op	      40 allocs/op
ulule/deepcopier
ulule/deepcopier-10    	   47137	     25717 ns/op	   50752 B/op	     550 allocs/op
mohae/deepcopy
mohae/deepcopy-10      	  597488	      1828 ns/op	    1208 B/op	      42 allocs/op
barkimedes/deepcopy
barkimedes/deepcopy-10 	  528232	      2206 ns/op	    1464 B/op	      15 allocs/op
mitchellh/copystructure
mitchellh/copystructure-10   123484	      9545 ns/op	    7592 B/op	     191 allocs/op
```

**Copy between the same struct type**
  [Benchmark code](https://gist.github.com/tiendc/502725af830d454382234e8dca22dbdf)

```
Go-DeepCopy
Go-DeepCopy-10         	 2693502	       438.0 ns/op	     248 B/op	       4 allocs/op
ManualCopy
ManualCopy-10          	36577604	        32.17 ns/op	      80 B/op	       1 allocs/op
JinzhuCopier
JinzhuCopier-10        	  187950	      6468 ns/op	     824 B/op	      39 allocs/op
ulule/deepcopier
ulule/deepcopier-10    	   50193	     23170 ns/op	   44768 B/op	     486 allocs/op
mohae/deepcopy
mohae/deepcopy-10      	 1000000	      1083 ns/op	     640 B/op	      26 allocs/op
barkimedes/deepcopy
barkimedes/deepcopy-10 	  886911	      1345 ns/op	     888 B/op	      13 allocs/op
mitchellh/copystructure
mitchellh/copystructure-10   212216	      5559 ns/op	    4552 B/op	     116 allocs/op
```

## Contributing

- You are welcome to make pull requests for new functions and bug fixes.

## License

- [MIT License](LICENSE)

[doc-img]: https://pkg.go.dev/badge/github.com/tiendc/go-deepcopy
[doc]: https://pkg.go.dev/github.com/tiendc/go-deepcopy
[gover-img]: https://img.shields.io/badge/Go-%3E%3D%201.18-blue
[gover]: https://img.shields.io/badge/Go-%3E%3D%201.18-blue
[ci-img]: https://github.com/tiendc/go-deepcopy/actions/workflows/go.yml/badge.svg
[ci]: https://github.com/tiendc/go-deepcopy/actions/workflows/go.yml
[cov-img]: https://codecov.io/gh/tiendc/go-deepcopy/branch/main/graph/badge.svg
[cov]: https://codecov.io/gh/tiendc/go-deepcopy
[rpt-img]: https://goreportcard.com/badge/github.com/tiendc/go-deepcopy
[rpt]: https://goreportcard.com/report/github.com/tiendc/go-deepcopy
