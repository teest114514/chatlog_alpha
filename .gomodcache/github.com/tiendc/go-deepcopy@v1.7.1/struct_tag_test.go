package deepcopy

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseTag(t *testing.T) {
	type Item struct {
		Col1 bool
		Col2 int    `copy:"col2,required"`
		Col3 string `copy:"-"`
		Col4 string `copy:""`
		Col5 string `copy:",unsupported"`
	}
	structType := reflect.TypeOf(Item{})

	col1, _ := structType.FieldByName("Col1")
	detail1 := &fieldDetail{field: &col1}
	parseTag(detail1)
	assert.True(t, detail1.key == "Col1" && !detail1.ignored)

	col2, _ := structType.FieldByName("Col2")
	detail2 := &fieldDetail{field: &col2}
	parseTag(detail2)
	assert.True(t, detail2.key == "col2" && detail2.required)

	col3, _ := structType.FieldByName("Col3")
	detail3 := &fieldDetail{field: &col3}
	parseTag(detail3)
	assert.True(t, detail3.key == "Col3" && detail3.ignored)

	col4, _ := structType.FieldByName("Col4")
	detail4 := &fieldDetail{field: &col4}
	parseTag(detail4)
	assert.True(t, detail4.key == "Col4" && !detail4.required)

	col5, _ := structType.FieldByName("Col5")
	detail5 := &fieldDetail{field: &col5}
	parseTag(detail5)
	assert.True(t, detail5.key == "Col5" && !detail5.required)
}
