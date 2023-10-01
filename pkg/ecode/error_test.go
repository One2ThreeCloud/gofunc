package ecode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSysErrCode(t *testing.T) {
	assert.True(t, checkSysError(1))

	wl := [][]int{
		{10, 15},
		{1, 5},
	}
	SetSysErrorCode(wl, nil)

	assert.True(t, checkSysError(3))
	assert.True(t, checkSysError(15))
	assert.True(t, checkSysError(10))
	assert.False(t, checkSysError(6))

	bl := [][]int{
		{4, 6},
		{1, 2},
	}
	SetSysErrorCode(nil, bl)

	assert.True(t, checkSysError(100))

	SetSysErrorCode(wl, bl)
	assert.False(t, checkSysError(2))
	assert.True(t, checkSysError(3))
}

func TestStatusCode(t *testing.T) {
	wl := [][]int{
		{1, 5},
	}
	bl := [][]int{
		{5},
	}
	SetSysErrorCode(wl, bl)

	code, st, isSys := ToErrorCode(nil)
	assert.Equal(t, "0", code)
	assert.Equal(t, "OK", st)
	assert.Equal(t, false, isSys)

	code, st, isSys = ToErrorCode(Errorf(5, "abc"))
	assert.Equal(t, "5", code)
	assert.Equal(t, "UsrErr", st)
	assert.Equal(t, false, isSys)

	code, st, isSys = ToErrorCode(Errorf(2, "abc"))
	assert.Equal(t, "2", code)
	assert.Equal(t, "SysErr", st)
	assert.Equal(t, true, isSys)
}
