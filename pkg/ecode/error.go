package ecode

import (
	"fmt"
	"net/http"
	"strconv"
)

const (
	BadRequestCode  = 400
	ServerErrorCode = 500
)

// APIError describe the error message
type APIError struct {
	// Error Code
	Code int `json:"code"`
	// Error Message
	Message string `json:"message"`
	// Trace ID
	TraceId string `json:"traceID"`
}

type arr2d [][]int

var checkSysError = func(code int) bool {
	if 400 <= code && code < 500 {
		return false
	}
	if 4000 <= code && code < 5000 {
		return false
	}
	return code != 0
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("Code: %d, Message: %s", e.Code, e.Message)
}

func Errorf(code int, format string, args ...interface{}) error {
	return &APIError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// SetSysErrorCode 设置系统错误的错误码，二维数组中每个元素代表一个区间
/* 使用whitelist-blacklist即差集来判断是否系统错误， 示例
sys_err:
  whitelist: # 白名单，在列表的错误码表示系统错误，为空表示所有大于0的错误码
  - [1, 1000] # 区间[1, 1000]
  - [5000] # 错误码为5000
  blacklist: # 黑名单，在列表的错误码表示不是系统错误
  - [0, 1000]
*/
func SetSysErrorCode(whitelist, blacklist arr2d) {
	var inList = func(arr arr2d, code int) bool {
		for i := range arr {
			if len(arr[i]) == 1 && arr[i][0] == code {
				return true
			}
			if len(arr[i]) == 2 && arr[i][0] <= code && arr[i][1] >= code {
				return true
			}
		}
		return false
	}
	var inBlacklist = func(code int) bool {
		if len(blacklist) == 0 {
			return false
		}
		return inList(blacklist, code)
	}
	var inWhitelist = func(code int) bool {
		if len(whitelist) == 0 {
			return true
		}
		return inList(whitelist, code)
	}
	checkSysError = func(code int) bool {
		if code == 0 || inBlacklist(code) {
			return false
		}
		return inWhitelist(code)
	}
}

// ToErrorCode 将error转成错误码，并返回是否是系统错误
func ToErrorCode(err error) (string, string, bool) {
	if err == nil {
		return "0", "OK", false
	}
	apiError, ok := err.(*APIError)
	if !ok {
		return fmt.Sprint(ServerErrorCode), "SysErr", true
	}
	if apiError == nil {
		return "0", "OK", false
	}
	strCode := strconv.Itoa(apiError.Code)
	if checkSysError(apiError.Code) {
		return strCode, "SysErr", true
	}
	return strCode, "UsrErr", false
}

// ToHttpCode 将error转成http错误码(200/400/500)
func ToHttpCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	apiError, ok := err.(*APIError)
	if !ok {
		return http.StatusInternalServerError
	}
	if apiError == nil {
		return http.StatusOK
	}
	if checkSysError(apiError.Code) {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}
