package utils

import "unsafe"

func Str2BytesUnsafe(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func Bytes2StrUnsafe(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
