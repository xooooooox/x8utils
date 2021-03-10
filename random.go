package x8utils

import (
	"math/rand"
)

// RandomString 随机字符串
func RandomString(length int, bt ...byte) (result []byte) {
	if length <= 0 {
		return
	}
	btl := len(bt)
	if btl == 0 {
		bt = []byte{48, 49, 50, 51, 52, 53, 54, 55, 56, 57}
		btl = len(bt)
	}
	result = []byte{}
	var tmp byte
	for i := 0; i < length; i++ {
		tmp = bt[rand.Intn(btl)]
		result = append(result, tmp)
	}
	return
}
