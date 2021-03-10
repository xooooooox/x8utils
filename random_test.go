package x8utils

import (
	"fmt"
	"testing"
)

func TestRandomString(t *testing.T) {
	result := RandomString(10)
	fmt.Println(string(result))
}

func BenchmarkRandomString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		result := RandomString(3)
		fmt.Println(string(result))
	}
}
