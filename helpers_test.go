package pedersen

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_bitsToBytes(t *testing.T) {
	bytes0 := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	bits := bytesToBits(bytes0)
	bytes1 := bitsToBytes(bits)
	require.Equal(t, bytes0, bytes1)
	t.Log(string(bytes1))
}