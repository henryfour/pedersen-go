package pedersen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/require"
	"pedersen-go/babyjub"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPedersen_HashBytes(t *testing.T) {
	point, err := PedersenHashBytes(zokratesName, []byte("abc"))
	assert.Nil(t, err)
	expectedX := babyjub.NewIntFromString("9869277320722751484529016080276887338184240285836102740267608137843906399765")
	expectedY := babyjub.NewIntFromString("19790690237145851554496394080496962351633528315779989340140084430077208474328")
	expectedPoint := babyjub.NewPoint()
	expectedPoint.X = expectedX
	expectedPoint.Y = expectedY
	assert.Equal(t, expectedPoint, point)
}

func TestPedersen_HashBytes2(t *testing.T) {
	point, err := PedersenHashBytes(zokratesName, []byte("abcdefghijklmnopqrstuvwx"))
	assert.Nil(t, err)
	expectedX := babyjub.NewIntFromString("3966548799068703226441887746390766667253943354008248106643296790753369303077")
	expectedY := babyjub.NewIntFromString("12849086395963202120677663823933219043387904870880733726805962981354278512988")
	expectedPoint := babyjub.NewPoint()
	expectedPoint.X = expectedX
	expectedPoint.Y = expectedY
	assert.Equal(t, expectedPoint, point)
}

// test case from zokrates_stdlib
// https://github.com/Zokrates/ZoKrates/blob/master/zokrates_stdlib/tests/tests/hashes/pedersen/512bit.zok
func TestPedersen_Zokrates(t *testing.T) {
	field512 := [512]byte{0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1}
	bytes := bitsToBytes(field512[:])
	// println(hex.EncodeToString(bytes))
	point, err := PedersenHashBytes(zokratesName, bytes)
	require.NoError(t, err)
	// t.Log(point)
	h1 := bytes32ToBits(PackPoint(point))
	h0 := [256]byte{0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1}
	require.Equal(t, h0[:], h1)
}

// generate new test cases for zokrates
func TestPedersen_generate(t *testing.T) {
	eHex := "e24f1d03d1d81e94a099042736d40bd9681b867321443ff58a4568e274dbd83b"
	eBytes, _ := hex.DecodeString(eHex)
	eBits := bytesToBits(eBytes)
	// hPx1 - pedersen hash x1
	point, err := PedersenHashBytes(zokratesName, eBytes, eBytes)
	require.NoError(t, err)
	hPx1Bits := bytes32ToBits(PackPoint(point))
	// hPx32 - pedersen hash x32
	for i := 1; i < 32; i++ {
		prev := PackPoint(point)
		point, err = PedersenHashBytes(zokratesName, prev[:], eBytes)
		require.NoError(t, err)
	}
	hPx32Bits := bytes32ToBits(PackPoint(point))

	hs := sha256.New()
	hs.Write(eBytes)
	// hSx1 - sha256 hash x1
	hs.Write(eBytes)
	hSx1Bits := bytesToBits(hs.Sum(nil))
	for i := 1; i < 32; i++ {
		hs.Write(eBytes)
	}
	hSx32Bits := bytesToBits(hs.Sum(nil))

	fmt.Printf("data bits: %v\n", bitsToFieldArray(eBits))
	fmt.Printf("petersen  x1: %v\n", bitsToFieldArray(hPx1Bits))
	fmt.Printf("petersen x32: %v\n", bitsToFieldArray(hPx32Bits))
	fmt.Printf("sha256    x1: %v\n", bitsToFieldArray(hSx1Bits))
	fmt.Printf("sha256   x32: %v\n", bitsToFieldArray(hSx32Bits))
}

