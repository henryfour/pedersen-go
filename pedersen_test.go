package pedersen

import (
	"pedersen-go/babyjub"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPedersen_HashBytes(t *testing.T) {
	point, err := PedersenHashBytes("test", []byte("abc"))
	assert.Nil(t, err)
	expectedX := babyjub.NewIntFromString("9869277320722751484529016080276887338184240285836102740267608137843906399765")
	expectedY := babyjub.NewIntFromString("19790690237145851554496394080496962351633528315779989340140084430077208474328")
	expectedPoint := babyjub.NewPoint()
	expectedPoint.X = expectedX
	expectedPoint.Y = expectedY
	assert.Equal(t, expectedPoint, point)
}

func TestPedersen_HashBytes2(t *testing.T) {
	point, err := PedersenHashBytes("test", []byte("abcdefghijklmnopqrstuvwx"))
	assert.Nil(t, err)
	expectedX := babyjub.NewIntFromString("3966548799068703226441887746390766667253943354008248106643296790753369303077")
	expectedY := babyjub.NewIntFromString("12849086395963202120677663823933219043387904870880733726805962981354278512988")
	expectedPoint := babyjub.NewPoint()
	expectedPoint.X = expectedX
	expectedPoint.Y = expectedY
	assert.Equal(t, expectedPoint, point)
}
