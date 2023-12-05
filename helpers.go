package main

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/pkg/errors"
)

/*
type secretKey struct {
	sk fr.Element
}
*/

func GenerateFe() fr.Element {
	var fe fr.Element
	// WHEN TO USE fr and when to use fp??
	// https://hackmd.io/@jpw/bn254
	// Curve is defined over Fp (x and y max vals?)
	// Fr is the curve order (max scalar value used to calculate ge)
	fe.SetRandom()
	return fe
}

func GenerateGe(fe fr.Element) bn254.G1Affine {
	var ge bn254.G1Affine
	bigInt := new(big.Int)
	fe.BigInt(bigInt)
	ge.ScalarMultiplicationBase(bigInt)
	return ge
}

func GetSignerIndex(ring []bn254.G1Affine, pk bn254.G1Affine) (int, error) {
	for i, v := range ring {
		if v.Equal(&pk) {
			return i, nil
		}
	}
	return -1, errors.New("Signer not found in ring.")
}

func GetRandomShiftFactor(n int) int {
	randInt, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}

	piRand := big.NewInt(randInt.Int64()) // pi is the index of the signer in the ring
	pi := int(piRand.Int64())             // hardcode to 0 for now
	return pi
}

func customHashG1ToFp(pk bn254.G1Affine) fp.Element {
	// In ring signatures we need to hash public keys (G1 elements)
	// to the curve. But the AVM only has a MapToG1 function,
	// which maps field elements to the curve.
	// hence we need to first map the pk to a field element

	// Hopefully this way of mapping pk to a field element
	// can be done inside the AVM with Sha256 and mod
	// 21888242871839275222246405745257275088696311157297823662689037894645226208583.
	// Ideally we would have been able to hash to G1 from G1 directly...

	var feVersionOfPk fp.Element
	// First hash pk to a field element
	bytesPk := pk.Bytes()
	hash := sha256.Sum256(bytesPk[:])
	hashInt := new(big.Int).SetBytes(hash[:])
	intVal := new(big.Int).Mod(hashInt, fp.Modulus())
	feVersionOfPk.SetBigInt(intVal)
	return feVersionOfPk
}

func GetKeyImage(sk fr.Element, pk bn254.G1Affine) bn254.G1Affine {
	var keyImage bn254.G1Affine

	keyImage = bn254.MapToG1(customHashG1ToFp(pk))
	// The AVM has the MapToG1 function.
	// Is it a trapdoor function though?
	// Does it matter?

	skBigInt := new(big.Int)
	sk.BigInt(skBigInt)

	keyImage.ScalarMultiplication(&keyImage, skBigInt)
	return keyImage
}

func ChallengeInit(msg string, a fr.Element, pk bn254.G1Affine) fr.Element {
	// Initializing ring link value
	// Creates the first ring link
	// msg is the message to be signed
	// a is a random nonce
	// pk is the public key of the signer
	var ringLinkElement fr.Element

	aBigInt := new(big.Int)
	a.BigInt(aBigInt)
	msgBytes := []byte(msg)

	var middle bn254.G1Affine
	middle.ScalarMultiplicationBase(aBigInt)

	last := bn254.MapToG1(customHashG1ToFp(pk))
	last.ScalarMultiplication(&last, aBigInt)

	hash := sha256.Sum256(append(append(msgBytes, middle.Marshal()...), last.Marshal()...))
	hashInt := new(big.Int).SetBytes(hash[:])
	intVal := new(big.Int).Mod(hashInt, fr.Modulus())
	ringLinkElement.SetBigInt(intVal)
	return ringLinkElement
}

func ChallengeMain(msg string, r fr.Element, c fr.Element, pk bn254.G1Affine, keyImage bn254.G1Affine) fr.Element {
	var ringLinkElement fr.Element

	rBigInt := new(big.Int)
	cBigInt := new(big.Int)
	r.BigInt(rBigInt)
	c.BigInt(cBigInt)

	msgBytes := []byte(msg)

	var middle, middleLeft, middleRight bn254.G1Affine
	middleLeft.ScalarMultiplicationBase(rBigInt)
	middleRight.ScalarMultiplication(&pk, cBigInt)
	middle.Add(&middleLeft, &middleRight)

	var last, lastLeft, lastRight bn254.G1Affine
	lastLeftLeft := bn254.MapToG1(customHashG1ToFp(pk))
	lastLeft.ScalarMultiplication(&lastLeftLeft, rBigInt)
	lastRight.ScalarMultiplication(&keyImage, cBigInt)
	last.Add(&lastLeft, &lastRight)

	hash := sha256.Sum256(append(append(msgBytes, middle.Marshal()...), last.Marshal()...))
	hashInt := new(big.Int).SetBytes(hash[:])
	intVal := new(big.Int).Mod(hashInt, fr.Modulus())
	ringLinkElement.SetBigInt(intVal)
	return ringLinkElement
}
