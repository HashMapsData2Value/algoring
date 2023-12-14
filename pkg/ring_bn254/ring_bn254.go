package ring_bn254

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

func HashPointToPoint(pk bn254.G1Affine) bn254.G1Affine {
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
	hash := sha256.Sum256(append(pk.X.Marshal(), pk.Y.Marshal()...))
	hashInt := new(big.Int).SetBytes(hash[:])
	intVal := new(big.Int).Mod(hashInt, fp.Modulus())
	feVersionOfPk.SetBigInt(intVal)
	return bn254.MapToG1(feVersionOfPk)
}

func GetKeyImage(sk fr.Element, pk bn254.G1Affine) bn254.G1Affine {
	var keyImage bn254.G1Affine

	keyImage = HashPointToPoint(pk)
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

	last := HashPointToPoint(pk)
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
	lastLeftLeft := HashPointToPoint(pk)
	lastLeft.ScalarMultiplication(&lastLeftLeft, rBigInt)
	lastRight.ScalarMultiplication(&keyImage, cBigInt)
	last.Add(&lastLeft, &lastRight)

	hash := sha256.Sum256(append(append(msgBytes, middle.Marshal()...), last.Marshal()...))
	hashInt := new(big.Int).SetBytes(hash[:])
	intVal := new(big.Int).Mod(hashInt, fr.Modulus())
	ringLinkElement.SetBigInt(intVal)
	return ringLinkElement
}

func KeyGen() (fr.Element, bn254.G1Affine) {
	sk := GenerateFe()
	pk := GenerateGe(sk)
	return sk, pk
}

func createRing(n int, signerIdx int, signerPk bn254.G1Affine) []bn254.G1Affine {
	ring := make([]bn254.G1Affine, n)
	for i := 0; i < len(ring); i++ {
		if i == signerIdx {
			ring[i] = signerPk
			continue
		}
		ring[i] = GenerateGe(GenerateFe())
	}
	return ring
}

func Sign(msg string, sk fr.Element, ring []bn254.G1Affine, keyImage bn254.G1Affine) []fr.Element {
	pi, err := GetSignerIndex(ring, GenerateGe(sk))
	if err != nil {
		panic(err)
	}

	n := len(ring)

	nonces := make([]fr.Element, n)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = GenerateFe()
	}

	values := make([]fr.Element, n)

	for i := 0; i < n; i++ {
		j := (i + pi) % n
		k := (i + pi + 1) % n

		if j == pi {
			values[k] = ChallengeInit(msg, nonces[j], ring[j])
			continue
		}

		values[k] = ChallengeMain(msg, nonces[j], values[j], ring[j], keyImage)
	}

	// Calculate r_pi, which ensures privacy.
	// It's not possible to distinguish r_pi from other nonce values
	// or tell that it is connected to the sk

	var rpi, mult fr.Element

	mult.Mul(&sk, &values[pi])
	rpi.Sub(&nonces[pi], &mult) // r_pi = a - sk * c_pi
	nonces[pi] = rpi

	sig := make([]fr.Element, n+1)

	sig[0] = values[0]
	for i := 0; i < n; i++ {
		sig[i+1] = nonces[i]
	}

	// run the Verify function to check that the signature is valid
	if !Verify(msg, sig, ring, keyImage) {
		panic("Signature is invalid!")
	}

	return sig
}

func Verify(msg string, sig []fr.Element, ring []bn254.G1Affine, keyImage bn254.G1Affine) bool {
	n := len(ring)
	valuesPrime := make([]fr.Element, n)

	valuesPrime[0] = sig[0]
	for i := 0; i < n-1; i++ {
		valuesPrime[i+1] = ChallengeMain(msg, sig[i+1], valuesPrime[i], ring[i], keyImage)
	}
	valuesPrime[0] = ChallengeMain(msg, sig[n], valuesPrime[n-1], ring[n-1], keyImage)

	return valuesPrime[0] == sig[0]
}
