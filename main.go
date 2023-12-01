package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

/*
type secretKey struct {
	sk fr.Element
}
*/

func generateFe() fr.Element {
	var fe fr.Element
	// WHEN TO USE fr and when to use fp??
	// https://hackmd.io/@jpw/bn254
	// Curve is defined over Fp (x and y max vals?)
	// Fr is the curve order (max scalar value used to calculate ge)
	fe.SetRandom()
	return fe
}

func generateGe(fe fr.Element) bn254.G1Affine {
	var ge bn254.G1Affine
	bigInt := new(big.Int)
	fe.BigInt(bigInt)
	ge.ScalarMultiplicationBase(bigInt)
	return ge
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

func getKeyImage(sk fr.Element, pk bn254.G1Affine) bn254.G1Affine {
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

func CreateRingLinkInit(msg string, a fr.Element, pk bn254.G1Affine) fr.Element {
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

func CreateRingLinkMain(msg string, r fr.Element, c fr.Element, pk bn254.G1Affine, keyImage bn254.G1Affine) fr.Element {
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

func main() {
	fmt.Println("Ring Signatures!")
	// Generate a secret key and public key
	sk := generateFe()
	pk := generateGe(sk)

	fmt.Println("SK and PK generated.")

	// Prepare n public keys for our ring signature
	// These would already be in the contract
	n := 1000 // Number of other participants

	// Shift the ring
	randInt, err := rand.Int(rand.Reader, big.NewInt(int64(n+1)))
	if err != nil {
		panic(err)
	}

	piRand := big.NewInt(randInt.Int64()) // pi is the index of the signer in the ring
	pi := int(piRand.Int64())             // hardcode to 0 for now
	pi = 0

	ring := make([]bn254.G1Affine, n+1)
	for i := 0; i < len(ring); i++ {
		if i == pi {
			ring[i] = pk
			continue
		}
		ring[i] = generateGe(generateFe())
	}

	fmt.Println(n, "public keys have been initialized in addition to signer's keypair.")

	// Generate the key image
	keyImage := getKeyImage(sk, pk)
	fmt.Println("keyImage generated.")
	fmt.Println()

	// Message
	msg := "Sign this message"

	// In the contract, we would include more info in this string
	// Recipient, reward fee, reward recipient (in case 3rd party is paying for fees)
	// Else? Key Image?
	// The important part is to avoid replay attacks, or for anyone monitoring the mempool
	// to be able to steal the ring signature and use it themselves

	fmt.Println("Message is:", msg)
	fmt.Println()

	a := generateFe()

	nonces := make([]fr.Element, n)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = generateFe()
	}
	fmt.Println("Generated nonces: ", len(nonces))

	values := make([]fr.Element, n+1)
	values[0] = CreateRingLinkInit(msg, a, ring[0]) //starts at index 0 but corresponds to c1
	for i := 0; i < n; i++ {
		values[i+1] = CreateRingLinkMain(msg, nonces[i], values[i], ring[i+1], keyImage)
	}

	fmt.Println("Generated values: ", len(values))

	// Calculate r_pi, which ensures privacy.
	// It's not possible to distinguish r_pi from other nonce values
	// or tell that it is connected to the sk

	var rpi, mult fr.Element

	mult.Mul(&sk, &values[len(values)-1])
	rpi.Sub(&a, &mult)

	sig := make([]fr.Element, n+2)
	sig[0] = values[len(values)-1]
	sig[1] = rpi
	for i := 0; i < n; i++ {
		sig[i+2] = nonces[i]
	}

	// Signature contains c_pi, r_pi, r_1, r_2, ..., r_n
	// Where pi is the signer's index in the ring
	// Importantly we do NOT include a! It is a secret nonce
	// Alongside the signature we should also include the key image,
	// a ring of public keys (including our own)
	// and of course the message we are signing!

	// the signature and ring should have their indices translated randomly but in this example they're indexed at 0

	// Let's verify the signature

	valuesPrime := make([]fr.Element, n+1)
	valuesPrime[0] = CreateRingLinkMain(msg, sig[1], sig[0], ring[0], keyImage)
	for i := 0; i < n; i++ {
		valuesPrime[i+1] = CreateRingLinkMain(msg, sig[i+2], valuesPrime[i], ring[i+1], keyImage)
	}

	fmt.Println("Finally... Let's check and see if they're equal:")
	fmt.Println(sig[0], valuesPrime[len(valuesPrime)-1])

}
