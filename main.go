package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

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

func main() {
	fmt.Println("Ring Signatures!")
	// Generate a secret key and public key
	sk, pk := KeyGen()

	fmt.Println("SK and PK generated.")

	// Prepare n public keys for our ring signature
	// These would already be in the contract

	n := 1000 // Number of participants

	if n < 2 {
		panic("n must be at least 2, signer and someone else")
	}

	pi := GetRandomShiftFactor(n) // signed index

	ring := createRing(n, pi, pk)

	fmt.Println(n, "public keys have been initialized in addition to signer's keypair.")

	// Generate the key image
	keyImage := GetKeyImage(sk, pk)
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

	sig := Sign(msg, sk, ring, keyImage)
	check := Verify(msg, sig, ring, keyImage)
	fmt.Println("Signature verified:", check)

}
