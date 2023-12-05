package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// TODO: SHIFT THE SIGNER PK AND EVERYTHING AROUND RANDOMLY!

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

	fmt.Println("Signer index:", pi)

	nonces := make([]fr.Element, n)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = GenerateFe()
	}
	fmt.Println("Generated nonces: ", len(nonces))

	values := make([]fr.Element, n)
	/*

		for i := 0; i < n; i++ {
			j := (i + pi) % n
			fmt.Println("j:", j)
			if j == pi {
				values[pi] = ChallengeInit(msg, nonces[pi], ring[pi])
				continue
			}
			fmt.Println("j-1:", (((j-1)%n)+n)%n)
			values[j] = ChallengeMain(msg, nonces[(((j-1)%n)+n)%n], values[(((j-1)%n)+n)%n], ring[j], keyImage)
		}
	*/

	// Funkar jättebra för pi=0
	///values[1] = ChallengeInit(msg, nonces[0], ring[0])
	///values[0] = ChallengeMain(msg, nonces[1], values[1], ring[1], keyImage)

	// För pi=1
	values[0] = ChallengeInit(msg, nonces[1], ring[1])
	values[1] = ChallengeMain(msg, nonces[0], values[0], ring[0], keyImage)

	//fmt.Println((pi + 1) % n)

	// Calculate r_pi, which ensures privacy.
	// It's not possible to distinguish r_pi from other nonce values
	// or tell that it is connected to the sk

	var rpi, mult fr.Element

	//fmt.Println("pi - 1 mod n = ", (((pi-1)%n)+n)%n)

	/*
		mult.Mul(&sk, &values[(((pi-1)%n)+n)%n])
		rpi.Sub(&nonces[pi], &mult) // r_pi = a - sk * c_pi
	*/
	// Funkar jättebra för pi=0
	//mult.Mul(&sk, &values[0])
	//rpi.Sub(&nonces[0], &mult) // r_pi = a - sk * c_pi

	// För pi=1
	mult.Mul(&sk, &values[1])
	rpi.Sub(&nonces[1], &mult) // r_pi = a - sk * c_pi

	sig := make([]fr.Element, n+1)
	fmt.Println()
	/*
		sig[0] = values[(((pi-1)%n)+n)%n]
		for i := 0; i < n; i++ {
			fmt.Println("i", i, nonces[i])
			sig[i+1] = nonces[i]
		}

		fmt.Println("before:", sig)

		sig[pi+1] = rpi
	*/
	// Funkar jättebra för pi=0
	///sig[0] = values[0]
	///sig[1] = rpi
	///sig[2] = nonces[1]

	// För pi=1
	sig[0] = values[0]
	sig[1] = nonces[0]
	sig[2] = rpi

	// run the Verify function to check that the signature is valid
	fmt.Println()
	fmt.Println()
	fmt.Println("Value:", values)
	fmt.Println()
	fmt.Println("Sig:", sig)
	return sig
}

func Verify(msg string, sig []fr.Element, ring []bn254.G1Affine, keyImage bn254.G1Affine) bool {
	n := len(ring)
	valuesPrime := make([]fr.Element, n)
	/*
		valuesPrime[0] = ChallengeMain(msg, sig[1], sig[0], ring[0], keyImage)
		for i := 0; i < n-1; i++ {
			fmt.Println("i", i)
			valuesPrime[i+1] = ChallengeMain(msg, sig[i+2], valuesPrime[i], ring[i+1], keyImage)
		}
		valuesPrime[0] = ChallengeMain(msg, sig[i], valuesPrime[n-1], ring[i+1], keyImage)
	*/
	valuesPrime[0] = sig[0]
	valuesPrime[1] = ChallengeMain(msg, sig[1], valuesPrime[0], ring[0], keyImage)
	valuesPrime[0] = ChallengeMain(msg, sig[2], valuesPrime[1], ring[1], keyImage)
	fmt.Println()
	fmt.Println()
	fmt.Println("ValuePrime:", len(valuesPrime), valuesPrime)

	// return valuesPrime[len(valuesPrime)-1] == sig[0]
	return valuesPrime[0] == sig[0]
}

func main() {
	fmt.Println("Ring Signatures!")
	// Generate a secret key and public key
	sk, pk := KeyGen()

	fmt.Println("SK and PK generated.")

	// Prepare n public keys for our ring signature
	// These would already be in the contract

	n := 2 // Number of participants

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
	// Signature contains c_pi, r_1, r_2, ..., r_n (hopefully r_pi shuffled somewhere there too)
	// Importantly we do NOT include a! It is a secret nonce
	// Alongside the signature we should also include the key image,
	// a ring of public keys (including our own)
	// and of course the message we are signing!

	check := Verify(msg, sig, ring, keyImage)
	fmt.Println("Signature verified:", check)

}
