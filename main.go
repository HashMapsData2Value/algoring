package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	fmt.Println("Ring Signatures!")
	// Generate a secret key and public key
	sk := GenerateFe()
	pk := GenerateGe(sk)

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
		ring[i] = GenerateGe(GenerateFe())
	}

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

	a := GenerateFe()

	nonces := make([]fr.Element, n)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = GenerateFe()
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
