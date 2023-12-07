package ring_bn254

import (
	"fmt"
	"testing"
)

func TestFull(t *testing.T) {

	// Generate a secret key and public key
	sk, pk := KeyGen()

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

	if !check {
		t.Fatalf(`Full test failed - signature is not valid`)
	}

}
