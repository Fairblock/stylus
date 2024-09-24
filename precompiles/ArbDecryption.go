package precompiles

import (
	"bytes"
	"fmt"
	"log"

	enc "github.com/FairBlock/DistributedIBE/encryption"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
)

type ArbDecryption struct {
	Address addr // 0x23
	pk      []byte
}

func (con *ArbDecryption) Get(c ctx, evm mech) ([]byte, error) {
	return con.pk, nil
}

func (con *ArbDecryption) Set(c ctx, evm mech, _pk []byte) (bool, error) {
	suite := bls.NewBLS12381Suite()
	pkPoint := suite.G1().Point()

	// Log input public key bytes
	log.Printf("Set: Public key bytes received: %x\n", _pk)

	// Unmarshal the public key
	err := pkPoint.UnmarshalBinary(_pk)
	if err != nil {
		log.Printf("Set: Error unmarshalling public key: %v\n", err)
		return false, err
	}

	// Store the public key
	con.pk = _pk

	log.Println("Set: Public key successfully set.")
	return true, nil
}

func (con *ArbDecryption) Decrypt(c ctx, evm mech, privateKeyByte []byte, cipherBytes []byte, id string) ([]byte, error) {
	suite := bls.NewBLS12381Suite()
	privateKeyPoint := suite.G2().Point()

	// Log input private key bytes and cipher bytes
	log.Printf("Decrypt: Private key bytes received: %x\n", privateKeyByte)
	log.Printf("Decrypt: Cipher bytes received: %x\n", cipherBytes)

	// Unmarshal the private key
	err := privateKeyPoint.UnmarshalBinary(privateKeyByte)
	if err != nil {
		log.Printf("Decrypt: Error unmarshalling private key: %v\n", err)
		return []byte{1}, err
	}
	log.Printf("Decrypt: Public key: %v\n", con.pk)
	// Unmarshal the stored public key
	pkPoint := suite.G1().Point()
	err = pkPoint.UnmarshalBinary(con.pk)
	if err != nil {
		log.Printf("Decrypt: Error unmarshalling stored public key: %v\n", err)
		return []byte{2}, err
	}

	// Log public and private keys
	log.Printf("Decrypt: Public key: %v\n", pkPoint)
	log.Printf("Decrypt: Private key: %v\n", privateKeyPoint)

	// Hash the identity to G2
	hG2, ok := suite.G2().Point().(kyber.HashablePoint)
	if !ok {
		log.Println("Decrypt: Hashing to G2 failed.")
		return []byte{3}, fmt.Errorf("failed to hash to G2")
	}

	idByte := []byte(id)
	Qid := hG2.Hash(idByte)

	// Log the hashed identity
	log.Printf("Decrypt: Hashed identity (Qid): %v\n", Qid)

	// Perform the pairing operations
	p1 := suite.Pair(pkPoint, Qid)
	p2 := suite.Pair(suite.G1().Point().Base(), privateKeyPoint)

	// Log the pairing results
	log.Printf("Decrypt: Pairing result p1: %v\n", p1)
	log.Printf("Decrypt: Pairing result p2: %v\n", p2)

	// Check if the pairings are equal
	if !p1.Equal(p2) {
		log.Println("Decrypt: Pairing verification failed. p1 does not equal p2.")
		return []byte{4}, nil
	}

	// Decrypt the ciphertext
	var destPlainText bytes.Buffer
	var cipherBuffer bytes.Buffer
	_, err = cipherBuffer.Write(cipherBytes)
	if err != nil {
		log.Printf("Decrypt: Error writing cipher bytes to buffer: %v\n", err)
		return []byte{5}, err
	}

	log.Println("Decrypt: Starting decryption process...")

	// Perform the actual decryption
	err = enc.Decrypt(privateKeyPoint, privateKeyPoint, &destPlainText, &cipherBuffer)
	if err != nil {
		log.Printf("Decrypt: Error during decryption: %v\n", err)
		return []byte{6}, err
	}

	log.Println("Decrypt: Decryption successful.")
	return []byte(destPlainText.String()), nil
}
