package precompiles

import (
	"bytes"

	enc "github.com/FairBlock/DistributedIBE/encryption"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
)

type ArbDecryption struct {
	Address addr // 0x23
    pk []byte
}


func (con *ArbDecryption) Get(c ctx, evm mech) ([]byte,error){
	return con.pk,nil;
}
func (con *ArbDecryption) Set(c ctx, evm mech, _pk []byte) (bool,error) {
	suite := bls.NewBLS12381Suite()
	pkPoint := suite.G1().Point()
	err := pkPoint.UnmarshalBinary(_pk)
	if err != nil {
		return false,err;
	}
	con.pk = _pk;
	return true,nil;
}

func (con *ArbDecryption) Decrypt(c ctx, evm mech, privateKeyByte []byte, cipherBytes []byte, id string) ([]byte, error) {
	suite := bls.NewBLS12381Suite()
	privateKeyPoint := suite.G2().Point()
	err := privateKeyPoint.UnmarshalBinary(privateKeyByte)
	if err != nil {
		return []byte{1},err
	}
	pkPoint := suite.G1().Point()
	_ = pkPoint.UnmarshalBinary(con.pk)
	hG2, ok := suite.G2().Point().(kyber.HashablePoint)
	if !ok {
		return []byte{2},err
	}
	idByte := []byte(id)
	Qid := hG2.Hash(idByte)
	p1 := suite.Pair(pkPoint,Qid)
	p2 := suite.Pair(suite.G1().Point().Base(), privateKeyPoint)
	if !p1.Equal(p2){
		return []byte{3},nil
	}
	var destPlainText bytes.Buffer
	var cipherBuffer bytes.Buffer
	_, err = cipherBuffer.Write(cipherBytes)
	if err != nil {
		return []byte{4},err
	}
	err = enc.Decrypt(privateKeyPoint, privateKeyPoint, &destPlainText, &cipherBuffer)
	if err != nil {
		return []byte{5},err
	}
	return []byte(destPlainText.String()),nil
}