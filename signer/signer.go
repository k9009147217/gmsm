package signer

import (
	"crypto"
	"errors"
	"io"
	"math/big"

	"github.com/warm3snow/gmsm/sm2"
)

type sm2CryptoSigner struct {
	key *sm2.PrivateKey
}

func New(key *sm2.PrivateKey) (crypto.Signer, error) {
	if key == nil {
		return nil, errors.New("key must be different from nil.")
	}
	if !key.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("The public key must be on the P256Sm2 curve.")
	}
	if sm2.P256Sm2() != key.Curve {
		return nil, errors.New("Invalid cureve, the sm2 curve must be sm2.P256SM2.")
	}
	if key.D.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("Private key must be different from 0.")
	}

	return &sm2CryptoSigner{key}, nil
}

func (this *sm2CryptoSigner) Public() crypto.PublicKey {
	return &this.key.PublicKey
}

func (this *sm2CryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return this.key.Sign(digest)
}
