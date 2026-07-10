package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/go-jose/go-jose/v4"
)

const KID = "mini-oidc-1"

type KeySet struct {
	PrivateKey *ecdsa.PrivateKey
	JWKSet     jose.JSONWebKeySet
	Signer     jose.Signer
}

func Generate() (*KeySet, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwk := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     KID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), KID),
	)
	if err != nil {
		return nil, err
	}

	return &KeySet{
		PrivateKey: priv,
		JWKSet:     jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}},
		Signer:     signer,
	}, nil
}
