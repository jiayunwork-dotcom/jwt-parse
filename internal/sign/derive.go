package sign

import (
	"crypto/sha256"
	"fmt"
)

func DeriveKey(masterSecret, salt, info []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 || keyLen > 64 {
		return nil, fmt.Errorf("derive: invalid key length %d", keyLen)
	}
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	prk := hmacSHA256(salt, masterSecret)

	var prev []byte
	var out []byte
	counter := byte(1)
	for len(out) < keyLen {
		input := append(prev, info...)
		input = append(input, counter)
		block := hmacSHA256(prk, input)
		out = append(out, block...)
		prev = block
		counter++
	}
	return out[:keyLen], nil
}

func hmacSHA256(key, data []byte) []byte {
	blockSize := 64
	if len(key) > blockSize {
		h := sha256.Sum256(key)
		key = h[:]
	}
	if len(key) < blockSize {
		padded := make([]byte, blockSize)
		copy(padded, key)
		key = padded
	}

	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}

	inner := sha256.New()
	inner.Write(ipad)
	inner.Write(data)
	innerHash := inner.Sum(nil)

	outer := sha256.New()
	outer.Write(opad)
	outer.Write(innerHash)
	return outer.Sum(nil)
}

func DeriveKeyForKid(masterSecret []byte, kid string) ([]byte, error) {
	info := []byte("jwt-kid:" + kid)
	return DeriveKey(masterSecret, nil, info, 32)
}

func DeriveKeyPair(masterSecret []byte, purpose string) (signKey, verifyKey []byte, err error) {
	signKey, err = DeriveKey(masterSecret, nil, []byte("sign:"+purpose), 32)
	if err != nil {
		return nil, nil, err
	}
	verifyKey, err = DeriveKey(masterSecret, nil, []byte("verify:"+purpose), 32)
	if err != nil {
		return nil, nil, err
	}
	return signKey, verifyKey, nil
}
