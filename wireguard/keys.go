/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const KeyLength = 32

type Key [KeyLength]byte

func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k *Key) Public() *Key {
	var p [KeyLength]byte
	curve25519.ScalarBaseMult(&p, (*[KeyLength]byte)(k))
	return (*Key)(&p)
}

func NewPrivateKey() (*Key, error) {
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("read random key: %w", err)
	}
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return &key, nil
}

func NewKey(base64Key string) (*Key, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(decoded) != KeyLength {
		return nil, fmt.Errorf("invalid key length %d", len(decoded))
	}

	var key Key
	copy(key[:], decoded)
	return &key, nil
}
