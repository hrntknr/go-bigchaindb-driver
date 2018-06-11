package bigchaindbdriver

import (
	"crypto"
	"testing"

	"github.com/hrntknr/go-bigchaindb-driver/base58"
	"golang.org/x/crypto/ed25519"
)

var key = ed25519.NewKeyFromSeed([]byte{0x79, 0x09, 0x70, 0x29, 0x9d, 0xf3, 0x1e, 0x74, 0x6f, 0x30, 0x7b, 0x48, 0x5d, 0x0e, 0xaa, 0x78, 0x2d, 0x46, 0x1c, 0xc2, 0x50, 0x41, 0x06, 0x37, 0xe7, 0x9e, 0x6c, 0x66, 0x64, 0xde, 0x4c, 0xe8})

func TestNewEd25519Condition(t *testing.T) {
	addr, err := base58.Encode(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Error(err)
	}
	condition, err := NewEd25519Condition(key.Public())
	if err != nil {
		t.Error(err)
	}
	if condition.URI != "ni:///sha-256;-7FGhx37yU7yeJWKn0kpLdR4YxhJWmwuP1Db5lX1fFg?fpt=ed25519-sha-256&cost=131072" {
		t.Error("invalid uri")
	}
	if condition.Details.(Ed25519ConditionDetails).Type != "ed25519-sha-256" {
		t.Error("invalid type")
	}
	if condition.Details.(Ed25519ConditionDetails).PublicKey != string(addr) {
		t.Error("invalid address")
	}
}

func TestNewTransaction(t *testing.T) {
	condition, err := NewEd25519Condition(key.Public())
	if err != nil {
		t.Error(err)
	}
	tx, err := NewTransaction(
		&TransactionConfig{
			Key:       key.Public(),
			Operation: "CREATE",
			Asset:     map[string]string{"test": "test"},
			MetaData:  map[string]string{"test": "test"},
			Outputs: []*OutputConfig{
				&OutputConfig{
					Condition:  condition,
					Amount:     "1",
					PublicKeys: []crypto.PublicKey{key.Public()},
				},
			},
		},
	)
	if err != nil {
		t.Error(err)
	}
	if tx.ID != nil {
		t.Error("txID should not null")
	}
}

func TestSignTransaction(t *testing.T) {
	condition, err := NewEd25519Condition(key.Public())
	if err != nil {
		t.Error(err)
	}
	addr, err := base58.Encode(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Error(err)
	}
	tx := &Transaction{
		ID:        nil,
		Operation: "CREATE",
		Outputs: []*Output{&Output{
			Condition:  condition,
			Amount:     "1",
			PublicKeys: []string{string(addr)},
		}},
		Inputs: []*Input{&Input{
			Fulfillment:  nil,
			Fulfills:     nil,
			OwnersBefore: []string{string(addr)},
		}},
		MetaData: map[string]string{"test": "test"},
		Asset:    map[string]map[string]string{"data": {"test": "test"}},
		Version:  "2.0",
	}
	signedTx, err := SignTransaction(tx, key)
	if err != nil {
		t.Error(err)
	}
	if signedTx.ID != "e96aa2f9b9a844823da3a2e43f971e03365af7ed13081088659bddbecb52e6b6" {
		t.Error("invalid txID")
	}
}
