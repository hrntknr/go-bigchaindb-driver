package main

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ed25519"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	condition, err := NewEd25519Condition(pub)
	if err != nil {
		panic(err)
	}
	tx, err := NewTransaction(&TransactionConfig{
		Operation: "CREATE",
		Asset: &map[string]interface{}{
			"data": map[string]string{"test": "test"},
		},
		MetaData: &map[string]string{"test": "test"},
		Key:      pub,
		Outputs: []*OutputConfig{&OutputConfig{
			Condition: condition,
			Amount:    "1",
			PublicKeys: []crypto.PublicKey{
				pub,
			},
		}},
	})
	if err != nil {
		panic(err)
	}
	tx, err = SignTransaction(tx, priv)

	conn := NewConnection("http://localhost:9984/api/v1/")
	res, _ := conn.SendTransaction(tx)
	body, _ := ioutil.ReadAll(res.Body)
	fmt.Printf("%d : %s", res.StatusCode, body)
}
