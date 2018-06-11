package main

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io/ioutil"

	driver "github.com/hrntknr/go-bigchaindb-driver"
	"golang.org/x/crypto/ed25519"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	condition, _ := driver.NewEd25519Condition(pub)
	tx, _ := driver.NewTransaction(&driver.TransactionConfig{
		Operation: "CREATE",
		Asset: &map[string]interface{}{
			"data": map[string]string{"test": "test"},
		},
		MetaData: &map[string]string{"test": "test"},
		Key:      pub,
		Outputs: []*driver.OutputConfig{&driver.OutputConfig{
			Condition: condition,
			Amount:    "1",
			PublicKeys: []crypto.PublicKey{
				pub,
			},
		}},
	})
	tx, _ = driver.SignTransaction(tx, priv)

	conn := driver.NewConnection("http://localhost:9984/api/v1/")
	res, _ := conn.SendTransaction(tx)
	body, _ := ioutil.ReadAll(res.Body)
	fmt.Printf("%d : %s", res.StatusCode, body)
}
