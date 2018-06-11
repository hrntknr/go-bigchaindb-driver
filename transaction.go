package bigchaindbdriver

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	// "github.com/go-interledger/cryptoconditions"
	"github.com/hrntknr/cryptoconditions"
	"github.com/hrntknr/go-bigchaindb-driver/base58"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

func NewTransaction(config *TransactionConfig) (*Transaction, error) {
	addr, err := base58.Encode(config.Key.(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	tx := &Transaction{}
	tx.Version = "2.0"
	tx.Operation = config.Operation
	tx.Asset = config.Asset
	tx.MetaData = config.MetaData
	tx.Outputs, err = createOutput(config.Outputs)
	if err != nil {
		return nil, err
	}
	if config.Operation == "CREATE" {
		tx.Inputs = []*Input{&Input{
			Fulfills:     nil,
			Fulfillment:  nil,
			OwnersBefore: []string{string(addr)},
		}}
	}
	return tx, nil
}

func createOutput(configs []*OutputConfig) ([]*Output, error) {
	if len(configs) == 0 {
		return make([]*Output, 0), nil
	}
	outputs := []*Output{}
	for _, config := range configs {
		output := Output{
			Amount:     config.Amount,
			PublicKeys: make([]string, 0),
			Condition:  config.Condition,
		}
		for _, publicKey := range config.PublicKeys {
			addr, err := base58.Encode(publicKey.(ed25519.PublicKey))
			if err != nil {
				return nil, err
			}
			output.PublicKeys = append(output.PublicKeys, string(addr))
		}
		outputs = append(outputs, &output)
	}
	return outputs, nil
}

type TransactionConfig struct {
	Operation string
	Asset     interface{}
	MetaData  interface{}
	Signers   []string
	Outputs   []*OutputConfig
	Key       crypto.PublicKey
}

type OutputConfig struct {
	Condition  *Condition
	Amount     string
	PublicKeys []crypto.PublicKey
}

type Output struct {
	Amount     string     `json:"amount"`
	Condition  *Condition `json:"condition"`
	PublicKeys []string   `json:"public_keys"`
}

type Condition struct {
	Details interface{} `json:"details"`
	URI     string      `json:"uri"`
}

type Ed25519ConditionDetails struct {
	PublicKey string `json:"public_key"`
	Type      string `json:"type"`
}

type Transaction struct {
	Asset     interface{} `json:"asset"`
	ID        interface{} `json:"id"`
	Inputs    []*Input    `json:"inputs"`
	MetaData  interface{} `json:"metadata"`
	Operation string      `json:"operation"`
	Outputs   []*Output   `json:"outputs"`
	Version   string      `json:"version"`
}

type Input struct {
	Fulfillment  interface{} `json:"fulfillment"`
	Fulfills     interface{} `json:"fulfills"`
	OwnersBefore []string    `json:"owners_before"`
}

type Fulfills struct {
	OutputIndex   uint   `json:"output_index"`
	TransactionID string `json:"transaction_id"`
}

func SignTransaction(tx *Transaction, priv ed25519.PrivateKey) (*Transaction, error) {
	bytesToSign, err := hash_of_aa(tx)
	if err != nil {
		return nil, err
	}
	for _, input := range tx.Inputs {
		sign := ed25519.Sign(priv, bytesToSign)
		res, err := cryptoconditions.NewEd25519Sha256(priv.Public().(ed25519.PublicKey), sign)
		if err != nil {
			return nil, err
		}
		fulfill, err := res.Encode()
		if err != nil {
			return nil, err
		}
		encodedFulfill := base64.StdEncoding.EncodeToString(fulfill)
		// for base64url
		encodedFulfill = strings.Replace(encodedFulfill, "+", "-", -1)
		encodedFulfill = strings.Replace(encodedFulfill, "/", "_", -1)
		input.Fulfillment = encodedFulfill
	}
	hash, err := hash_of_aa(tx)
	if err != nil {
		return nil, err
	}
	tx.ID = fmt.Sprintf("%x", hash)
	return tx, nil
}

func hash_of_aa(obj interface{}) ([]byte, error) {
	_json, err := jsonMarshal(obj)
	if err != nil {
		return []byte{}, err
	}
	hash := sha3.Sum256(_json)
	return hash[:], nil
}

func NewEd25519Condition(pubKey crypto.PublicKey) (*Condition, error) {
	ff, err := cryptoconditions.NewEd25519Sha256(pubKey.(ed25519.PublicKey), nil)
	if err != nil {
		return nil, err
	}
	uri := ff.Condition().URI()
	splitURI := strings.Split(uri, "?")
	query, err := url.ParseQuery(splitURI[1])
	if err != nil {
		return nil, err
	}
	uri = fmt.Sprintf("%s?fpt=%s&cost=%s", splitURI[0], query.Get("fpt"), query.Get("cost"))
	addr, err := base58.Encode(pubKey.(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &Condition{
		Details: Ed25519ConditionDetails{
			Type:      "ed25519-sha-256",
			PublicKey: string(addr),
		},
		URI: uri,
	}, nil
}

func jsonMarshal(src interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(src)
	if err != nil {
		return nil, err
	}
	res, err := buf.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return res[:len(res)-1], nil
}
