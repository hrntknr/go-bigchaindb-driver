package bigchaindbdriver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

type Connection struct {
	BasePath string
	Paths    map[string]string
}

func NewConnection(path string) *Connection {
	return &Connection{
		BasePath: path,
		Paths: map[string]string{
			"transactions": path + "transactions",
		},
	}
}

func (conn *Connection) SendTransaction(tx *Transaction) (*http.Response, error) {
	return conn.SendTransactionWithContext(tx, context.Background())
}

func (conn *Connection) SendTransactionWithContext(tx *Transaction, ctx context.Context) (*http.Response, error) {
	return conn.req(conn.Paths["transactions"], "POST", ctx, tx)
}

func (conn *Connection) req(endpoint string, method string, ctx context.Context, params interface{}) (*http.Response, error) {
	_json, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(_json)
	req, err := http.NewRequest(method, endpoint, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	client := http.DefaultClient
	return client.Do(req)
}
