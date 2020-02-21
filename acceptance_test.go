package packethost

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	envVarRunAccTests = "VAULT_PACKET_TEST_API"
	envVarAPIToken    = "PACKET_AUTH_TOKEN"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

type testEnv struct {
	APIToken string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	MostRecentSecret *logical.Secret
}

func TestCreds(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add user role", acceptanceTestEnv.AddUserRole)
	t.Run("read user role", acceptanceTestEnv.ReadUserRole)
	t.Run("read user creds", acceptanceTestEnv.ReadUserCreds)
}

func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     time.Hour,
		},
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		APIToken: os.Getenv(envVarAPIToken),
		Backend:  b,
		Context:  ctx,
		Storage:  &logical.InmemStorage{},
	}, nil
}

func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"api_token": e.APIToken,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadFirstConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Data["api_token"] != e.APIToken {
		t.Fatal("expected api_token of " + e.APIToken)
	}
}

func (e *testEnv) AddUserRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/testuserrole",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"name":       "testrole",
			"type":       "user",
			"read_only":  true,
			"project_id": "",
			"ttl":        20,
			"max_ttl":    60,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *testEnv) ReadUserRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/testuserrole",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
}

func (e *testEnv) ReadUserCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/testuserrole",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	log.Printf("%#v", resp)

	if resp.Data["api_key"] == "" {
		t.Fatal("failed to receive api_key")
	}
	//e.MostRecentSecret = resp.Secret
}
