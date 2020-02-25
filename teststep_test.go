package packet

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/packethost/packngo"
)

func (e *testEnv) AddBadConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"api_token": "hopefullythisisnotavalidtoken",
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

func (e *testEnv) ReadUserCredsBadConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("creds/%s", e.RoleName),
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if !resp.IsError() {
		t.Fatal("expected an error response")
	}
	errStr := resp.Data["error"].(string)
	if !strings.Contains(errStr, "Invalid authentication token") {
		t.Fatalf("Packet API should return error reporting a wrong auth token. Err was %#v", errStr)
	}

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

func (e *testEnv) ReadRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", e.RoleName),
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

func (e *testEnv) RenewCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   e.Storage,
		Secret:    e.MostRecentSecret,
		Data: map[string]interface{}{
			"lease_id": "foo",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Secret != e.MostRecentSecret {
		t.Fatalf("expected %+v but got %+v", e.MostRecentSecret, resp.Secret)
	}
}

func (e *testEnv) RevokeCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   e.Storage,
		Secret:    e.MostRecentSecret,
		Data: map[string]interface{}{
			"lease_id": "foo",
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

func (e *testEnv) CreatePacketProject(t *testing.T) {
	pcr := packngo.ProjectCreateRequest{Name: "Vault-testing-project"}
	c := packngo.NewClientWithAuth("Hashicorp Vault Test", e.APIToken, nil)
	p, _, err := c.Projects.Create(&pcr)
	if err != nil {
		t.Fatal(err)
	}
	e.TestProjectID = p.ID
}

func (e *testEnv) RemovePacketProject(t *testing.T) {
	c := packngo.NewClientWithAuth("Hashicorp Vault Test", e.APIToken, nil)
	_, err := c.Projects.Delete(e.TestProjectID)
	if err != nil {
		t.Fatal(err)
	}
}

func GetPacketProjectAPIKey(projectID, keyID string) (*packngo.APIKey, error) {
	c, err := packngo.NewClient()
	if err != nil {
		return nil, err
	}
	return c.APIKeys.ProjectGet(projectID, keyID, nil)
}

func (e *testEnv) AddProjectRole(t *testing.T) {
	if e.TestProjectID == "" {
		t.Fatal("You must create a testing project before testing project role")
	}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", e.RoleName),
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"type":       "project",
			"project_id": e.TestProjectID,
			"read_only":  true,
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

func (e *testEnv) ReadProjectCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("creds/%s", e.RoleName),
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}

	if resp.Data["api_key_token"] == "" {
		t.Fatal("failed to receive api_key_token")
	}
	if resp.Secret.InternalData["api_key_id"] == "" {
		t.Fatal("failed to receive api_key_id")
	}
	keyID := resp.Secret.InternalData["api_key_id"].(string)

	apiKey, err := GetPacketProjectAPIKey(e.TestProjectID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if !apiKey.ReadOnly {
		t.Fatal("Created API key should be read-only")
	}
	expectedDesc := fmt.Sprintf("Vault-%s", e.RoleName)
	if apiKey.Description != expectedDesc {
		t.Fatal("Created API key should be read-only")
	}
	if apiKey.Token != resp.Data["api_key_token"] {
		t.Fatal("mismatch in api tokens")
	}

	e.MostRecentSecret = resp.Secret
}

func (e *testEnv) AddUserRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", e.RoleName),
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"type":      "user",
			"read_only": true,
			"ttl":       20,
			"max_ttl":   60,
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

func GetPacketUserAPIKey(id string) (*packngo.APIKey, error) {
	c, err := packngo.NewClient()
	if err != nil {
		return nil, err
	}
	return c.APIKeys.UserGet(id, nil)
}

func (e *testEnv) ReadUserCreds(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("creds/%s", e.RoleName),
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}

	if resp.Data["api_key_token"] == "" {
		t.Fatal("failed to receive api_key_token")
	}
	if resp.Secret.InternalData["api_key_id"] == "" {
		t.Fatal("failed to receive api_key_id")
	}
	keyID := resp.Secret.InternalData["api_key_id"].(string)

	apiKey, err := GetPacketUserAPIKey(keyID)
	if err != nil {
		t.Fatal(err)
	}
	if !apiKey.ReadOnly {
		t.Fatal("Created API key should be read-only")
	}
	expectedDesc := fmt.Sprintf("Vault-%s", e.RoleName)
	if apiKey.Description != expectedDesc {
		t.Fatal("Created API key should be read-only")
	}
	if apiKey.Token != resp.Data["api_key_token"] {
		t.Fatal("mismatch in api tokens")
	}

	e.MostRecentSecret = resp.Secret
}
