package packethost

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/packethost/packngo"
)

const (
	envVarRunAccTests = "VAULT_PACKET_ACCEPTANCE_TEST_API"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

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

func TestUserCreds(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv("testuserrole")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", acceptanceTestEnv.AddConfig)

	t.Run("add user role", acceptanceTestEnv.AddUserRole)
	t.Run("read user role", acceptanceTestEnv.ReadRole)
	t.Run("read user creds", acceptanceTestEnv.ReadUserCreds)

	t.Run("renew user creds", acceptanceTestEnv.RenewCreds)
	t.Run("revoke user creds", acceptanceTestEnv.RevokeCreds)
}

func TestProjectCreds(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv("testprojectrole")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", acceptanceTestEnv.AddConfig)

	t.Run("create testing project", acceptanceTestEnv.CreatePacketProject)
	t.Run("add project role", acceptanceTestEnv.AddProjectRole)
	t.Run("read project role", acceptanceTestEnv.ReadRole)
	t.Run("read project creds", acceptanceTestEnv.ReadProjectCreds)

	t.Run("renew project creds", acceptanceTestEnv.RenewCreds)
	t.Run("revoke project creds", acceptanceTestEnv.RevokeCreds)
	t.Run("remove testing project", acceptanceTestEnv.RemovePacketProject)
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
