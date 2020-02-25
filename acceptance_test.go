package packet

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	envVarRunAccTests = "VAULT_PACKET_ACCEPTANCE_TEST_API"
	envVarAPIToken    = "PACKET_AUTH_TOKEN"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

type testEnv struct {
	APIToken string
	RoleName string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	MostRecentSecret *logical.Secret

	TestProjectID string
}

func newAcceptanceTestEnv(roleName string) (*testEnv, error) {
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
		RoleName: roleName,
		APIToken: os.Getenv(envVarAPIToken),
		Backend:  b,
		Context:  ctx,
		Storage:  &logical.InmemStorage{},
	}, nil
}

func TestUserBadConfig(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv("testuserrolebadconf")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add bad config", acceptanceTestEnv.AddBadConfig)

	t.Run("add user role", acceptanceTestEnv.AddUserRole)
	t.Run("read user role", acceptanceTestEnv.ReadRole)
	t.Run("check error trying to get user creds with wrong token",
		acceptanceTestEnv.ReadUserCredsBadConfig)

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
