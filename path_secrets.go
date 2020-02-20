package packethost

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathSecrets() *framework.Secret {
	return &framework.Secret{
		Type: "packethost",
		Fields: map[string]*framework.FieldSchema{
			"api_token": {
				Type:        framework.TypeString,
				Description: "Access Key",
			},
		},
		Renew:  b.operationRenew,
		Revoke: b.operationRevoke,
	}
}

type walEntry struct {
	Name  string
	KeyID string
}

const programmaticAPIKey = "programatic_api_key"

func (b *backend) operationRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (b *backend) operationRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	return nil, nil
}
