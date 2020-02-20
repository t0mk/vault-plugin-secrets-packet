package packethost

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathSecrets() *framework.Secret {
	return &framework.Secret{
		Type: "packethost",
		Fields: map[string]*framework.FieldSchema{
			"api_token": {
				Type:        framework.TypeString,
				Description: "API token",
			},
			"api_key_id": {
				Type:        framework.TypeString,
				Description: "ID of API Token Resource",
			},
		},
		Renew:  b.operationRenew,
		Revoke: b.operationRevoke,
	}
}

func (b *backend) operationRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (b *backend) operationRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	idRaw, ok := req.Secret.InternalData["api_key_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing ID of the API token")
	}
	keyID := idRaw.(string)
	client, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	_, err = client.APIKeys.Delete(keyID)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
