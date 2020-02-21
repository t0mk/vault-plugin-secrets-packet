package packethost

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"api_token": {
				Type:        framework.TypeString,
				Description: "User API token with read-write permissions",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.operationConfigUpdate,
		},
		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

type packetSecretsEngineConfig struct {
	APIToken string `json:"api_token"`
}

func (b *backend) operationConfigUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	apiToken := ""
	if apiTokenIfc, ok := data.GetOk("api_token"); ok {
		apiToken = apiTokenIfc.(string)
	} else {
		return nil, errors.New("api_token is required")
	}
	entry, err := logical.StorageEntryJSON("config",
		packetSecretsEngineConfig{
			APIToken: apiToken,
		})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	b.resetClient(ctx)
	return nil, nil
}

const pathConfigRootHelpSyn = `Configure the API token which Vault will use to create temporary tokens.`

const pathConfigRootHelpDesc = `Before doing anything, the Packet backend needs credentials that are able to create other API tokens. This endpoint is used to configure those credentials.`
