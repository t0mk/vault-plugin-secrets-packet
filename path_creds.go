package packethost

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/packethost/packngo"
)

func (b *backend) pathCredentials() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "The name of the role.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.operationCredsRead,
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

func (b *backend) operationCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}
	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		log.Println("Role", roleName, "doesn't exist")
		// Attempting to read a role that doesn't exist.
		return nil, nil
	}

	tokenCreateRequest := packngo.APIKeyCreateRequest{
		Description: fmt.Sprintf("Vault-%s", roleName),
		ReadOnly:    role.ReadOnly,
		ProjectID:   role.ProjectID,
	}
	client, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	apiKey, _, err := client.APIKeys.Create(&tokenCreateRequest)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(secretType).Response(map[string]interface{}{
		"api_key_token": apiKey.Token,
	}, map[string]interface{}{
		"api_key_id": apiKey.ID,
	})
	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

const pathCredsHelpSyn = `Generate an API token using the given role's configuration.`

const pathCredsHelpDesc = `This path will generate a new API key for Packet API.`
