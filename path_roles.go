package packet

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	TypeUser    = "user"
	TypeProject = "project"
)

func readRole(ctx context.Context, s logical.Storage, roleName string) (*roleEntry, error) {
	role, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	result := &roleEntry{}
	if err := role.DecodeJSON(result); err != nil {
		return nil, err
	}
	return result, nil
}

type roleEntry struct {
	Type      string        `json:"type"`
	ReadOnly  bool          `json:"read_only"`
	ProjectID string        `json:"project_id"`
	TTL       time.Duration `json:"ttl"`
	MaxTTL    time.Duration `json:"max_ttl"`
}

func (b *backend) pathListRoles() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.operationRolesList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func (b *backend) operationRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "The name of the role.",
			},
			"type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf("%s or %s", TypeUser, TypeProject),
				Required:    true,
			},
			"read_only": {
				Type:        framework.TypeBool,
				Description: "should API tokens be read only",
				Default:     true,
			},
			"project_id": {
				Type:        framework.TypeString,
				Description: "project_id for a project key",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fallback to the system/mount defaults.`,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
		},
		ExistenceCheck: b.operationRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.operationRoleCreate,
			logical.UpdateOperation: b.operationRoleCreate,
			logical.ReadOperation:   b.operationRoleRead,
			logical.DeleteOperation: b.operationRoleDelete,
		},
		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) operationRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := readRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func IsValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

func (b *backend) operationRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return nil, errors.New("name is required")
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil && req.Operation == logical.UpdateOperation {
		return nil, fmt.Errorf("no role found to update for %s", roleName)
	} else if role == nil {
		role = &roleEntry{}
	}

	if raw, ok := data.GetOk("type"); ok {
		role.Type = raw.(string)
		if (role.Type != TypeUser) && (role.Type != TypeProject) {
			return nil, fmt.Errorf("role type should be either %s or %s, was %s", TypeUser, TypeProject, role.Type)
		}
	}

	if raw, ok := data.GetOk("read_only"); ok {
		role.ReadOnly = raw.(bool)
	}

	if raw, ok := data.GetOk("project_id"); ok {
		role.ProjectID = raw.(string)
		switch role.Type {
		case TypeUser:
			if role.ProjectID != "" {
				return nil, fmt.Errorf("For user API key role, project_id must be left empty")
			}
		case TypeProject:
			if !IsValidUUID(role.ProjectID) {
				return nil, fmt.Errorf("For project API key role, you must supply valid Packet API project ID")
			}
		}
	}

	if raw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(raw.(int)) * time.Second
	}

	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return nil, errors.New("ttl exceeds max_ttl")
	}

	entry, err := logical.StorageEntryJSON("role/"+roleName, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) operationRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return nil, errors.New("name is required")
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"type":       role.Type,
			"read_only":  role.ReadOnly,
			"project_id": role.ProjectID,
			"ttl":        role.TTL / time.Second,
			"max_ttl":    role.MaxTTL / time.Second,
		},
	}, nil
}

func (b *backend) operationRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

const pathListRolesHelpSyn = "List the existing roles in this backend."

const pathListRolesHelpDesc = "Roles will be listed by the role name."

const pathRolesHelpSyn = `
Read, write and reference roles that API tokens can be made for.
`

const pathRolesHelpDesc = `
This path allows to read and write roles that are used to create API tokens.

To obtain an API token after the role is created, if the backend is mounted
at "packethost" and you create a role at "packethost/roles/deploy",
then a user could request access credentials at "alicloud/packethost/deploy".
`
