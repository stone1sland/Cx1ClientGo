package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

func (r *Role) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(r.RoleID), r.Name)
}

func (r *Role) HasCategory(name string) bool {
	for _, role := range r.Attributes.Category {
		if role == name {
			return true
		}
	}
	return false
}

func (c *Cx1Client) GetKeyCloakRoles() ([]Role, error) {
	c.logger.Debugf("Getting KeyCloak Roles")
	var roles []Role

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/roles?briefRepresentation=true", nil, nil)
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	c.logger.Tracef("Got %d roles", len(roles))
	return roles, err
}
func (c *Cx1Client) GetKeyCloakRoleByName(name string) (Role, error) {
	c.logger.Debugf("Getting KeyCloak Role named %v", name)
	var role Role
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/roles/%v", url.QueryEscape(name)), nil, nil)
	if err != nil {
		return role, err
	}

	err = json.Unmarshal(response, &role)
	return role, err
}

func (c *Cx1Client) GetRolesByClient(clientId string) ([]Role, error) {
	c.logger.Debugf("Getting KeyCloak Roles for client %v", clientId)
	var roles []Role

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/roles?briefRepresentation=true", clientId), nil, nil)
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	c.logger.Tracef("Got %d roles", len(roles))
	return roles, err
}

func (c *Cx1Client) GetRoleByClientAndName(clientId string, name string) (Role, error) {
	c.logger.Debugf("Getting KeyCloak Roles for client %v with name %v", clientId, name)
	var role Role

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/roles/%v", clientId, url.PathEscape(name)), nil, nil)
	if err != nil {
		return role, err
	}

	err = json.Unmarshal(response, &role)
	return role, err
}

func (c *Cx1Client) CreateASTRole(roleName, createdBy string) (Role, error) {
	c.logger.Debugf("User %v creating client role %v", createdBy, roleName)
	data := map[string]interface{}{
		"name":       roleName,
		"composite":  true,
		"clientRole": true,
		"attributes": map[string]interface{}{
			"category":   []string{"Composite role"},
			"type":       []string{"Role"},
			"creator":    []string{fmt.Sprintf("SAST2CX1 by %v", createdBy)},
			"lastUpdate": []int64{time.Now().UnixMilli()},
		},
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		c.logger.Errorf("Failed to marshal data somehow: %s", err)
		return Role{}, err
	}
	_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/clients/%v/roles", c.GetASTAppID()), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Errorf("Failed to create a client role: %s", err)
		return Role{}, err
	}

	return c.GetRoleByClientAndName(c.GetASTAppID(), roleName)
}

func (c *Cx1Client) GetASTRoles() ([]Role, error) {
	c.logger.Debug("Getting roles set for ast-app client")
	return c.GetRolesByClient(c.GetASTAppID())
}

func (c *Cx1Client) GetASTRoleByName(name string) (Role, error) {
	c.logger.Debugf("Getting role named %v in ast-app client", name)
	return c.GetRoleByClientAndName(c.GetASTAppID(), name)
}

// convenience function to get both KeyCloak (system) roles plus the AST-APP-specific roles
func (c *Cx1Client) GetCombinedRoles() ([]Role, error) {
	c.logger.Debug("Getting System (KeyCloak) and Application (AST-APP) roles")
	ast_roles, err := c.GetASTRoles()
	if err != nil {
		return ast_roles, err
	}
	system_roles, err := c.GetKeyCloakRoles()
	if err != nil {
		return ast_roles, err
	}

	ast_roles = append(ast_roles, system_roles...)
	return ast_roles, nil
}
func (c *Cx1Client) GetCombinedRoleByName(name string) (Role, error) {
	c.logger.Debug("Getting System (KeyCloak) and Application (AST-APP) role named: %v", name)

	role, err := c.GetASTRoleByName(name)
	if err == nil {
		return role, nil
	}
	role, err = c.GetKeyCloakRoleByName(name)
	if err == nil {
		return role, nil
	}

	return Role{}, errors.New("Role not found")
}

func (c *Cx1Client) RoleLink(r *Role) string {
	return fmt.Sprintf("%v/auth/admin/%v/console/#/realms/%v/roles/%v", c.iamUrl, c.tenant, c.tenant, r.RoleID)
}
