package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Roles and Clients
func (c Cx1Client) GetClients() ([]OIDCClient, error) {
	c.logger.Debug("Getting OIDC Clients")
	var clients []OIDCClient

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/clients?briefRepresentation=true", nil, nil)
	if err != nil {
		return clients, err
	}

	err = json.Unmarshal(response, &clients)
	c.logger.Tracef("Got %d clients", len(clients))
	return clients, err
}

func (c Cx1Client) GetClientByName(clientName string) (OIDCClient, error) {
	c.logger.Debugf("Getting OIDC client with name %v", clientName)

	var client OIDCClient
	clients, err := c.GetClients()
	if err != nil {
		return client, err
	}

	for _, c := range clients {
		if c.ClientID == clientName {
			client = c
			return client, nil
		}
	}

	return client, fmt.Errorf("no such client %v found", clientName)
}

func (c Cx1Client) CreateClient(name string) (OIDCClient, error) {
	c.logger.Debugf("Creating OIDC client with name %v", name)

	body := map[string]interface{}{
		"enabled":      true,
		"attributes":   map[string]interface{}{},
		"redirectUris": []string{},
		"clientId":     name,
		"protocol":     "openid-connect",
	}

	jsonBody, _ := json.Marshal(body)

	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", "/clients", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return OIDCClient{}, err
	}

	return c.GetClientByName(name)
}

func (c Cx1Client) DeleteClientByID(id string) error {
	c.logger.Debugf("Deleting OIDC client with ID %v", id)
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/clients/%v", id), nil, nil)
	return err
}

func (c Cx1Client) GetServiceAccountByID(oidcId string) (User, error) {
	c.logger.Debugf("Getting service account user behind OIDC client with ID %v", oidcId)
	var user User
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/service-account-user", oidcId), nil, nil)
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(response, &user)
	return user, err
}

func (c Cx1Client) GetTenantID() string {
	if tenantID != "" {
		return tenantID
	}

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "", nil, nil)
	if err != nil {
		c.logger.Warnf("Failed to retrieve tenant ID: %s", err)
		return tenantID
	}

	var realms struct {
		ID    string `json:"id"`
		Realm string `json:"realm"`
	} // Sometimes this returns an array of one element? Is it possible to return multiple?

	err = json.Unmarshal(response, &realms)
	if err != nil {
		c.logger.Warnf("Failed to parse tenant ID: %s", err)
		c.logger.Tracef("Response was: %v", string(response))
		return tenantID
	}

	//for _, r := range realms {
	if realms.Realm == c.tenant {
		tenantID = realms.ID
	}
	//}
	if tenantID == "" {
		c.logger.Warnf("Failed to retrieve tenant ID: no tenant found matching %v", c.tenant)
	}

	return tenantID
}

// convenience function
func (c Cx1Client) GetASTAppID() string {
	if astAppID == "" {
		client, err := c.GetClientByName("ast-app")
		if err != nil {
			c.logger.Warnf("Error finding AST App ID: %s", err)
			return ""
		}

		astAppID = client.ID
	}

	return astAppID
}
