package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Roles and Clients
func (c Cx1Client) GetClients() ([]KeyCloakClient, error) {
	c.logger.Debug("Getting KeyCloak Clients")
	var clients []KeyCloakClient

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/clients?briefRepresentation=true", nil, nil)
	if err != nil {
		return clients, err
	}

	err = json.Unmarshal(response, &clients)
	c.logger.Tracef("Got %d clients", len(clients))
	return clients, err
}

func (c Cx1Client) GetClientByName(clientName string) (KeyCloakClient, error) {
	c.logger.Debugf("Getting KeyCloak client with name %v", clientName)

	var client KeyCloakClient
	clients, err := c.GetClients()
	if err != nil {
		return client, err
	}

	for _, c := range clients {
		if c.Name == clientName {
			client = c
			return client, nil
		}
	}

	return client, fmt.Errorf("no such client %v found", clientName)
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

		astAppID = client.ClientID
	}

	return astAppID
}
