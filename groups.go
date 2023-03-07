package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (g *Group) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(g.GroupID), g.Name)
}

func (c *Cx1Client) CreateGroup(groupname string) (Group, error) {
	c.logger.Debugf("Create Group: %v ", groupname)
	data := map[string]interface{}{
		"name": groupname,
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Group{}, err
	}

	_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", "/groups", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error creating group %v: %s", groupname, err)
		return Group{}, err
	}

	return c.GetGroupByName(groupname)
}

func (c *Cx1Client) CreateChildGroup(parentGroup Group, childGroupName string) (Group, error) {
	c.logger.Debugf("Create child Group: %v ", childGroupName)
	data := map[string]interface{}{
		"name": childGroupName,
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Group{}, err
	}

	_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", "/groups/"+parentGroup.GroupID+"/children", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Errorf("Error creating group: %s", err)
		return Group{}, err
	}

	return parentGroup, nil
}

func (c *Cx1Client) GetGroupsPIP() ([]Group, error) {
	c.logger.Debug("Get cx1 groups pip")
	var groups []Group
	response, err := c.sendRequestIAM(http.MethodGet, "/auth", "/pip/groups", nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	return groups, err
}

func (c *Cx1Client) GetGroupPIPByName(groupname string) (Group, error) {
	c.logger.Debugf("Get Cx1 Group by name: %v", groupname)

	groups, err := c.GetGroupsPIP()
	if err != nil {
		return Group{}, err
	}

	for _, g := range groups {
		if g.Name == groupname {
			return g, nil
		}
	}

	return Group{}, fmt.Errorf("no such group %v found", groupname)
}

func (c *Cx1Client) GetGroups() ([]Group, error) {
	c.logger.Debug("Get Cx1 Groups")
	var groups []Group

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/groups?briefRepresentation=true", nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	c.logger.Tracef("Got %d groups", len(groups))
	return groups, err
}

func (c *Cx1Client) GetGroupByName(groupname string) (Group, error) {
	c.logger.Debugf("Get Cx1 Group by name: %v", groupname)
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups?briefRepresentation=true&search=%v", url.PathEscape(groupname)), nil, nil)
	if err != nil {
		return Group{}, err
	}
	var groups []Group
	err = json.Unmarshal(response, &groups)

	if err != nil {
		c.logger.Tracef("Error retrieving group %v: %s", groupname, err)
		return Group{}, err
	}

	c.logger.Tracef("Got %d groups", len(groups))

	for i := range groups {
		if groups[i].Name == groupname {
			match := groups[i]
			return match, nil
		} else {
			subg, err := groups[i].FindSubgroupByName(groupname)
			if err == nil {
				return subg, nil
			}
		}
	}

	return Group{}, fmt.Errorf("no group %v found", groupname)
}

func (c *Cx1Client) GetGroupsByName(groupname string) ([]Group, error) {
	c.logger.Debugf("Get Cx1 Group by name: %v", groupname)
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups?briefRepresentation=true&search=%v", url.PathEscape(groupname)), nil, nil)
	if err != nil {
		return []Group{}, err
	}
	var groups []Group
	err = json.Unmarshal(response, &groups)
	return groups, err
}

func (c *Cx1Client) DeleteGroup(group *Group) error {
	c.logger.Debugf("Deleting Group %v...", group.String())

	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/groups/%v", group.GroupID), nil, http.Header{})
	return err
}

func (c *Cx1Client) GetGroupByID(groupID string) (Group, error) {
	c.logger.Debugf("Getting Group with ID %v...", groupID)
	var group Group

	body := url.Values{
		"briefRepresentation": {"true"},
	}

	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v?%v", groupID, body.Encode()), nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching group %v failed: %s", groupID, err)
		return group, err
	}

	err = json.Unmarshal(data, &group)
	group.Filled = true
	return group, err
}

func (c *Cx1Client) GroupLink(g *Group) string {
	return fmt.Sprintf("%v/auth/admin/%v/console/#/realms/%v/groups/%v", c.iamUrl, c.tenant, c.tenant, g.GroupID)
}

func (c *Cx1Client) SetGroupParent(g *Group, parent *Group) error {
	body := map[string]string{
		"id":   g.GroupID,
		"name": g.Name,
	}
	jsonBody, _ := json.Marshal(body)
	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/groups/%v/children", parent.GroupID), bytes.NewReader(jsonBody), http.Header{})
	if err != nil {
		c.logger.Tracef("Failed to add child to parent: %s", err)
		return err
	}

	return nil
}

func (c *Cx1Client) UpdateGroup(g *Group) error {
	if !g.Filled {
		return fmt.Errorf("group %v data is not filled (use GetGroupByID) - may be missing expected roles & subgroups, update aborted", g.String())
	}

	err := c.groupRoleChange(g)
	if err != nil {
		return fmt.Errorf("failed to update role changes for group %v: %s", g.String(), err)
	}

	jsonBody, _ := json.Marshal(*g)
	_, err = c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/groups/%v", g.GroupID), bytes.NewReader(jsonBody), http.Header{})
	return err
}

func (g *Group) AddRole(client, new_role string) error {
	if !g.Filled {
		return fmt.Errorf("group is not filled, first fetch the details via GetGroupByID")
	}

	if g.ClientRoles == nil {
		g.ClientRoles = make(map[string][]string)
	}

	_, ok := g.ClientRoles[client]
	if !ok {
		g.ClientRoles[client] = make([]string, 0)
	}

	for _, role := range g.ClientRoles[client] {
		if strings.EqualFold(role, new_role) {
			return fmt.Errorf("group already has role %v - %v", client, new_role)
		}
	}

	g.ClientRoles[client] = append(g.ClientRoles[client], new_role)

	return nil
}

func (g *Group) RemoveRole(client, del_role string) error {
	if !g.Filled {
		return fmt.Errorf("group %v is not filled, first fetch the details via GetGroupByID", g.String())
	}

	_, ok := g.ClientRoles[client]
	if !ok {
		return fmt.Errorf("group %v does not have the %v client", g.String(), client)
	}

	for id, role := range g.ClientRoles[client] {
		if strings.EqualFold(role, del_role) {
			return fmt.Errorf("group already has role %v - %v", client, del_role)
		} else {
			if id != len(g.ClientRoles[client])-1 {
				g.ClientRoles[client][id] = g.ClientRoles[client][len(g.ClientRoles[client])-1]
			}
			g.ClientRoles[client] = g.ClientRoles[client][:len(g.ClientRoles[client])-1]
			return nil
		}
	}

	return fmt.Errorf("group %v does not have the %v - %v role", g.String(), client, del_role)
}

func (c *Cx1Client) groupRoleChange(g *Group) error {
	orig_group, err := c.GetGroupByID(g.GroupID)
	if err != nil {
		return fmt.Errorf("failed to get original group info for group %v: %s", g.String(), err)
	}

	add_roles := map[string][]string{}
	del_roles := map[string][]string{}

	for new_client, new_roles := range g.ClientRoles {
		if _, ok := orig_group.ClientRoles[new_client]; !ok {
			add_roles[new_client] = new_roles
		} else {
			for _, nr := range new_roles {
				found := false
				for _, or := range orig_group.ClientRoles[new_client] {
					if strings.EqualFold(nr, or) {
						found = true
						break
					}
				}
				if !found {
					add_roles[new_client] = append(add_roles[new_client], nr)
				}
			}
		}
	}

	for orig_client, orig_roles := range orig_group.ClientRoles {
		if _, ok := g.ClientRoles[orig_client]; !ok {
			del_roles[orig_client] = orig_roles
		} else {
			for _, nr := range orig_roles {
				found := false
				for _, or := range g.ClientRoles[orig_client] {
					if strings.EqualFold(nr, or) {
						found = true
						break
					}
				}
				if !found {
					del_roles[orig_client] = append(del_roles[orig_client], nr)
				}
			}
		}
	}

	err = c.DeleteRolesFromGroup(g, del_roles)
	if err != nil {
		return fmt.Errorf("failed to delete roles from group %v: %s", g.String(), err)
	}

	err = c.AddRolesToGroup(g, add_roles)
	if err != nil {
		return fmt.Errorf("failed to delete roles from group %v: %s", g.String(), err)
	}

	return nil
}

// https://deu.iam.checkmarx.net/auth/admin/realms/cx_tam_appsec_canary_michael_kubiaczyk/groups/6083061f-09a9-447f-a609-282d8feae780/role-mappings/clients/8f855199-bf36-4c37-8edf-cbff9dd6aa37
// post [{"clientRole":true,"composite":true,"containerId":"8f855199-bf36-4c37-8edf-cbff9dd6aa37","id":"b25c6003-7332-479f-bcff-cbf171e68b25","name":"scanonly"}]
// https://deu.iam.checkmarx.net/auth/admin/realms/cx_tam_appsec_canary_michael_kubiaczyk/groups/6083061f-09a9-447f-a609-282d8feae780
func (c *Cx1Client) DeleteRolesFromGroup(g *Group, clientRoles map[string][]string) error {
	type roleid struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var role_list []roleid

	for client, roles := range clientRoles {
		kc_client, err := c.GetClientByName(client)
		if err != nil {
			return fmt.Errorf("failed to retrieve client %v: %s", client, err)
		}

		client_role_set, err := c.GetRolesByClient(kc_client.ClientID)
		if err != nil {
			return fmt.Errorf("failed to retrieve roles for client %v: %s", client, err)
		}

		for _, r := range roles {
			for _, kcr := range client_role_set {
				if strings.EqualFold(r, kcr.Name) {
					role_list = append(role_list, roleid{kcr.RoleID, kcr.Name})
				}
			}
		}

		jsonBody, _ := json.Marshal(role_list)
		_, err = c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/groups/%v/role-mappings/clients/%v", g.GroupID, kc_client.ClientID), bytes.NewReader(jsonBody), http.Header{})
		if err != nil {
			return fmt.Errorf("failed to remove roles from group %v: %s", g.String(), err)
		}
	}

	return nil
}
func (c *Cx1Client) AddRolesToGroup(g *Group, clientRoles map[string][]string) error {
	type roleid struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var role_list []roleid

	for client, roles := range clientRoles {
		kc_client, err := c.GetClientByName(client)
		if err != nil {
			return fmt.Errorf("failed to retrieve client %v: %s", client, err)
		}

		client_role_set, err := c.GetRolesByClient(kc_client.ClientID)
		if err != nil {
			return fmt.Errorf("failed to retrieve roles for client %v: %s", client, err)
		}

		for _, r := range roles {
			for _, kcr := range client_role_set {
				if strings.EqualFold(r, kcr.Name) {
					role_list = append(role_list, roleid{kcr.RoleID, kcr.Name})
				}
			}
		}

		jsonBody, _ := json.Marshal(role_list)
		_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/groups/%v/role-mappings/clients/%v", g.GroupID, kc_client.ClientID), bytes.NewReader(jsonBody), http.Header{})
		if err != nil {
			return fmt.Errorf("failed to remove roles from group %v: %s", g.String(), err)
		}
	}

	return nil
}

// convenience
func (c *Cx1Client) GetOrCreateGroup(name string) (Group, error) {
	group, err := c.GetGroupByName(name)
	if err != nil {
		group, err = c.CreateGroup(name)
		if err != nil {
			return group, err
		}
	}

	return group, nil
}

func (g *Group) FindSubgroupByName(name string) (Group, error) {
	for _, s := range g.SubGroups {
		if s.Name == name {
			return s, nil
		} else {
			subg, err := s.FindSubgroupByName(name)
			if err == nil {
				return subg, nil
			}
		}
	}

	return Group{}, fmt.Errorf("group %v does not contain subgroup named %v", g.String(), name)
}
