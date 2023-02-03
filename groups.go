package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
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
		c.logger.Errorf("Error creating group: %s", err)
		return Group{}, err
	}

	return c.GetGroupByName(groupname)
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

	return Group{}, errors.New("No such group found")
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
		c.logger.Errorf("Error retrieving group: %s", err)
		return Group{}, err
	}

	c.logger.Tracef("Got %d groups", len(groups))

	for i := range groups {
		if groups[i].Name == groupname {
			match := groups[i]
			return match, nil
		}
	}

	return Group{}, errors.New("No matching group found")
}

func (c *Cx1Client) GetGroupByID(groupID string) (Group, error) {
	c.logger.Debugf("Getting Group with ID %v...", groupID)
	var group Group

	body := url.Values{
		"briefRepresentation": {"true"},
	}

	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v?%v", groupID, body.Encode()), nil, http.Header{})
	if err != nil {
		c.logger.Errorf("Fetching group failed: %s", err)
		return group, err
	}

	err = json.Unmarshal(data, &group)
	return group, err
}

func (c *Cx1Client) GroupLink(g *Group) string {
	return fmt.Sprintf("%v/auth/admin/%v/console/#/realms/%v/groups/%v", c.iamUrl, c.tenant, c.tenant, g.GroupID)
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
