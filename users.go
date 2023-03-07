package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (c *Cx1Client) GetCurrentUser() (User, error) {
	var whoami struct {
		UserID string
	}
	var user User

	response, err := c.sendRequestOther(http.MethodGet, "/auth/admin", "/console/whoami", nil, nil)
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(response, &whoami)
	if err != nil {
		return user, err
	}

	return c.GetUserByID(whoami.UserID)
}

func (u *User) String() string {
	return fmt.Sprintf("[%v] %v %v (%v)", ShortenGUID(u.UserID), u.FirstName, u.LastName, u.Email)
}

func (c *Cx1Client) GetUsers() ([]User, error) {
	c.logger.Debug("Get Cx1 Users")

	var users []User
	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/users", nil, nil)
	if err != nil {
		return users, err
	}

	err = json.Unmarshal(response, &users)
	c.logger.Tracef("Got %d users", len(users))
	return users, err
}

func (c *Cx1Client) GetUserByID(userID string) (User, error) {
	c.logger.Debug("Get Cx1 User by ID")

	var user User
	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/users/%v", userID), nil, nil)
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(response, &user)
	return user, err
}

func (c *Cx1Client) GetUserByUserName(name string) (User, error) {
	c.logger.Debugf("Get Cx1 User by Username: %v", name)

	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/users/?exact=true&username=%v", url.QueryEscape(name)), nil, nil)
	if err != nil {
		return User{}, err
	}

	var users []User

	err = json.Unmarshal(response, &users)
	if err != nil {
		return User{}, err
	}
	if len(users) == 0 {
		return User{}, fmt.Errorf("no user %v found", name)
	}
	if len(users) > 1 {
		return User{}, fmt.Errorf("too many users (%d) match %v", len(users), name)
	}
	return users[0], err
}

func (c *Cx1Client) CreateUser(newuser User) (User, error) {
	c.logger.Debugf("Creating a new user %v", newuser.String())
	newuser.UserID = ""
	jsonBody, err := json.Marshal(newuser)
	if err != nil {
		c.logger.Tracef("Failed to marshal data somehow: %s", err)
		return User{}, err
	}

	response, err := c.sendRequestRawIAM(http.MethodPost, "/auth/admin", "/users", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return User{}, err
	}

	location := response.Header.Get("Location")
	if location != "" {
		lastInd := strings.LastIndex(location, "/")
		guid := location[lastInd+1:]
		c.logger.Infof(" New user ID: %v", guid)
		return c.GetUserByID(guid)
	} else {
		return User{}, fmt.Errorf("unknown error - no Location header redirect in response")
	}
}

func (c *Cx1Client) UpdateUser(user *User) error {
	c.logger.Debugf("Updating user %v", user.String())
	jsonBody, err := json.Marshal(user)
	if err != nil {
		c.logger.Tracef("Failed to marshal data somehow: %s", err)
		return err
	}

	_, err = c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/users/%v", user.UserID), bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) DeleteUser(userid string) error {
	c.logger.Debugf("Deleting a user %v", userid)

	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/users/%v", userid), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to delete user: %s", err)
		return err
	}
	return nil
}

func (c *Cx1Client) GetUserRoleMappings(userID string, clientID string) ([]Role, error) {
	c.logger.Debugf("Get Cx1 Rolemappings for userid %v and clientid %v", userID, clientID)

	var roles []Role
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/users/%v/role-mappings/clients/%v", userID, clientID), nil, nil)
	if err != nil {
		return roles, err
	}
	err = json.Unmarshal(response, &roles)
	return roles, err
}

func (c *Cx1Client) GetUserASTRoleMappings(userID string) ([]Role, error) {
	return c.GetUserRoleMappings(userID, c.GetASTAppID())
}

func (c *Cx1Client) AddUserRoleMappings(userID string, clientID string, roles []Role) error {
	c.logger.Debugf("Add Cx1 Rolemappings for userid %v and clientid %v", userID, clientID)

	jsonBody, err := json.Marshal(roles)
	if err != nil {
		c.logger.Tracef("Failed to marshal roles: %s", err)
		return err
	}

	_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/users/%v/role-mappings/clients/%v", userID, clientID), bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) AddUserASTRoleMappings(userID string, roles []Role) error {
	return c.AddUserRoleMappings(userID, c.GetASTAppID(), roles)
}

func (c *Cx1Client) RemoveUserRoleMappings(userID string, clientID string, roles []Role) error {
	c.logger.Debugf("Add Cx1 Rolemappings for userid %v and clientid %v", userID, clientID)

	jsonBody, err := json.Marshal(roles)
	if err != nil {
		c.logger.Tracef("Failed to marshal roles: %s", err)
		return err
	}

	_, err = c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/users/%v/role-mappings/clients/%v", userID, clientID), bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) RemoveUserASTRoleMappings(userID string, roles []Role) error {
	return c.RemoveUserRoleMappings(userID, c.GetASTAppID(), roles)
}

func (c *Cx1Client) UserLink(u *User) string {
	return fmt.Sprintf("%v/auth/admin/%v/console/#/realms/%v/users/%v", c.iamUrl, c.tenant, c.tenant, u.UserID)
}

func (c *Cx1Client) GetUserGroups(user *User) error {
	var usergroups []Group

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/users/%v/groups", user.UserID), nil, nil)

	if err != nil {
		c.logger.Tracef("Failed to fetch user's groups: %s", err)
		return err
	}

	err = json.Unmarshal(response, &usergroups)
	if err != nil {
		c.logger.Tracef("Failed to unmarshal response: %s", err)
		return err
	}

	user.Groups = usergroups

	return nil
}

func (u *User) IsInGroup(groupId string) bool {
	for _, g := range u.Groups {
		if g.GroupID == groupId {
			return true
		}
	}
	return false
}

func (u *User) IsInGroupByName(groupName string) bool {
	for _, g := range u.Groups {
		if g.Name == groupName {
			return true
		}
	}
	return false
}

func (c *Cx1Client) AssignUserToGroup(user *User, groupId string) error {
	if !user.IsInGroup(groupId) {
		params := map[string]string{
			"realm":   c.tenant,
			"userId":  user.UserID,
			"groupId": groupId,
		}

		jsonBody, err := json.Marshal(params)
		if err != nil {
			c.logger.Tracef("Failed to marshal group params: %s", err)
			return err
		}

		_, err = c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/users/%v/groups/%v", user.UserID, groupId), bytes.NewReader(jsonBody), nil)
		if err != nil {
			c.logger.Tracef("Failed to add user to group: %s", err)
			return err
		}

		// TODO: Should user structure be updated to include the new group membership? (get group obj, append to list)
	}
	return nil
}

func (c *Cx1Client) RemoveUserFromGroup(user *User, groupId string) error {
	if user.IsInGroup(groupId) {
		params := map[string]string{
			"realm":   c.tenant,
			"userId":  user.UserID,
			"groupId": groupId,
		}

		jsonBody, err := json.Marshal(params)
		if err != nil {
			c.logger.Tracef("Failed to marshal group params: %s", err)
			return err
		}

		_, err = c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/users/%v/groups/%v", user.UserID, groupId), bytes.NewReader(jsonBody), nil)
		if err != nil {
			c.logger.Tracef("Failed to remove user from group: %s", err)
			return err
		}

		// TODO: should user structure be updated to remove the group also? (iterate over list & remove element?)
	}
	return nil
}
