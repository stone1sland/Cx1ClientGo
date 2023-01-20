package Cx1ClientGo

import (
	"fmt"

	"github.com/pkg/errors"
)

type Cx1Cache struct {
	ProjectRefresh bool
	Projects       []Project
	GroupRefresh   bool
	Groups         []Group
	UserRefresh    bool
	Users          []User
	QueryRefresh   bool
	Queries        []Query
	QueryGroups    []QueryGroup
	PresetRefresh  bool
	Presets        []Preset
	RoleRefresh    bool
	Roles          []Role
}

func (c *Cx1Cache) PresetSummary() string {
	return fmt.Sprintf("%d presets", len(c.Presets))
}

func (c *Cx1Cache) QuerySummary() string {
	return fmt.Sprintf("%d queries in %d query groups", len(c.Queries), len(c.QueryGroups))
}
func (c *Cx1Cache) UserSummary() string {
	return fmt.Sprintf("%d users", len(c.Users))
}
func (c *Cx1Cache) GroupSummary() string {
	return fmt.Sprintf("%d groups", len(c.Groups))
}
func (c *Cx1Cache) ProjectSummary() string {
	return fmt.Sprintf("%d projects", len(c.Projects))
}

func (c *Cx1Cache) RefreshProjects(client *Cx1Client) error {
	var err error
	if !c.ProjectRefresh {
		c.ProjectRefresh = true
		c.Projects, err = client.GetProjects(0)
		c.ProjectRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshGroups(client *Cx1Client) error {
	var err error
	if !c.GroupRefresh {
		c.GroupRefresh = true
		c.Groups, err = client.GetGroups()
		c.GroupRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshUsers(client *Cx1Client) error {
	var err error
	if !c.UserRefresh {
		c.UserRefresh = true
		c.Users, err = client.GetUsers()
		c.UserRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshQueries(client *Cx1Client) error {
	var err error
	if !c.QueryRefresh {
		c.QueryRefresh = true
		c.Queries, err = client.GetQueries()
		c.QueryGroups = client.GetQueryGroups(&c.Queries)
		c.QueryRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshPresets(client *Cx1Client) error {
	var err error
	if !c.PresetRefresh {
		c.PresetRefresh = true
		c.Presets, err = client.GetPresets()

		if err != nil {
			client.logger.Errorf("Failed while retrieving presets: %s", err)
		} else {
			for id := range c.Presets {
				err := client.GetPresetContents(&c.Presets[id], &c.Queries)
				if err != nil {
					client.logger.Errorf("Failed to retrieve preset contents for preset %v: %s", c.Presets[id].String(), err)
				}
			}
		}
		c.PresetRefresh = false
	}
	return err
}

func (c *Cx1Cache) RefreshRoles(client *Cx1Client) error {
	var err error
	if !c.RoleRefresh {
		c.RoleRefresh = true
		c.Roles, err = client.GetCombinedRoles()
		if err != nil {
			client.logger.Errorf("Failed while retrieving roles: %s", err)
		} else {
			for id, r := range c.Roles {
				var role Role
				var err error
				if r.ClientRole {
					role, err = client.GetASTRoleByName(r.Name)
				}
				c.Roles[id].Attributes = role.Attributes
				if err != nil {
					client.logger.Errorf("Failed to retrieve details for role %v: %s", r.String(), err)
				}
			}
		}
		c.RoleRefresh = false
	}
	return err
}

func (c *Cx1Cache) Refresh(client *Cx1Client) error {
	var err error

	err = c.RefreshProjects(client)
	if err != nil {
		return err
	}

	err = c.RefreshGroups(client)
	if err != nil {
		return err
	}

	err = c.RefreshUsers(client)
	if err != nil {
		return err
	}

	err = c.RefreshQueries(client)
	if err != nil {
		return err
	}

	err = c.RefreshPresets(client)
	if err != nil {
		return err
	}

	err = c.RefreshRoles(client)
	if err != nil {
		return err
	}

	return nil
}

func (c *Cx1Cache) GetGroup(groupID string) (*Group, error) {
	for id, t := range c.Groups {
		if t.GroupID == groupID {
			return &c.Groups[id], nil
		}
	}
	return nil, errors.New("No such group")
}
func (c *Cx1Cache) GetGroupByName(name string) (*Group, error) {
	for id, t := range c.Groups {
		if t.Name == name {
			return &c.Groups[id], nil
		}
	}
	return nil, errors.New("No such group")
}

func (c *Cx1Cache) GetUser(userID string) (*User, error) {
	for id, g := range c.Users {
		if g.UserID == userID {
			return &c.Users[id], nil
		}
	}
	return nil, errors.New("No such user")
}
func (c *Cx1Cache) GetUserByEmail(email string) (*User, error) {
	for id, g := range c.Users {
		if g.Email == email {
			return &c.Users[id], nil
		}
	}
	return nil, errors.New("No such user")
}
func (c *Cx1Cache) GetUserByString(displaystring string) (*User, error) {
	for id, g := range c.Users {
		if g.String() == displaystring {
			return &c.Users[id], nil
		}
	}
	return nil, errors.New("No such user")
}

func (c *Cx1Cache) GetProject(projectID string) (*Project, error) {
	for id, g := range c.Projects {
		if g.ProjectID == projectID {
			return &c.Projects[id], nil
		}
	}
	return nil, errors.New("No such project")
}
func (c *Cx1Cache) GetProjectByName(name string) (*Project, error) {
	for id, g := range c.Projects {
		if g.Name == name {
			return &c.Projects[id], nil
		}
	}
	return nil, errors.New("No such project")
}

func (c *Cx1Cache) GetPreset(presetID uint64) (*Preset, error) {
	for id, g := range c.Presets {
		if g.PresetID == presetID {
			return &c.Presets[id], nil
		}
	}
	return nil, errors.New("No such preset")
}
func (c *Cx1Cache) GetPresetByName(name string) (*Preset, error) {
	for id, g := range c.Presets {
		if g.Name == name {
			return &c.Presets[id], nil
		}
	}
	return nil, errors.New("No such preset")
}

func (c *Cx1Cache) GetRole(roleID string) (*Role, error) {
	for id, g := range c.Roles {
		if g.RoleID == roleID {
			return &c.Roles[id], nil
		}
	}
	return nil, errors.New("No such role")
}
func (c *Cx1Cache) GetRoleByName(name string) (*Role, error) {
	for id, g := range c.Roles {
		if g.Name == name {
			return &c.Roles[id], nil
		}
	}
	return nil, errors.New("No such role")
}

func (c *Cx1Cache) GetQuery(queryID uint64) (*Query, error) {
	for id, g := range c.Queries {
		if g.QueryID == queryID {
			return &c.Queries[id], nil
		}
	}
	return nil, errors.New("No such query")
}
func (c *Cx1Cache) GetQueryByNames(language, group, query string) (*Query, error) {
	/*for _, g := range c.Queries {
	      if g.QueryID == queryID {
	          return g, nil
	      }
	  }
	  return nil, errors.New( "No such query" )*/
	return nil, errors.New("Not implemented")
}
