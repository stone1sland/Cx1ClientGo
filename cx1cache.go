package Cx1ClientGo

import (
    "strconv"
    "github.com/pkg/errors"
)


type Cx1Cache struct {
    ProjectRefresh bool
    Projects []Project
    GroupRefresh bool
	Groups []Group
    UserRefresh bool
	Users []User
    QueryRefresh bool
	Queries []Query
	//QueryGroups []QueryGroup // caching - to reconsider if needed
    PresetRefresh bool
	Presets []Preset
    RoleRefresh bool
    Roles []Role
}

func (c *Cx1Cache) PresetSummary() string {

	return strconv.Itoa( len( c.Presets ) ) + " presets"
}

func (c *Cx1Cache) QuerySummary() string {
	
	return strconv.Itoa( len( c.Queries ) ) + " queries"
}
func (c *Cx1Cache) UserSummary() string {
	
	return strconv.Itoa( len( c.Users ) ) + " users"
}
func (c *Cx1Cache) GroupSummary() string {
	
	return strconv.Itoa( len( c.Groups ) ) + " groups"
}
func (c *Cx1Cache) GroupTree() string {
	
	return ""
}
func (c *Cx1Cache) ProjectSummary() string {
	
	return strconv.Itoa( len( c.Projects ) ) + " projects"
}

func (c *Cx1Cache) RefreshProjects( client *Cx1Client ) error {
    var err error
    if !c.ProjectRefresh {
        c.ProjectRefresh = true
        c.Projects, err = client.GetProjects()
        c.ProjectRefresh = false
    }
    return err
}

func (c *Cx1Cache) RefreshGroups( client *Cx1Client ) error {
    var err error
    if !c.GroupRefresh {
        c.GroupRefresh = true
        c.Groups, err = client.GetGroups()
        c.GroupRefresh = false
    }
    return err
}

func (c *Cx1Cache) RefreshUsers( client *Cx1Client ) error {
    var err error
    if !c.UserRefresh {
        c.UserRefresh = true
        c.Users, err = client.GetUsers()
        c.UserRefresh = false
    }
    return err
}

func (c *Cx1Cache) RefreshQueries( client *Cx1Client ) error {
    var err error
    if !c.QueryRefresh {
        c.QueryRefresh = true
        c.Queries, err = client.GetQueries()
        c.QueryRefresh = false
    }
    return err
}

func (c *Cx1Cache) RefreshPresets( client *Cx1Client ) error {
    var err error
    if !c.PresetRefresh {
        c.PresetRefresh = true
        c.Presets, err = client.GetPresets()
        c.PresetRefresh = false
    }
    return err
}

func (c *Cx1Cache) RefreshRoles( client *Cx1Client ) error {
    var err error
    if !c.RoleRefresh {
        c.RoleRefresh = true
        c.Roles, err = client.GetCombinedRoles()
        c.RoleRefresh = false
    }
    return err
}

func (c *Cx1Cache) Refresh( client *Cx1Client ) error {
    var err error

    err = c.RefreshProjects(client)
    if err != nil { return err }
    
    err = c.RefreshGroups(client)
    if err != nil { return err }

    err = c.RefreshUsers(client)
    if err != nil { return err }

    err = c.RefreshQueries(client)
    if err != nil { return err }

    err = c.RefreshPresets(client)
    if err != nil { return err }

    err = c.RefreshRoles(client)
    if err != nil { return err }

    return nil
}



func (c *Cx1Cache) GetGroup( groupID string ) (Group, error) {
    for _, g := range c.Groups {
        if g.GroupID == groupID {
            return g, nil
        }
    }
    return Group{}, errors.New( "No such group" )
}

func (c *Cx1Cache) GetUser( userID string ) (User, error) {
    for _, g := range c.Users {
        if g.UserID == userID {
            return g, nil
        }
    }
    return User{}, errors.New( "No such user" )
}

func (c *Cx1Cache) GetProject( projectID string ) (Project, error) {
    for _, g := range c.Projects {
        if g.ProjectID == projectID {
            return g, nil
        }
    }
    return Project{}, errors.New( "No such project" )
}

func (c *Cx1Cache) GetPreset( presetID uint64 ) (Preset, error) {
    for _, g := range c.Presets {
        if g.PresetID == presetID {
            return g, nil
        }
    }
    return Preset{}, errors.New( "No such preset" )
}

func (c *Cx1Cache) GetRole( roleID string ) (Role, error) {
    for _, g := range c.Roles {
        if g.RoleID == roleID {
            return g, nil
        }
    }
    return Role{}, errors.New( "No such role" )
}