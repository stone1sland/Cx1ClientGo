package Cx1ClientGo

import (
    "strconv"
)


type Cx1Cache struct {
    Projects []Project
	Groups []Group
	Users []User
	Queries []Query
	//QueryGroups []QueryGroup // caching - to reconsider if needed
	Presets []Preset
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
func (c *Cx1Cache) Refresh( client *Cx1Client ) error {
    var err error
	c.Projects, err = client.GetProjects()
    if err != nil {
        return err
    }

	c.Groups, err = client.GetGroups()
    if err != nil {
        return err
    }
    
	c.Users, err = client.GetUsers()
    if err != nil {
        return err
    }
    
	c.Presets, err = client.GetPresets()
    if err != nil {
        return err
    }
    
	c.Queries, err = client.GetQueries() 
    if err != nil {
        return err
    }
    
    return nil
}