package Cx1ClientGo

import "fmt"

func (u User) String() string {
	return fmt.Sprintf("[%v] %v %v (%v)", ShortenGUID(u.UserID), u.FirstName, u.LastName, u.Email)
}
func (u WhoAmI) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(u.UserID), u.Name)
}

func (u User) HasRole(role *Role) bool {
	return u.HasRoleByID(role.RoleID)
}
func (u User) HasRoleByID(roleID string) bool {
	for _, r := range u.Roles {
		if r.RoleID == roleID {
			return true
		}
	}
	return false
}
func (u User) HasRoleByName(role string) bool {
	for _, r := range u.Roles {
		if r.Name == role {
			return true
		}
	}
	return false
}

func (u User) IsInGroup(group *Group) bool {
	return u.IsInGroupByID(group.GroupID)
}
func (u User) IsInGroupByID(groupId string) bool {
	for _, g := range u.Groups {
		if g.GroupID == groupId {
			return true
		}
	}
	return false
}
func (u User) IsInGroupByName(groupName string) bool {
	for _, g := range u.Groups {
		if g.Name == groupName {
			return true
		}
	}
	return false
}

func (u *User) AddGroup(client *Cx1Client, group *Group) error {
	//client.AddUserRoles( u,
	return nil
}

func (u User) Save(client *Cx1Client) error {
	return client.UpdateUser(&u)
}
func (u User) Delete(client *Cx1Client) error {
	return client.DeleteUser(&u)
}
func (u User) Link(client *Cx1Client) string {
	return client.UserLink(&u)
}
