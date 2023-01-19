package Cx1ClientGo

import (
	"encoding/json"
	"net/http"
)

// Applications
func (c *Cx1Client) GetApplications() ([]Project, error) {
	c.logger.Debug("Get Cx1 Projects")
	var ProjectResponse struct {
		TotalCount    uint64
		FilteredCount uint64
		Projects      []Project
	}

	response, err := c.sendRequest(http.MethodGet, "/projects/", nil, nil)
	if err != nil {
		return ProjectResponse.Projects, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	c.logger.Tracef("Retrieved %d projects", len(ProjectResponse.Projects))
	return ProjectResponse.Projects, err
}
