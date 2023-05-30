package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Projects
func (c Cx1Client) CreateProject(projectname string, cx1_group_ids []string, tags map[string]string) (Project, error) {
	c.logger.Debugf("Create Project: %v", projectname)
	data := map[string]interface{}{
		"name":        projectname,
		"groups":      []string{},
		"tags":        map[string]string{},
		"criticality": 3,
		"origin":      cxOrigin,
	}

	if len(tags) > 0 {
		data["tags"] = tags
	}
	if len(cx1_group_ids) > 0 {
		data["groups"] = cx1_group_ids
	}

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Project{}, err
	}

	var project Project
	response, err := c.sendRequest(http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while creating project %v: %s", projectname, err)
		return project, err
	}

	err = json.Unmarshal(response, &project)

	return project, err
}

func (p *Project) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(p.ProjectID), p.Name)
}

func (p *Project) GetTags() string {
	str := ""
	for key, val := range p.Tags {
		if str == "" {
			str = key + " = " + val
		} else {
			str = str + ", " + key + " = " + val
		}
	}
	return str
}

func (c Cx1Client) GetProjects(limit uint64) ([]Project, error) {
	c.logger.Debug("Get Cx1 Projects")
	var ProjectResponse struct {
		TotalCount    uint64
		FilteredCount uint64
		Projects      []Project
	}

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", limit)},
		//"name":  {projectname},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/?%v", body.Encode()), nil, nil)
	if err != nil {
		return ProjectResponse.Projects, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	c.logger.Tracef("Retrieved %d projects", len(ProjectResponse.Projects))
	return ProjectResponse.Projects, err
}

func (c Cx1Client) GetProjectByID(projectID string) (Project, error) {
	c.logger.Debugf("Getting Project with ID %v...", projectID)
	var project Project

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/%v", projectID), nil, nil)
	if err != nil {
		return project, fmt.Errorf("failed to fetch project %v: %s", projectID, err)
	}

	err = json.Unmarshal([]byte(data), &project)
	if err != nil {
		return project, err
	}

	err = c.GetProjectConfiguration(&project)
	return project, err
}

func (c Cx1Client) GetProjectByName(projectname string) (Project, error) {
	count, err := c.GetProjectCountByName(projectname)
	if err != nil {
		return Project{}, err
	}

	projects, err := c.GetProjectsByName(projectname, count)
	if err != nil {
		return Project{}, err
	}

	for _, p := range projects {
		if p.Name == projectname {
			err = c.GetProjectConfiguration(&p)
			return p, err
		}
	}

	return Project{}, fmt.Errorf("no project matching %v found", projectname)
}

func (c Cx1Client) GetProjectsByName(projectname string, limit uint64) ([]Project, error) {
	c.logger.Debugf("Get Cx1 Projects By Name: %v", projectname)

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", limit)},
		"name":  {projectname},
	}

	var ProjectResponse struct {
		TotalCount    uint64
		FilteredCount uint64
		Projects      []Project
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects?%v", body.Encode()), nil, nil)
	if err != nil {
		return ProjectResponse.Projects, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	if err != nil {
		c.logger.Tracef("Error getting project: %s", err)
		c.logger.Tracef("Failed to unmarshal: %v", string(response))
		return ProjectResponse.Projects, err
	}

	c.logger.Tracef("Retrieved %d projects", len(ProjectResponse.Projects))

	return ProjectResponse.Projects, nil
}

func (c Cx1Client) GetProjectsByNameAndGroup(projectName string, groupID string) ([]Project, error) {
	c.depwarn("GetProjectsByNameAndGroup", "GetProjectsByNameAndGroupID")
	return c.GetProjectsByNameAndGroupID(projectName, groupID)
}

func (c Cx1Client) GetProjectsByNameAndGroupID(projectName string, groupID string) ([]Project, error) {
	c.logger.Debugf("Getting projects with name %v of group ID %v...", projectName, groupID)

	var projectResponse struct {
		TotalCount    int       `json:"totalCount"`
		FilteredCount int       `json:"filteredCount"`
		Projects      []Project `json:"projects"`
	}

	var data []byte
	var err error

	body := url.Values{}
	if len(groupID) > 0 {
		body.Add("groups", groupID)
	}
	if len(projectName) > 0 {
		body.Add("name", projectName)
	}

	if len(body) > 0 {
		data, err = c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/?%v", body.Encode()), nil, nil)
	} else {
		data, err = c.sendRequest(http.MethodGet, "/projects/", nil, nil)
	}
	if err != nil {
		return projectResponse.Projects, fmt.Errorf("fetching project %v failed: %s", projectName, err)
	}

	err = json.Unmarshal(data, &projectResponse)
	c.logger.Tracef("Retrieved %d projects matching %v in group ID %v", len(projectResponse.Projects), projectName, groupID)

	return projectResponse.Projects, err
}

// convenience
func (p *Project) IsInGroupID(groupId string) bool {
	for _, g := range p.Groups {
		if g == groupId {
			return true
		}
	}
	return false
}

func (p *Project) IsInGroup(group *Group) bool {
	return p.IsInGroupID(group.GroupID)
}

func (c Cx1Client) GetProjectConfiguration(project *Project) error {
	configurations, err := c.GetProjectConfigurationByID(project.ProjectID)
	project.Configuration = configurations
	return err
}

func (c Cx1Client) GetProjectConfigurationByID(projectID string) ([]ProjectConfigurationSetting, error) {
	c.logger.Debug("Getting project configuration")
	var projectConfigurations []ProjectConfigurationSetting
	params := url.Values{
		"project-id": {projectID},
	}
	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/configuration/project?%v", params.Encode()), nil, nil)

	if err != nil {
		c.logger.Tracef("Failed to get project configuration for project ID %v: %s", projectID, err)
		return projectConfigurations, err
	}

	err = json.Unmarshal([]byte(data), &projectConfigurations)
	return projectConfigurations, err
}

// UpdateProjectConfiguration updates the configuration of the project addressed by projectID
func (c Cx1Client) UpdateProjectConfiguration(project *Project, settings []ProjectConfigurationSetting) error {
	project.Configuration = settings
	return c.UpdateProjectConfigurationByID(project.ProjectID, settings)
}

func (c Cx1Client) UpdateProjectConfigurationByID(projectID string, settings []ProjectConfigurationSetting) error {
	if len(settings) == 0 {
		return fmt.Errorf("empty list of settings provided")
	}

	params := url.Values{
		"project-id": {projectID},
	}

	jsonBody, err := json.Marshal(settings)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPatch, fmt.Sprintf("/configuration/project?%v", params.Encode()), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Failed to update project %v configuration: %s", projectID, err)
		return err
	}

	return nil
}

func (c Cx1Client) SetProjectBranch(projectID, branch string, allowOverride bool) error {
	c.depwarn("SetProjectBranch", "SetProjectBranchByID")
	return c.SetProjectBranchByID(projectID, branch, allowOverride)
}

func (c Cx1Client) SetProjectBranchByID(projectID, branch string, allowOverride bool) error {
	var setting ProjectConfigurationSetting
	setting.Key = "scan.handler.git.branch"
	setting.Value = branch
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ProjectConfigurationSetting{setting})
}

func (c Cx1Client) SetProjectPreset(projectID, presetName string, allowOverride bool) error {
	c.depwarn("SetProjectPreset", "SetProjectPresetByID")
	return c.SetProjectPresetByID(projectID, presetName, allowOverride)
}

func (c Cx1Client) SetProjectPresetByID(projectID, presetName string, allowOverride bool) error {
	var setting ProjectConfigurationSetting
	setting.Key = "scan.config.sast.presetName"
	setting.Value = presetName
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ProjectConfigurationSetting{setting})
}

func (c Cx1Client) SetProjectLanguageMode(projectID, languageMode string, allowOverride bool) error {
	c.depwarn("SetProjectLanguageMode", "SetProjectLanguageModeByID")
	return c.SetProjectLanguageModeByID(projectID, languageMode, allowOverride)
}

func (c Cx1Client) SetProjectLanguageModeByID(projectID, languageMode string, allowOverride bool) error {
	var setting ProjectConfigurationSetting
	setting.Key = "scan.config.sast.languageMode"
	setting.Value = languageMode
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ProjectConfigurationSetting{setting})
}

func (c Cx1Client) SetProjectFileFilter(projectID, filter string, allowOverride bool) error {
	c.depwarn("SetProjectFileFilter", "SetProjectFileFilterByID")
	return c.SetProjectFileFilterByID(projectID, filter, allowOverride)
}

func (c Cx1Client) SetProjectFileFilterByID(projectID, filter string, allowOverride bool) error {
	var setting ProjectConfigurationSetting
	setting.Key = "scan.config.sast.filter"
	setting.Value = filter
	setting.AllowOverride = allowOverride

	// TODO - apply the filter across all languages? set up separate calls per engine? engine as param?

	return c.UpdateProjectConfigurationByID(projectID, []ProjectConfigurationSetting{setting})
}

// GetScans returns all scan status on the project addressed by projectID
func (c Cx1Client) GetLastScans(projectID string, limit int) ([]Scan, error) {
	c.depwarn("GetLastScans", "GetLastScansByID")
	return c.GetLastScansByID(projectID, limit)
}

func (c Cx1Client) GetLastScansByID(projectID string, limit int) ([]Scan, error) {
	var scanResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
		Scans              []Scan
	}

	body := url.Values{
		"project-id": {projectID},
		"offset":     {fmt.Sprintf("%d", 0)},
		"limit":      {fmt.Sprintf("%d", limit)},
		"sort":       {"+created_at"},
	}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scans?%v", body.Encode()), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch scans of project %v: %s", projectID, err)
		return scanResponse.Scans, fmt.Errorf("failed to fetch scans of project %v: %s", projectID, err)
	}

	err = json.Unmarshal(data, &scanResponse)
	return scanResponse.Scans, err
}

func (f ScanFilter) AddURLValues(params *url.Values) {
	if f.Offset != 0 {
		params.Add("offset", strconv.Itoa(f.Offset))
	}
	if f.Limit != 0 {
		params.Add("limit", strconv.Itoa(f.Limit))
	}

	for _, b := range f.Branches {
		params.Add("branches", b)
	}
	for _, k := range f.TagKeys {
		params.Add("tags-keys", k)
	}
	for _, v := range f.TagValues {
		params.Add("tags-values", v)
	}
	for _, s := range f.Statuses {
		params.Add("statuses", s)
	}
}

func (c Cx1Client) GetLastScansByIDFiltered(projectID string, filter ScanFilter) ([]Scan, error) {
	var scanResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
		Scans              []Scan
	}

	query := url.Values{
		"project-id": {projectID},
		"sort":       {"+created_at"},
	}

	filter.AddURLValues(&query)

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scans?%v", query.Encode()), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch scans of project %v: %s", projectID, err)
		return scanResponse.Scans, fmt.Errorf("failed to fetch scans of project %v: %s", projectID, err)
	}

	err = json.Unmarshal(data, &scanResponse)
	return scanResponse.Scans, err
}

// GetScans returns all scan status on the project addressed by projectID
func (c Cx1Client) GetLastScansByStatus(projectID string, limit int, status []string) ([]Scan, error) {
	c.depwarn("GetLastScansByStatus", "GetLastScansByStatusAndID")
	return c.GetLastScansByStatusAndID(projectID, limit, status)
}
func (c Cx1Client) GetLastScansByStatusAndID(projectID string, limit int, status []string) ([]Scan, error) {
	var scanResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
		Scans              []Scan
	}
	body := url.Values{
		"project-id": {projectID},
		"offset":     {fmt.Sprintf("%d", 0)},
		"limit":      {fmt.Sprintf("%d", limit)},
		"sort":       {"+created_at"},
		"statuses":   status,
	}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scans?%v", body.Encode()), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch scans of project %v: %s", projectID, err)
		return scanResponse.Scans, fmt.Errorf("failed to fetch scans of project %v: %s", projectID, err)
	}

	//c.logger.Infof( "Returned: %v", string(data) )

	err = json.Unmarshal(data, &scanResponse)
	return scanResponse.Scans, err
}

// convenience
func (c Cx1Client) GetProjectCount() (uint64, error) {
	c.logger.Debug("Get Cx1 Projects")
	var ProjectResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
	}

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", 1)},
		//"sort":       {"+created_at"},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects?%v", body.Encode()), nil, nil)

	if err != nil {
		return 0, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	return ProjectResponse.TotalCount, err
}

func (c Cx1Client) GetProjectCountByName(name string) (uint64, error) {
	c.logger.Debug("Get Cx1 Projects")
	var ProjectResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
	}

	body := url.Values{
		//"offset":     {fmt.Sprintf("%d", 0)},
		"limit": {fmt.Sprintf("%d", 1)},
		"name":  {name},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects?%v", body.Encode()), nil, nil)

	if err != nil {
		return 0, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	return ProjectResponse.FilteredTotalCount, err
}

func (c Cx1Client) ProjectLink(p *Project) string {
	return fmt.Sprintf("%v/projects/%v/overview", c.baseUrl, p.ProjectID)
}

func (c Cx1Client) UpdateProject(project *Project) error {
	c.logger.Debugf("Updating project %v", project.String())

	jsonBody, err := json.Marshal(project)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/projects/%v", project.ProjectID), bytes.NewReader(jsonBody), nil)
	return err
}

func (c Cx1Client) DeleteProject(p *Project) error {
	c.logger.Debugf("Deleting Project %v", p.String())

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/projects/%v", p.ProjectID), nil, nil)
	if err != nil {
		return fmt.Errorf("deleting project %v failed: %s", p.String(), err)
	}

	return nil
}

func (p *Project) AssignGroup(group *Group) {
	if p.IsInGroup(group) {
		return
	}
	p.Groups = append(p.Groups, group.GroupID)
}

func (c Cx1Client) GetOrCreateProject(name string) (Project, error) {
	c.depwarn("GetOrCreateProject", "GetOrCreateProjectByName")
	return c.GetOrCreateProjectByName(name)
}

func (c Cx1Client) GetOrCreateProjectByName(name string) (Project, error) {
	project, err := c.GetProjectByName(name)
	if err == nil {
		return project, nil
	}

	return c.CreateProject(name, []string{}, map[string]string{})
}

func (p Project) GetConfigurationByName(configKey string) *ProjectConfigurationSetting {
	for id := range p.Configuration {
		if p.Configuration[id].Key == configKey {
			return &(p.Configuration[id])
		}
	}
	return nil
}

/* misc future stuff

Listing of files in a scan:
	https://deu.ast.checkmarx.net/api/repostore/project-tree/74328f1f-94ec-452f-8f1a-047d76f6764e
*/
