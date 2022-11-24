package Cx1ClientGo

import (
    "fmt"
    "io"
    "net/http"
	"time"
	"net/url"
	"io/ioutil"
	"strings"
	"encoding/json"
	"bytes"
    "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)


var cxOrigin = "Cx1-Golang-Client"

func init() {
	
}

type Cx1Client struct {
	httpClient *http.Client
	authToken string
	baseUrl string
	iamUrl string
	tenant string
    logger  *logrus.Logger
}

type Group struct {
	GroupID string
	Name string
//	Path string // ignoring for now
//  SubGroups string // ignoring for now
}


type Preset struct {
	PresetID int        `yaml:"id"`
	Name string         `yaml:"name"`
}



type Project struct {
    ProjectID           string              `json:"id"`
    Name                string              `json:"name"`
    CreatedAt           string              `json:"createdAt"`
    UpdatedAt           string              `json:"updatedAt"`
    Groups              []string            `json:"groups"`
    Tags                map[string]string   `json:"tags"`
    RepoUrl             string              `json:"repoUrl"`
    MainBranch          string              `json:"mainBranch"`
    Origin              string              `json:"origin"`
    Criticality         int                 `json:"criticality"`
}

type ProjectConfigurationSetting struct {
    Key                 string              `json:"key"`
    Name                string              `json:"name"`
    Category            string              `json:"category"`
    OriginLevel         string              `json:"originLevel"`
    Value               string              `json:"value"`
    ValueType           string              `json:"valuetype"`
    ValueTypeParams     string              `json:"valuetypeparams"`
    AllowOverride       bool                `json:"allowOverride"`
}

type Query struct {
	QueryID uint64
	Name string
}

type ReportStatus struct {
    ReportID            string              `json:"reportId"`
    Status              string              `json:"status"`
    ReportURL           string              `json:"url"`
}

type RunningScan struct {
	ScanID string
	Status string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Scan struct {
    ScanID   string  `json:"id"`
    Status string `json:"status"`
    StatusDetails []ScanStatusDetails  `json:"statusDetails"`
    Branch string `json:"branch"`
    CreatedAt string `json:"createdAt"`
    UpdatedAt string `json:"updatedAt"`
    ProjectID string `json:"projectId"`
    ProjectName string `json:"projectName"`
    UserAgent string `json:"userAgent"`
    Initiator string `json:"initiator"`
    Tags map[string]string `json:"tags"`
    Metadata struct {
        Type string `json:"type"`
        Configs []ScanConfiguration `json:"configs"`
    } `json:"metadata"`
    Engines []string `json:"engines"`
    SourceType string `json:"sourceType"`
    SourceOrigin string `json:"sourceOrigin"`
}

type ScanConfiguration struct {
    ScanType string `json:"type"`
    Values map[string]string `json:"value"`
}

type ScanMetadata struct {
    scanID          string
    ProjectID       string
    Local           uint64
    fileCount       uint64
    IsIncremental   bool
    IsIncrementalCanceled bool
    PresetName      string
}

type ScanResultData struct {
    QueryID         uint64
    QueryName       string
    Group           string
    ResultHash      string
    LanguageName    string
    Nodes           []ScanResultNodes
}

type ScanResultNodes struct {
    ID              string
    Line            int
    Name            string
    Column          int
    Length          int
    Method          string
    NodeID          int
    DOMType         string
    FileName        string
    FullName        string
    TypeName        string
    MethodLine      int
    Definitions     string 
}

type ScanResults struct {
    Type            string
    ResultID        string              `json:"id"`
    SimilarityID    string
    Status          string
    State           string
    Severity        string
    CreatedAt       string              `json:"created"`
    FirstFoundAt    string
    FoundAt         string
    FirstScanId     string
    Description     string
    Data            ScanResultData
    VulnerabilityDetails ScanResultDetails 
}

type ScanResultDetails struct {
    CweId           int
    Compliances     []string
}

type ScanStatusDetails struct {
    Name            string `json:"name"`
    Status          string `json:"status"`
    Details         string `json:"details"`
}

type Status struct {
    ID      int                 `json:"id"`
    Name    string              `json:"name"`
    Details ScanStatusDetails   `json:"details"`
}

type User struct {
	UserID string
	FirstName string
	LastName string
	UserName string
}

type WorkflowLog struct {
    Source              string              `json:"Source"`
    Info                string              `json:"Info"`
    Timestamp           string              `json:"Timestamp"`
}


// Main entry for users of this client:
func NewOAuthClient( client *http.Client, base_url string, iam_url string, tenant string, client_id string, client_secret string, logger *logrus.Logger ) (*Cx1Client, error) {
    token, err := getTokenOIDC( client, iam_url, tenant, client_id, client_secret, logger )
    if err != nil {
        return nil, err
    }
	cli := Cx1Client{ client, token, base_url, iam_url, tenant, logger }
	return &cli, nil
}

func NewAPIKeyClient(client *http.Client, base_url string, iam_url string, tenant string, api_key string, logger *logrus.Logger ) (*Cx1Client, error) {
    token, err := getTokenAPIKey( client, iam_url, tenant, api_key, logger )
    if err != nil {
        return nil, err
    }

	cli := Cx1Client{ client, token, base_url, iam_url, tenant, logger }
	return &cli, nil
}


func getTokenOIDC( client *http.Client, iam_url string, tenant string, client_id string, client_secret string, logger *logrus.Logger ) (string, error) {
	login_url := fmt.Sprintf( "%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant )
	
	data := url.Values{}
	data.Set( "grant_type", "client_credentials" )
	data.Set( "client_id", client_id )
	data.Set( "client_secret", client_secret )

	
	logger.Infof( "Authenticating with Cx1 at: %v", login_url )

	cx1_req, err := http.NewRequest(http.MethodPost, login_url, strings.NewReader(data.Encode()))
	cx1_req.Header.Add( "Content-Type", "application/x-www-form-urlencoded" )
	if err != nil {
		logger.Errorf( "Error: %s", err )
		return "", err
	}

	res, err := client.Do( cx1_req );
	defer res.Body.Close()

	if err != nil {
		logger.Errorf( "Error: %s", err )
		return "", err
	}

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		logger.Errorf( "Error: %s", err )
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if ( err == nil ) {
		return jsonBody["access_token"].(string), nil
	} else {
		logger.Errorf( "Error parsing response: %s", err )
		logger.Tracef( "Input was: %s", string(resBody) )
		return "", err
	}
}

func getTokenAPIKey( client *http.Client, iam_url string, tenant string, api_key string, logger *logrus.Logger ) (string, error) {
	login_url := fmt.Sprintf( "%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant )
	
	data := url.Values{}
	data.Set( "grant_type", "refresh_token" )
	data.Set( "client_id", "ast-app" )
	data.Set( "refresh_token", api_key )

	
	logger.Info( "Authenticating with Cx1 at: %v", login_url )

	cx1_req, err := http.NewRequest(http.MethodPost, login_url, strings.NewReader(data.Encode()))
	cx1_req.Header.Add( "Content-Type", "application/x-www-form-urlencoded" )
	if err != nil {
		logger.Errorf( "Error: %s", err )
		return "", err
	}
	
	res, err := client.Do( cx1_req );
	if err != nil {
		logger.Errorf( "Error: %s", err )
		return "", err
	}
    defer res.Body.Close()

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		logger.Errorf( "Error: %s", err )
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if ( err == nil ) {
		return jsonBody["access_token"].(string), nil
	} else {
		logger.Errorf( "Error parsing response: %s", err )
		logger.Tracef( "Input was: %v", string(resBody) )
		return "", err
	}
}

func (c *Cx1Client) GetToken() string {
    return c.authToken
}

func (c *Cx1Client) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

    for name, headers := range *header {
        for _, h := range headers {
            request.Header.Add(name, h)
        }
    }

    request.Header.Set( "Authorization", fmt.Sprintf("Bearer %v", c.authToken ) )
    if request.Header.Get("User-Agent") == "" {
        request.Header.Set( "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0" )
    }

    if request.Header.Get("Content-Type") == "" {
        request.Header.Set( "Content-Type", "application/json" )
    }

	return request, nil
}

func (c *Cx1Client) sendRequestInternal(method, url string, body io.Reader, header http.Header) ([]byte, error) {
    var requestBody io.Reader
    var requestBodyCopy io.Reader

    if body != nil {
        closer := ioutil.NopCloser(body)
        bodyBytes, _ := ioutil.ReadAll(closer)
        requestBody = bytes.NewBuffer(bodyBytes)
        requestBodyCopy = bytes.NewBuffer(bodyBytes)
        defer closer.Close()
    }

    request, err := c.createRequest( method, url, requestBody, &header, nil )
    if err != nil {
        c.logger.Errorf("Unable to create request: %s", err )
        return []byte{}, err
    }

    response, err := c.httpClient.Do(request)
    defer response.Body.Close()
    if err != nil || response.StatusCode >= 400 {
        resBody,_ := ioutil.ReadAll( response.Body )
        reqBody,_ := ioutil.ReadAll( requestBodyCopy )
        c.recordRequestDetailsInErrorCase(reqBody, resBody)
        if err != nil {
            c.logger.Errorf("HTTP request failed with error: %s", err)
        } else {
            c.logger.Errorf("HTTP request returned code: %s", response.Status)
        }
        return resBody, err
    }
    
    resBody,err := ioutil.ReadAll( response.Body )

	if err != nil {
		c.logger.Errorf( "Error reading response body: %s", err )
        c.logger.Tracef( "Parsed: %v", string(resBody) )
	}

    return resBody, err
}

// internal calls
func (c *Cx1Client) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
    cx1url := fmt.Sprintf("%v/api%v", c.baseUrl, url)
    return c.sendRequestInternal(method, cx1url, body, header )
}

func (c *Cx1Client) sendRequestIAM(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
    iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.iamUrl, base, c.tenant, url)
    return c.sendRequestInternal(method, iamurl, body, header)
}

func (c *Cx1Client) recordRequestDetailsInErrorCase(requestBody []byte, responseBody []byte ) {
    if len(requestBody) != 0 {
        c.logger.Errorf("Request body: %s", string(requestBody) )
    }
    if len(responseBody) != 0 {
        c.logger.Errorf("Response body: %s", string(responseBody))
    }
}

func (c Cx1Client) PutFile( URL string, filename string ) (string,error) {
	c.logger.Tracef( "Putting file %v to %v", filename, URL )

	fileContents, err := ioutil.ReadFile(filename)
    if err != nil {
    	c.logger.Errorf("Failed to Read the File %v: %s", filename, err)
		return "", err
    }

	cx1_req, err := http.NewRequest(http.MethodPut, URL, bytes.NewReader( fileContents ) )
	if err != nil {
		c.logger.Errorf( "Error: %s", err )
		return "", err
	}

	cx1_req.Header.Add( "Content-Type", "application/zip" )
	cx1_req.Header.Add( "Authorization", fmt.Sprintf("Bearer %v", c.authToken ) )
	cx1_req.ContentLength = int64(len(fileContents))

	res, err := c.httpClient.Do( cx1_req );
	if err != nil {
		c.logger.Errorf( "Error: %s", err )
		return "", err
	}
	defer res.Body.Close()

	
	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		c.logger.Errorf( "Error: %s", err )
		return "", err
	}

	return string(resBody), nil
}


// Groups
func (c *Cx1Client) CreateGroup ( groupname string ) (Group, error) {
	c.logger.Debugf( "Create Group: %v ", groupname  )
	data := map[string]interface{} {
		"name" : groupname,
	}
    jsonBody, err := json.Marshal( data )
    if err != nil {
        return Group{}, err
    }

	_, err = c.sendRequestIAM( http.MethodPost, "/auth/admin", "/groups", bytes.NewReader( jsonBody ), nil )
    if err != nil {
        c.logger.Errorf( "Error creating group: %s", err )
        return Group{}, err
    }

	return c.GetGroupByName( groupname )
}

func (c *Cx1Client) GetGroups () ([]Group, error) {
	c.logger.Debug( "Get Groups" )
    var Groups []Group
	
    response, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", "/groups?briefRepresentation=true", nil, nil )
    if err != nil {
        return Groups, err
    }

    Groups, err = c.parseGroups( response )
    c.logger.Tracef( "Got %d groups", len(Groups) )
    return Groups, err
}

func (c *Cx1Client) GetGroupByName (groupname string) (Group, error) {
	c.logger.Debugf( "Get Group by name: %v", groupname )
    response, err := c.sendRequestIAM( http.MethodGet,  "/auth/admin", fmt.Sprintf( "/groups?briefRepresentation=true&search=%v", url.QueryEscape(groupname)), nil, nil )
    if err != nil {
        return Group{}, err
    }
	groups, err := c.parseGroups( response )
	
    if err != nil {
        c.logger.Errorf( "Error retrieving group: %s", err )
        return Group{}, err
    }

	c.logger.Tracef( "Got %d groups", len(groups) )

	for i := range groups {
		if groups[i].Name == groupname {
			match := groups[i]
			return match, nil
		}
	}
	
	return Group{}, errors.New( "No matching group found" )
}

// New for Cx1
func (c *Cx1Client) GetGroupByID( groupID string ) (Group, error) {
    c.logger.Debugf("Getting Group with ID %v...", groupID)
    var group Group

    body := url.Values {
        "briefRepresentation" : {"true"},
    }

    data, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v?%v", groupID, body.Encode()), nil, http.Header{} )
    if err != nil {
        c.logger.Errorf("Fetching group failed: %s", err)
        return group, err
    }

    err = json.Unmarshal(data, &group)
    return group, err
}


func (c *Cx1Client) GetPresets () ([]Preset, error) {
	c.logger.Debug( "Get Presets" )
    var Presets []Preset
    response, err := c.sendRequest( http.MethodGet, "/queries/presets", nil, nil )
    if err != nil {
        return Presets, err
    }

    Presets, err = c.parsePresets( response )
    c.logger.Tracef( "Got %d presets", len(Presets) )
    return Presets, err
}





// Projects
func (c *Cx1Client) CreateProject ( projectname string, cx1_group_id string, tags map[string]string ) (Project,error) {
	c.logger.Debugf ( "Create Project: %v, group id %v", projectname, cx1_group_id )
	data := map[string]interface{} {
		"name" : projectname,
		"groups" : []string{ cx1_group_id },
		"tags" : tags,
		"criticality" : 3,
		"origin" : "SAST2Cx1",
	}
    jsonBody, err := json.Marshal( data )
    if err != nil {
        return Project{}, err
    }

    var project Project
	response, err := c.sendRequest( http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil )
	if err != nil {
        c.logger.Errorf( "Error while creating project: %s", err )
        return project, err
	}
    
    err = json.Unmarshal( response, &project )        

	return project, err
}

func (c *Cx1Client) GetProjects () ([]Project, error) {
	c.logger.Debug( "Get Projects" )
    var Projects []Project
	
    response, err := c.sendRequest( http.MethodGet, "/projects/", nil, nil )
    if err != nil {
        return Projects, err
    }

    Projects, err = c.parseProjects( response )
    c.logger.Tracef( "Retrieved %d projects",  len(Projects) )
    return Projects, err
	
}
func (c *Cx1Client) GetProjectByID(projectID string) (Project, error) {
    c.logger.Debugf("Getting Project with ID %v...", projectID)
    var project Project

    data, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/projects/%v", projectID), nil, nil )
    if err != nil {
        return project, errors.Wrapf(err, "fetching project %v failed", projectID)
    }

    err = json.Unmarshal( []byte(data) , &project)
    return project, err
}
func (c *Cx1Client) GetProjectByName ( projectname string ) (Project,error) {
	c.logger.Debugf( "Get Project By Name: %v", projectname )
    response, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/projects?name=%v", url.QueryEscape(projectname)), nil, nil )
    if err != nil {
        return Project{}, err
    }

	projects, err := c.parseProjects( response )
    if err != nil {
        c.logger.Errorf( "Error getting project: %s", err )
        return Project{}, err
    }

	c.logger.Tracef( "Retrieved %d projects", len(projects) ) 

	for i := range projects {
		if projects[i].Name == projectname {
			match := projects[i]
			return match, nil
		}
	}

	return Project{}, errors.New( "No such project found" )
}
func (c *Cx1Client) GetProjectsByNameAndGroup(projectName, groupID string) ([]Project, error) {
    c.logger.Debugf("Getting projects with name %v of group %v...", projectName, groupID)
    
    var projectResponse struct {
        TotalCount      int     `json:"totalCount"`
        FilteredCount   int     `json:"filteredCount"`
        Projects        []Project `json:"projects"`
    } 

    var data []byte
    var err error

    body := url.Values{}
    if len(groupID) > 0 {
        body.Add( "groups", groupID )
    }
    if len(projectName) > 0 {
        body.Add( "name", projectName )
    }


    if len(body) > 0 {
        data, err = c.sendRequest( http.MethodGet, fmt.Sprintf("/projects/?%v", body.Encode()), nil, nil )
    } else {
        data, err = c.sendRequest( http.MethodGet, "/projects/", nil, nil )
    }
    if err != nil {
        return projectResponse.Projects, errors.Wrapf(err, "fetching project %v failed", projectName)
    }

    err = json.Unmarshal( data, &projectResponse)
    return projectResponse.Projects, err
}
func (c *Cx1Client) GetScanResults (scanID string) ([]ScanResults, error) {
	c.logger.Debug( "Get Scan Results" )
    var resultResponse struct {
        Results         []ScanResults
        TotalCount      int
    }
    
    params := url.Values{
        "scan-id":   {scanID},
    }
    	
    response, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/results/?%v", params.Encode()), nil, nil )
    if err != nil && len(response) == 0 {
        c.logger.Errorf( "Failed to retrieve scan results for scan ID %v", scanID )
        return []ScanResults{}, err
    }

    err = json.Unmarshal( response, &resultResponse )
    if err != nil {
        c.logger.Errorf( "Failed while parsing response: %s", err )
        c.logger.Tracef( "Response contents: %s", string(response) )
        return []ScanResults{}, err
    }
    c.logger.Debugf( "Retrieved %d results", resultResponse.TotalCount )
    return resultResponse.Results, nil	
}


// New for Cx1
func (c *Cx1Client) GetProjectConfiguration(projectID string) ([]ProjectConfigurationSetting, error) {
    c.logger.Debug("Getting project configuration")
    var projectConfigurations []ProjectConfigurationSetting
    params := url.Values{
        "project-id":   {projectID},
    }
    data, err := c.sendRequest( http.MethodGet, fmt.Sprintf( "/configuration/project?%v", params.Encode() ), nil, nil )

    if err != nil {
        c.logger.Errorf("Failed to get project configuration for project ID %v: %s", projectID, err)
        return projectConfigurations, err
    }

    err = json.Unmarshal( []byte(data), &projectConfigurations )
    return projectConfigurations, err
}

// UpdateProjectConfiguration updates the configuration of the project addressed by projectID
// Updated for Cx1
func (c *Cx1Client) UpdateProjectConfiguration(projectID string, settings []ProjectConfigurationSetting) error {
    if len(settings) == 0 {
        return errors.New("Empty list of settings provided.")
    }

    params := url.Values{
        "project-id":   {projectID},
    }

    jsonBody, err := json.Marshal( settings )
    if err != nil {
        return err
    }

    _, err = c.sendRequest( http.MethodPatch, fmt.Sprintf( "/configuration/project?%v", params.Encode() ), bytes.NewReader( jsonBody ), nil )
    if err != nil {
        c.logger.Errorf( "Failed to update project configuration: %s", err )
        return err
    }

    return nil
}


func (c *Cx1Client) SetProjectBranch( projectID, branch string, allowOverride bool ) error {
    var setting ProjectConfigurationSetting
    setting.Key = "scan.handler.git.branch"
    setting.Value = branch
    setting.AllowOverride = allowOverride

    return c.UpdateProjectConfiguration( projectID, []ProjectConfigurationSetting{setting} )
}

func (c *Cx1Client) SetProjectPreset( projectID, presetName string, allowOverride bool ) error {
    var setting ProjectConfigurationSetting
    setting.Key = "scan.config.sast.presetName"
    setting.Value = presetName
    setting.AllowOverride = allowOverride

    return c.UpdateProjectConfiguration( projectID, []ProjectConfigurationSetting{setting} )
}

func (c *Cx1Client) SetProjectLanguageMode( projectID, languageMode string, allowOverride bool ) error {
    var setting ProjectConfigurationSetting
    setting.Key = "scan.config.sast.languageMode"
    setting.Value = languageMode
    setting.AllowOverride = allowOverride

    return c.UpdateProjectConfiguration( projectID, []ProjectConfigurationSetting{setting} )
}

func (c *Cx1Client) SetProjectFileFilter( projectID, filter string, allowOverride bool ) error {
    var setting ProjectConfigurationSetting
    setting.Key = "scan.config.sast.filter"
    setting.Value = filter
    setting.AllowOverride = allowOverride

    // TODO - apply the filter across all languages? set up separate calls per engine? engine as param?

    return c.UpdateProjectConfiguration( projectID, []ProjectConfigurationSetting{setting} )
}




func (c *Cx1Client) GetQueries () ([]Query, error) {
	c.logger.Debug( "Get Queries" )
    var Queries []Query

	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.	
	//c.Queries = parseQueries( c.sendRequest( http.MethodGet, "/queries" ) )

	return Queries, nil
}


// Reports
func (c *Cx1Client) RequestNewReport(scanID, projectID, branch, reportType string) (string, error) {
    jsonData := map[string]interface{}{
        "fileFormat": reportType,
        "reportType": "ui",
        "reportName": "scan-report",
        "data": map[string]interface{}{
            "scanId":     scanID,
            "projectId":  projectID,
            "branchName": branch,
            "sections": []string{
                "ScanSummary",
                "ExecutiveSummary",
                "ScanResults",
            },
            "scanners": []string{ "SAST" },
            "host":"",
        },
    }
    
    jsonBody, err := json.Marshal( jsonData )
    if err != nil {
        return "", err
    }

    data, err := c.sendRequest( http.MethodPost, "/reports", bytes.NewReader( jsonBody ), nil )
    if err != nil {
        return "", errors.Wrapf(err, "Failed to trigger report generation for scan %v", scanID)
    }

    var reportResponse struct {
        ReportId string
    }
    err = json.Unmarshal( []byte(data), &reportResponse )

    return reportResponse.ReportId, err
}

func (c *Cx1Client) GetReportStatus(reportID string) (ReportStatus, error) {
    var response ReportStatus

    data, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/reports/%v", reportID), nil, nil )
    if err != nil {
        c.logger.Errorf("Failed to fetch report status for reportID %v: %s", reportID, err)
        return response, errors.Wrapf(err, "failed to fetch report status for reportID %v", reportID)
    }

    err = json.Unmarshal( [] byte(data), &response)
    return response, err
}

func (c *Cx1Client) DownloadReport(reportUrl string) ([]byte, error) {

    data, err := c.sendRequestInternal( http.MethodGet, reportUrl, nil, nil )
    if err != nil {
        return []byte{}, errors.Wrapf(err, "failed to download report from url: %v", reportUrl)
    }
    return data, nil
}




// Scans
// GetScans returns all scan status on the project addressed by projectID
// todo cleanup systeminstance
func (c *Cx1Client) GetScan(scanID string) (Scan, error) {
    var scan Scan

    data, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/scans/%v", scanID), nil, nil )
    if err != nil {
        c.logger.Errorf("Failed to fetch scan with ID %v: %s", scanID, err)
        return scan, errors.Wrapf(err, "failed to fetch scan with ID %v", scanID)
    }

    json.Unmarshal( []byte(data), &scan)
    return scan, nil
}

func (c *Cx1Client) GetScanMetadata(scanID string) (ScanMetadata, error) {
    var scanmeta ScanMetadata

    data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-metadata/%v", scanID), nil, http.Header{})
    if err != nil {
        c.logger.Errorf("Failed to fetch metadata for scan with ID %v: %s", scanID, err)
        return scanmeta, errors.Wrapf(err, "failed to fetch metadata for scan with ID %v", scanID)
    }

    json.Unmarshal(data, &scanmeta)
    return scanmeta, nil
}

// GetScans returns all scan status on the project addressed by projectID
func (c *Cx1Client) GetLastScans(projectID string, limit int ) ([]Scan, error) {
    scans := []Scan{}
    body := url.Values{
        "projectId": {projectID},
        "offset":     {fmt.Sprintf("%v",0)},
        "limit":      {fmt.Sprintf("%v", limit)},
        "sort":        {"+created_at"},
    }

    data, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/scans?%v", body.Encode()), nil, nil )
    if err != nil {
        c.logger.Errorf("Failed to fetch scans of project %v: %s", projectID, err)
        return scans, errors.Wrapf(err, "failed to fetch scans of project %v", projectID)
    }

    json.Unmarshal(data, &scans)
    return scans, nil
}

func (c *Cx1Client) scanProject( scanConfig map[string]interface{} ) (Scan, error) {
    scan := Scan{}

    jsonBody, err := json.Marshal( scanConfig )
    if err != nil {
        return scan, err
    }

    data, err := c.sendRequest( http.MethodPost, "/scans", bytes.NewReader( jsonBody ), nil )
    if err != nil {
        return scan, err
    }

    err = json.Unmarshal(data, &scan)
    return scan, err
}

func (c *Cx1Client) ScanProjectZip(projectID, sourceUrl, branch string, settings []ScanConfiguration, tags map[string]string ) (Scan, error) {
    jsonBody := map[string]interface{}{
        "project" : map[string]interface{}{    "id" : projectID },
        "type": "upload",
        "tags": tags,
        "handler" : map[string]interface{}{ 
            "uploadurl" : sourceUrl,
            "branch" : branch,
        },
        "config" : settings,
    }

    scan, err := c.scanProject( jsonBody )
    if err != nil {
        return scan, errors.Wrapf( err, "Failed to start a zip scan for project %v", projectID )
    }
    return scan, err
}

func (c *Cx1Client) ScanProjectGit(projectID, repoUrl, branch string, settings []ScanConfiguration, tags map[string]string ) (Scan, error) {
    jsonBody := map[string]interface{}{
        "project" : map[string]interface{}{    "id" : projectID },
        "type": "git",
        "tags": tags,
        "handler" : map[string]interface{}{ 
            "repoUrl" : repoUrl,
            "branch" : branch,
        },
        "config" : settings,
    }

    scan, err := c.scanProject( jsonBody )
    if err != nil {
        return scan, errors.Wrapf( err, "Failed to start a git scan for project %v", projectID )
    }
    return scan, err
}

// convenience function
func (c *Cx1Client) ScanProject(projectID, sourceUrl, branch, scanType string, settings []ScanConfiguration, tags map[string]string ) (Scan, error) {
    if scanType == "upload" {
        return c.ScanProjectZip( projectID, sourceUrl, branch, settings, tags )
    } else if scanType == "git" {
        return c.ScanProjectGit( projectID, sourceUrl, branch, settings, tags )
    }

    return Scan{}, errors.New( "Invalid scanType provided, must be 'upload' or 'git'" )
}

// convenience function
func (s *Scan) IsIncremental() (bool, error) {
    for _, scanconfig := range s.Metadata.Configs {
        if scanconfig.ScanType == "sast" {
            if val, ok := scanconfig.Values["incremental"]; ok {
                return val=="true", nil
            }
        }
    }
    return false, errors.New( fmt.Sprintf("Scan %v did not have a sast-engine incremental flag set", s.ScanID) )
}



func (c *Cx1Client) GetUploadURL () (string,error) {
	c.logger.Debug( "Get Upload URL" )
	response, err := c.sendRequest( http.MethodPost, "/uploads", nil, nil )

    if err != nil {
        c.logger.Errorf( "Unable to get Upload URL: %s", err )
        return "", err
    } 

	var jsonBody map[string]interface{}

	err = json.Unmarshal( response, &jsonBody )
	if err != nil {
		c.logger.Errorf("Error: %s", err )
		c.logger.Tracef( "Input was: %s", string(response) )
		return "", err
	} else {
		return jsonBody["url"].(string), nil
	}
}




func (c *Cx1Client) GetUsers () ([]User, error) {
	c.logger.Debug( "Get Users" )

    var Users []User
    // Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.	
    response, err := c.sendRequestIAM( http.MethodGet,  "/auth/admin", "/users?briefRepresentation=true", nil, nil )
    if err != nil {
        return Users, err
    }

    Users, err = c.parseUsers( response )
    c.logger.Tracef( "Got %d users", len(Users) )
    return Users, err 
}



func (c *Cx1Client) ToString() string {
	return fmt.Sprintf( "%v on %v with token: %v...%v", c.tenant, c.baseUrl, c.authToken[:4], c.authToken[len(c.authToken)-4:] )
}



// internal data-parsing

func (c *Cx1Client) parseGroups( input []byte ) ([]Group, error) {
	//c.logger.Tracef( "Parsing groups from: %v", string(input) )
	var groups []interface{}

	var groupList []Group

	err := json.Unmarshal( input, &groups )
	if err != nil {
		c.logger.Errorf("Error: %s", err )
		c.logger.Tracef( "Input was: %v", string(input) )
		return groupList, err
	} else {
		groupList = make([]Group, len(groups) )
		for id := range groups {
			groupList[id].GroupID = groups[id].(map[string]interface{})["id"].(string)
			groupList[id].Name = groups[id].(map[string]interface{})["name"].(string)

		}
	}

	return groupList, nil
}



func (c *Cx1Client) parsePresets( input []byte ) ([]Preset, error) {
	//c.logger.Tracef( "Parsing presets from: %v", string(input) )

	var presets []Preset
    var presetResponse []map[string]interface{}
    var err error

    err = json.Unmarshal( []byte( input ), &presetResponse )
    if err != nil {
		c.logger.Errorf("Error: %s", err )
		c.logger.Tracef( "Input was: %v", string(input) )
		return presets, err
	}

    presets = make( []Preset, len(presetResponse) )

    for id, p := range presetResponse {
        presets[id].PresetID = int(p["id"].(float64))
        presets[id].Name = p["name"].(string)
    }

	return presets, nil

}

func (c *Cx1Client) parseProjects( input []byte ) ([]Project, error) {
	//c.logger.Tracef( "Parsing projects from: %v", string(input) )
	var projectResponse struct {
        TotalCount int
        filteredTotalCount int
        Projects []interface{}
    }
    var projectList []Project

	err := json.Unmarshal( []byte( input ), &projectResponse )
	if err != nil {
		c.logger.Errorf("Error: %s", err )
		c.logger.Tracef( "Input was: %v", string(input) )
		return projectList, err
	}

	projects := projectResponse.Projects

	projectList = make([]Project, len(projects) )
	for id := range projects {
		projectList[id].ProjectID = projects[id].(map[string]interface{})["id"].(string)
		projectList[id].Name = projects[id].(map[string]interface{})["name"].(string)
	}
	

	return projectList, nil
}

func (c *Cx1Client) parseRunningScans( input []byte ) ([]RunningScan,error) {
	var scans []RunningScan

	//var scanList []interface{} TODO
	
	return scans, nil
}

func (c *Cx1Client) parseRunningScanFromInterface( input *map[string]interface{} ) (RunningScan, error) {
	//c.logger.Trace( "Parsing scan from interface" )
	scan := RunningScan{}

	scan.ScanID = (*input)["id"].(string)
	scan.ProjectID = (*input)["projectId"].(string)
	scan.Status = (*input)["status"].(string)

	var err error
    var err2 error

	scan.CreatedAt, err = time.Parse(time.RFC3339, (*input)["createdAt"].(string) )

	if err != nil {
		c.logger.Warnf( "Failed to parse time from %v", (*input)["createdAt"].(string) )
	}



	scan.UpdatedAt, err2 = time.Parse(time.RFC3339, (*input)["updatedAt"].(string) )

	if err2 != nil {
		c.logger.Warnf( "Failed to parse time from %v", (*input)["updatedAt"].(string) )
        err = errors.Wrap( err, err2.Error() )
	}

	return scan, err
}

func (c *Cx1Client) parseUsers( input []byte ) ([]User, error) {
	//c.logger.Tracef( "Parsing users from: %v", string(input) )
	var users []map[string]interface{}

	var userList []User

	err := json.Unmarshal( []byte( input ), &users )
	if err != nil {
		c.logger.Errorf("Error: %s", err )
		c.logger.Tracef( "Input was: %v", string(input) )
		return userList, err
	} else {
		userList = make([]User, 0 )
		
		for _, u := range users {
			user, err := c.parseUserFromInterface( &u )			
			if err != nil {
                c.logger.Errorf("Failed to parse user: %s", err )

            } else {
				userList = append( userList, user )
			}
		}
	}

	return userList, nil
}

func (c *Cx1Client) parseUserFromInterface( input *map[string]interface{} ) (User, error) {
	c.logger.Trace( "Parsing user from interface" )
    var user User

	if (*input)["id"] == nil {
		return user, errors.New( "No id variable in input" )
	}

	user.UserID = (*input)["id"].(string)

	if (*input)["firstName"] != nil {
		user.FirstName = (*input)["firstName"].(string)
	}

	if (*input)["lastName"] != nil {	
		user.LastName = (*input)["lastName"].(string)
	}

	user.UserName = (*input)["username"].(string)

	return user, nil
}

