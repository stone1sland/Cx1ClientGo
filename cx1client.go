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
    "strconv"
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
	GroupID string          `json:"id"`
	Name string
//	Path string // ignoring for now
//  SubGroups string // ignoring for now
}


type Preset struct {
	PresetID            uint64        `json:"id"`
	Name                string         `json:"name"`
    Filled              bool
    Queries             []Query       
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
    Criticality         uint                `json:"criticality"`
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
	QueryID             uint64      `json:"queryID,string"`
	Name                string      `json:"queryName"`
    Group               string
    Language            string
    Severity            string
    CweID               int64    
    QueryDescriptionId  int64
    Custom              bool
}

type QueryGroup struct {
    Name                string
    Language            string
    Queries             []*Query
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

type ResultsPredicates struct {
    PredicateID string              `json:"ID"`
    SimilarityID int64              `json:"similarityId,string"`
    ProjectID   string              `json:"projectId"`
    State       string              `json:"state"`
    Comment     string              `json:"comment"`
    Severity    string              `json:"severity"`
    CreatedBy   string
    CreatedAt   string 
}

type KeyCloakClient struct {
    ClientID    string              `json:"id"`
    Name        string              `json:"clientId"`
    Enabled     bool
}
type Role struct {
    RoleID      string              `json:"id"`
    Name        string
    Description string
    Attributes  struct {
        Creator     []string
        Type        []string
        Category    []string
        LastUpdate  []string // it is returned as [ "uint",... ]            
    }
    Composite   bool
    ClientRole  bool
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
    LOC             uint64
    FileCount       uint64
    IsIncremental   bool
    IsIncrementalCanceled bool
    PresetName      string `json:"queryPreset"`
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
    Line            uint64
    Name            string
    Column          uint64
    Length          uint64
    Method          string
    NodeID          uint64
    DOMType         string
    FileName        string
    FullName        string
    TypeName        string
    MethodLine      uint64
    Definitions     string 
}

type ScanResult struct {
    Type            string
    ResultID        string              `json:"id"`
    SimilarityID    int64               `json:"similarityId,string"`
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

type ScanResultStatusSummary struct {
    ToVerify        uint64
    NotExploitable  uint64
    Confirmed       uint64
    ProposedNotExploitable uint64
    Urgent          uint64
}

type ScanResultSummary struct {
    High        ScanResultStatusSummary
    Medium      ScanResultStatusSummary
    Low         ScanResultStatusSummary
    Information ScanResultStatusSummary
}

// Very simplified for now
type ScanSummary struct {
    TenantID            string
    ScanID              string
    SASTCounters        struct {
        //QueriesCounters           []?
        //SinkFileCounters          []?
        LanguageCounters    []struct{
            Language        string
            Counter         uint64
        }
        ComplianceCounters  []struct{
            Compliance      string
            Counter         uint64
        }
        SeverityCounters    []struct{
            Severity        string
            Counter         uint64
        }
        StatusCounters      []struct{
            Status          string
            Counter         uint64
        }
        StateCounters       []struct{
            State           string
            Counter         uint64
        }
        TotalCounter        uint64
        FilesScannedCounter uint64
    }
    // ignoring the other counters
    // KICSCounters
    // SCACounters
    // SCAPackagesCounters
    // SCAContainerCounters
    // APISecCounters
}

type Status struct {
    ID      int                 `json:"id"`
    Name    string              `json:"name"`
    Details ScanStatusDetails   `json:"details"`
}

type User struct {
	UserID string               `json:"id"`
	FirstName string
	LastName string
	UserName string
    Email   string
}

type WorkflowLog struct {
    Source              string              `json:"Source"`
    Info                string              `json:"Info"`
    Timestamp           string              `json:"Timestamp"`
}

var astAppID string

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
        if jsonBody["access_token"] == nil {
            logger.Errorf( "Response does not contain access token: %v", string(resBody) )
            return "", errors.New( "Response does not contain access token" )
        } else {
		    return jsonBody["access_token"].(string), nil
        }
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

	
	logger.Infof( "Authenticating with Cx1 at: %v", login_url )

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
        if jsonBody["access_token"] == nil {
            logger.Errorf( "Response does not contain access token: %v", string(resBody) )
            return "", errors.New( "Response does not contain access token" )
        } else {
		    return jsonBody["access_token"].(string), nil
        }
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
    var bodyBytes []byte

    c.logger.Debugf( "Sending request to URL %v", url )

    if body != nil {
        closer := ioutil.NopCloser(body)
        bodyBytes, _ := ioutil.ReadAll(closer)
        requestBody = bytes.NewBuffer(bodyBytes)
        defer closer.Close()
    }

    request, err := c.createRequest( method, url, requestBody, &header, nil )
    if err != nil {
        c.logger.Errorf("Unable to create request: %s", err )
        return []byte{}, err
    }

    response, err := c.httpClient.Do(request)
    if err != nil {
        resBody,_ := ioutil.ReadAll( response.Body )
        c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
        c.logger.Errorf("HTTP request failed with error: %s", err)
        return resBody, err
    }
    if response.StatusCode >= 400 {
        resBody,_ := ioutil.ReadAll( response.Body )
        c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
        c.logger.Errorf("HTTP response indicates error: %v", response.Status )
        return resBody, errors.New( "HTTP Response: " + response.Status )
    }
    
    resBody,err := ioutil.ReadAll( response.Body )

	if err != nil {
        if err.Error() == "remote error: tls: user canceled" {
            c.logger.Warnf( "HTTP request encountered error: %s", err )
            return resBody, nil
        } else {
            c.logger.Errorf( "Error reading response body: %s", err )
        }
        c.logger.Tracef( "Parsed: %v", string(resBody) )
	}

    return resBody, nil
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

// not sure what to call this one? used for /console/ calls, not part of the /realms/ path
func (c *Cx1Client) sendRequestOther(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
    iamurl := fmt.Sprintf("%v%v/%v%v", c.iamUrl, base, c.tenant, url)
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
func (g *Group) String() string {
    return fmt.Sprintf( "[%v] %v", shortenGUID( g.GroupID ), g.Name )
}

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
	c.logger.Debug( "Get Cx1 Groups" )
    var groups []Group
	
    response, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", "/groups?briefRepresentation=true", nil, nil )
    if err != nil {
        return groups, err
    }

    err = json.Unmarshal( response, &groups )
    c.logger.Tracef( "Got %d groups", len(groups) )
    return groups, err
}

func (c *Cx1Client) GetGroupByName (groupname string) (Group, error) {
	c.logger.Debugf( "Get Cx1 Group by name: %v", groupname )
    response, err := c.sendRequestIAM( http.MethodGet,  "/auth/admin", fmt.Sprintf( "/groups?briefRepresentation=true&search=%v", url.PathEscape(groupname)), nil, nil )
    if err != nil {
        return Group{}, err
    }
    var groups []Group
	err = json.Unmarshal( response, &groups )
	
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


// Presets

func (p *Preset) String() string {
    return fmt.Sprintf( "[%d] %v", p.PresetID, p.Name )
}

func (c *Cx1Client) GetPresets () ([]Preset, error) {
	c.logger.Debug( "Get Cx1 Presets" )
    var presets []Preset
    response, err := c.sendRequest( http.MethodGet, "/queries/presets", nil, nil )
    if err != nil {
        return presets, err
    }

    err = json.Unmarshal( response, &presets )
    c.logger.Tracef( "Got %d presets", len(presets) )
    return presets, err
}

func (c *Cx1Client) GetPresetContents(p *Preset, queries *[]Query ) error {
    c.logger.Tracef( "Fetching contents for preset %v", p.PresetID )

    if len(*queries) == 0 {
        return errors.New( "Queries list is empty" )
    }

    response, err := c.sendRequest( http.MethodGet, fmt.Sprintf( "/presets/%v", p.PresetID ), nil, nil )
    if err != nil {
        return err
    }

    var PresetContents struct {
        ID              uint64
        Name            string
        Description     string
        Custom          bool
        QueryIDs        []string
    }

    err = json.Unmarshal( response, &PresetContents )
    if err != nil {
        return errors.Wrap( err, "Failed to parse preset contents" )
    }

    c.logger.Tracef( "Parsed preset %v with %d queries", PresetContents.Name, len( PresetContents.QueryIDs ) )

    p.Queries = make( []Query, 0 )
    for _, qid := range PresetContents.QueryIDs {
        var u uint64
        u, _ = strconv.ParseUint( qid, 0, 64 )
        q := c.GetQueryByID( u, queries )
        if q != nil {
            p.Queries = append( p.Queries, *q )
            c.logger.Tracef( " - linked query: %v", q.String() )
        }
    }

    p.Filled = true
    return nil
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

func (p *Project) String() string {
    return fmt.Sprintf( "[%v] %v (%v)", p.ProjectID, p.Name, p.GetTags() )
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

func (c *Cx1Client) GetProjects() ([]Project, error) {
	c.logger.Debug( "Get Cx1 Projects" )
    var ProjectResponse struct {
        TotalCount          uint64
        FilteredCount       uint64
        Projects            []Project
    }
	
    response, err := c.sendRequest( http.MethodGet, "/projects/", nil, nil )
    if err != nil {
        return ProjectResponse.Projects, err
    }

    err = json.Unmarshal( response, &ProjectResponse )
    c.logger.Tracef( "Retrieved %d projects",  len(ProjectResponse.Projects) )
    return ProjectResponse.Projects, err	
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
func (c *Cx1Client) GetProjectByName( projectname string ) (Project,error) {
	c.logger.Debugf( "Get Cx1 Project By Name: %v", projectname )
    response, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/projects?name=%v", url.QueryEscape(projectname)), nil, nil )
    if err != nil {
        return Project{}, err
    }
    var ProjectResponse struct {
        TotalCount          uint64
        FilteredCount       uint64
        Projects            []Project
    }

	err = json.Unmarshal( response, &ProjectResponse )
    if err != nil {
        c.logger.Errorf( "Error getting project: %s", err )
        c.logger.Tracef( "Failed to unmarshal: %v", string(response) )
        return Project{}, err
    }

	c.logger.Tracef( "Retrieved %d projects", len(ProjectResponse.Projects) ) 

	for i := range ProjectResponse.Projects {
		if ProjectResponse.Projects[i].Name == projectname {
			match := ProjectResponse.Projects[i]
			return match, nil
		}
	}

	return Project{}, errors.New( "No such project found" )
}
func (c *Cx1Client) GetProjectsByNameAndGroup(projectName, groupID string) ([]Project, error) {
    c.logger.Debugf("Getting projects with name %v of group ID %v...", projectName, groupID)
    
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
    c.logger.Tracef("Retrieved %d projects matching %v in group ID %v", len(projectResponse.Projects), projectName, groupID )

    return projectResponse.Projects, err
}

func (c *Cx1Client) GetScanResults(scanID string, limit uint64) ([]ScanResult, error) {
	c.logger.Debug( "Get Cx1 Scan Results" )
    var resultResponse struct {
        Results         []ScanResult
        TotalCount      int
    }
    
    params := url.Values{
        "scan-id":   {scanID},
        "limit":    {fmt.Sprintf( "%d", limit )},
        "state":    []string{},
        "severity": []string{},
        "status":   []string{},
    }
    	
    response, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/results/?%v", params.Encode()), nil, nil )
    if err != nil && len(response) == 0 {
        c.logger.Errorf( "Failed to retrieve scan results for scan ID %v", scanID )
        return []ScanResult{}, err
    }

    err = json.Unmarshal( response, &resultResponse )
    if err != nil {
        c.logger.Errorf( "Failed while parsing response: %s", err )
        c.logger.Tracef( "Response contents: %s", string(response) )
        return []ScanResult{}, err
    }
    c.logger.Debugf( "Retrieved %d results", resultResponse.TotalCount )

    if len(resultResponse.Results) != resultResponse.TotalCount {
        c.logger.Warnf( "Expected results total count %d but parsed only %d", resultResponse.TotalCount, len( resultResponse.Results ) )
        c.logger.Warnf( "Response was: %v", string(response) )
    }

    return resultResponse.Results, nil	
}

// results
func (c *Cx1Client) AddResultsPredicates( predicates []ResultsPredicates ) error {
    c.logger.Debugf( "Adding %d results predicates", len( predicates ) )

    jsonBody, err := json.Marshal( predicates )
    if err != nil {
        c.logger.Errorf( "Failed to add results predicates: %s", err )
        return err
    }

    _, err = c.sendRequest( http.MethodPost, "/sast-results-predicates", bytes.NewReader( jsonBody ), nil )
    return err
}

func (c *Cx1Client) GetResultsPredicates( SimilarityID int64, ProjectID string ) ([]ResultsPredicates, error) {
    c.logger.Debugf( "Fetching results predicates for project %v similarityId %d", ProjectID, SimilarityID )

    var Predicates struct {
        PredicateHistoryPerProject []struct {
            ProjectID       string
            SimilarityID    int64           `json:"similarityId,string"`
            Predicates      []ResultsPredicates
            TotalCount      uint
        }

        TotalCount      uint
    }
    response, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/sast-results-predicates/%d?project-ids=%v", SimilarityID, ProjectID ), nil, nil )
    if err != nil {
        return []ResultsPredicates{}, err
    }

    err = json.Unmarshal( response, &Predicates )
    if err != nil {
        return []ResultsPredicates{}, err
    }

    if Predicates.TotalCount == 0 {
        return []ResultsPredicates{}, nil
    }

    return Predicates.PredicateHistoryPerProject[0].Predicates, err
}

func (r ScanResult) String() string {
    return fmt.Sprintf( "%v (%d) - %v to %v - in file %v:%d", r.Data.QueryName, r.SimilarityID, r.Data.Nodes[0].Name, r.Data.Nodes[ len(r.Data.Nodes)-1 ].Name, r.Data.Nodes[0].FileName, r.Data.Nodes[0].Line )
}

func addResultStatus( summary *ScanResultStatusSummary, result *ScanResult ) {
    switch result.State {
    case "CONFIRMED":
        summary.Confirmed++
    case "URGENT":
        summary.Urgent++
    case "URGENT ":
        summary.Urgent++
    case "PROPOSED_NOT_EXPLOITABLE":
        summary.ProposedNotExploitable++
    case "NOT_EXPLOITABLE":
        summary.NotExploitable++
    default:
        summary.ToVerify++
    }
}

func (c *Cx1Client) GetScanResultSummary( results []ScanResult ) ScanResultSummary {
    summary := ScanResultSummary{}

    for _, result := range results {
        switch result.Severity {
        case "HIGH":
            addResultStatus(&(summary.High), &result)
        case "MEDIUM":
            addResultStatus(&(summary.Medium), &result)
        case "LOW":
            addResultStatus(&(summary.Low), &result)
        default:
            addResultStatus(&(summary.Information), &result)
        }        
    }

    return summary
}

func (s ScanResultStatusSummary) Total() uint64 {
    return s.ToVerify + s.Confirmed + s.Urgent + s.ProposedNotExploitable + s.NotExploitable
}
func (s ScanResultStatusSummary) String() string {
    return fmt.Sprintf( "To Verify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d", s.ToVerify, s.Confirmed, s.Urgent, s.ProposedNotExploitable, s.NotExploitable )
}
func (s ScanResultSummary) String() string {
    return fmt.Sprintf( "%v\n%v\n%v", fmt.Sprintf( "\tHigh: %v\n\tMedium: %v\n\tLow: %v\n\tInfo: %v", s.High.String(), s.Medium.String(), s.Low.String(), s.Information.String() ),
            fmt.Sprintf( "\tTotal High: %d, Medium: %d, Low: %d, Info: %d", s.High.Total(), s.Medium.Total(), s.Low.Total(), s.Information.Total() ),
            fmt.Sprintf( "\tTotal ToVerify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d", 
                s.High.ToVerify + s.Medium.ToVerify + s.Low.ToVerify + s.Information.ToVerify,
                s.High.Confirmed + s.Medium.Confirmed + s.Low.Confirmed + s.Information.Confirmed,
                s.High.Urgent + s.Medium.Urgent + s.Low.Urgent + s.Information.Urgent,
                s.High.ProposedNotExploitable + s.Medium.ProposedNotExploitable + s.Low.ProposedNotExploitable + s.Information.ProposedNotExploitable,
                s.High.NotExploitable + s.Medium.NotExploitable + s.Low.NotExploitable + s.Information.NotExploitable ) )
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
	c.logger.Debug( "Get Cx1 Queries" )
    var queries []Query

	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.	
	response, err := c.sendRequest( http.MethodGet, "/presets/queries", nil, nil )
    if err != nil {
        return queries, err
    }

    err = json.Unmarshal( response, &queries )
    if err != nil {
        c.logger.Errorf( "Failed to parse %v", string(response) )   
    }
	return queries, err
}

// convenience
func (c *Cx1Client) GetQueryGroups(queries *[]Query) []QueryGroup {
    qgs := make( []QueryGroup, 0 )

    for id, q := range *queries {
        qg := c.GetQueryGroup( q.Group, q.Language, &qgs )
        if qg == nil {
            qgs = append( qgs, QueryGroup{ q.Group, q.Language, []*Query{ &(*queries)[id] } } )
        } else {
            qg.Queries = append( qg.Queries, &(*queries)[id] )
        }
    }
    return qgs
}
func (c *Cx1Client) GetQueryGroup( name string, language string, qgs *[]QueryGroup ) *QueryGroup {
    for id, qg := range *qgs {
        if qg.Name == name {
            return &(*qgs)[id]
        }
    }
    return nil
}
func (c *Cx1Client) GetQueryByID( qid uint64, queries *[]Query ) *Query {
    for id, q := range *queries {
        if q.QueryID == qid {
            return &(*queries)[id]
        }
    }
    return nil
}
func (q *Query) String() string {
    return fmt.Sprintf( "[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name )
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
                "ScanResult",
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

func (s *ScanSummary) TotalCount() uint64 {
    var count uint64
    count = 0

    for _, c := range s.SASTCounters.StateCounters{
        count += c.Counter
    }

    return count
}

func (c *Cx1Client) GetScanSummary(scanID string) (ScanSummary, error) {
    var ScansSummaries struct {
        ScanSum []ScanSummary               `json:"scansSummaries"`
        TotalCount  uint64
    }

    params := url.Values {
        "scan-ids" : {scanID},
        "include-queries": {"false"},
        "include-status-counters" : {"true"},
        "include-files": {"false"},
    }

    data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scan-summary/?%v", params.Encode() ), nil, http.Header{})
    if err != nil {
        c.logger.Errorf("Failed to fetch metadata for scan with ID %v: %s", scanID, err)
        return ScanSummary{}, errors.Wrapf(err, "failed to fetch metadata for scan with ID %v", scanID)
    }

    err = json.Unmarshal(data, &ScansSummaries)

    if err != nil {
        return ScanSummary{}, err
    }
    if ScansSummaries.TotalCount == 0 {
        return ScanSummary{}, errors.New( fmt.Sprintf( "Failed to retrieve scan summary for scan ID %v", scanID ) )
    }

    if len(ScansSummaries.ScanSum) == 0 {
        c.logger.Errorf( "Failed to parse data, 0-len ScanSum.\n%v", string(data) )
        return ScanSummary{}, errors.New( "Fail" )
    }

    return ScansSummaries.ScanSum[0], nil
}

// GetScans returns all scan status on the project addressed by projectID
func (c *Cx1Client) GetLastScans(projectID string, limit int ) ([]Scan, error) {
    var scanResponse struct {
        TotalCount          uint64
        FilteredTotalCount  uint64 
        Scans               []Scan
    }

    body := url.Values{
        "project-id": {projectID},
        "offset":     {fmt.Sprintf("%d",0)},
        "limit":      {fmt.Sprintf("%d", limit)},
        "sort":        {"+created_at"},
    }

    data, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/scans?%v", body.Encode()), nil, nil )
    if err != nil {
        c.logger.Errorf("Failed to fetch scans of project %v: %s", projectID, err)
        return scanResponse.Scans, errors.Wrapf(err, "failed to fetch scans of project %v", projectID)
    }

    err = json.Unmarshal(data, &scanResponse)
    return scanResponse.Scans, err
}

// GetScans returns all scan status on the project addressed by projectID
func (c *Cx1Client) GetLastScansByStatus(projectID string, limit int, status []string ) ([]Scan, error) {
    var scanResponse struct {
        TotalCount          uint64
        FilteredTotalCount  uint64 
        Scans               []Scan
    }
    body := url.Values{
        "project-id": {projectID},
        "offset":     {fmt.Sprintf("%d",0)},
        "limit":      {fmt.Sprintf("%d", limit)},
        "sort":        {"+created_at"},
        "statuses":     status,
    }

    data, err := c.sendRequest( http.MethodGet, fmt.Sprintf("/scans?%v", body.Encode()), nil, nil )
    if err != nil {
        c.logger.Errorf("Failed to fetch scans of project %v: %s", projectID, err)
        return scanResponse.Scans, errors.Wrapf(err, "failed to fetch scans of project %v", projectID)
    }

    //c.logger.Infof( "Returned: %v", string(data) )

    err = json.Unmarshal(data, &scanResponse)
    return scanResponse.Scans, err
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

// convenience
func (c *Cx1Client) ScanPolling( s *Scan ) (Scan, error) {
	c.logger.Infof( "Polling status of scan %v", s.ScanID )
    var err error
    scan := *s
	for scan.Status == "Running" {
		time.Sleep( 10 * time.Second )
		scan, err = c.GetScan( scan.ScanID )
		if err != nil {
			c.logger.Errorf( "Failed to get scan status: %v", err )
			return scan, err
		}
		c.logger.Infof( " - %v", scan.Status )
        if scan.Status != "Running" {
            break
        }
	}
    return scan, nil
}

func (c *Cx1Client) GetUploadURL () (string,error) {
	c.logger.Debug( "Get Cx1 Upload URL" )
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


func (c *Cx1Client) GetCurrentUser() (User, error) {
    var whoami struct {
        UserID      string
    }
    var user User

    response, err := c.sendRequestOther( http.MethodGet, "/auth/admin", "/console/whoami", nil, nil )
    if err != nil {
        return user, err
    }

    err = json.Unmarshal( response, &whoami )
    if err != nil {
        return user, err
    }

    return c.GetUserByID( whoami.UserID )    
}

func (u *User) String() string {
    return fmt.Sprintf( "[%v] %v %v (%v)", shortenGUID(u.UserID), u.FirstName, u.LastName, u.Email )
}

func (c *Cx1Client) GetUsers () ([]User, error) {
	c.logger.Debug( "Get Cx1 Users" )

    var users []User
    // Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.	
    response, err := c.sendRequestIAM( http.MethodGet,  "/auth/admin", "/users?briefRepresentation=true", nil, nil )
    if err != nil {
        return users, err
    }

    err = json.Unmarshal( response, &users )
    c.logger.Tracef( "Got %d users", len(users) )
    return users, err 
}

func (c *Cx1Client) GetUserByID (userID string) (User, error) {
	c.logger.Debug( "Get Cx1 User by ID" )


    var user User
    // Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.	
    response, err := c.sendRequestIAM( http.MethodGet,  "/auth/admin", fmt.Sprintf("/users/%v?briefRepresentation=true", userID), nil, nil )
    if err != nil {
        return user, err
    }

    err = json.Unmarshal( response, &user )
    return user, err 
}

// Roles and Clients
func (c *Cx1Client) GetClients() ([]KeyCloakClient, error) {
    c.logger.Debug( "Getting KeyCloak Clients" )
    var clients []KeyCloakClient

    response, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", "/clients?briefRepresentation=true", nil, nil )
    if err != nil {
        return clients, err
    }

    err = json.Unmarshal( response, &clients )
    c.logger.Tracef( "Got %d clients", len(clients) )
    return clients, err
}

func (c *Cx1Client) GetClientByName( clientName string ) (KeyCloakClient, error) {
    c.logger.Debugf( "Getting KeyCloak client with name %v", clientName )

    var client KeyCloakClient
    clients, err := c.GetClients()
    if err != nil {
        return client, err
    }

    for _, c := range clients {
        if c.Name == clientName {
            client = c
            return client, nil
        }
    }

    return client, errors.New( "No such client found" )
}

func (r *Role) String() string {
    return fmt.Sprintf( "[%v] %v", shortenGUID( r.RoleID ), r.Name )
}

func (r *Role) HasCategory( name string ) bool {
    for _, role := range r.Attributes.Category {
        if role == name {
            return true
        }
    }
    return false
}

func (c *Cx1Client) GetKeyCloakRoles() ([]Role, error) {
    c.logger.Debugf( "Getting KeyCloak Roles" )
    var roles []Role

    response, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", "/roles?briefRepresentation=true", nil, nil )
    if err != nil {
        return roles, err
    }

    err = json.Unmarshal( response, &roles )
    c.logger.Tracef( "Got %d roles", len(roles) )
    return roles, err
}
func (c *Cx1Client) GetKeyCloakRoleByName( name string) (Role, error) {
    c.logger.Debugf( "Getting KeyCloak Role named %v", name )
    var role Role
    response, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", fmt.Sprintf("/roles/%v", url.QueryEscape(name) ), nil, nil )
    if err != nil {
        return role, err
    }

    err = json.Unmarshal( response, &role )
    return role, err
}

func (c *Cx1Client) GetRolesByClient(clientId string) ([]Role, error) {
    c.logger.Debugf( "Getting KeyCloak Roles for client %v", clientId )
    var roles []Role

    response, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", fmt.Sprintf( "/clients/%v/roles?briefRepresentation=true", clientId ), nil, nil )
    if err != nil {
        return roles, err
    }

    err = json.Unmarshal( response, &roles )
    c.logger.Tracef( "Got %d roles", len(roles) )
    return roles, err
}

func (c *Cx1Client) GetRoleByClientAndName(clientId string, name string) (Role, error) {
    c.logger.Debugf( "Getting KeyCloak Roles for client %v with name %v", clientId, name )
    var role Role

    response, err := c.sendRequestIAM( http.MethodGet, "/auth/admin", fmt.Sprintf( "/clients/%v/roles/%v", clientId, url.PathEscape(name) ), nil, nil )
    if err != nil {
        return role, err
    }

    err = json.Unmarshal( response, &role )
    return role, err
}

func (c *Cx1Client) CreateASTRole(roleName, createdBy string) (Role, error) {
    c.logger.Debugf( "User %v creating client role %v", createdBy, roleName )
    data := map[string]interface{} {
		"name" : roleName,
        "composite" : true,
        "clientRole" : true,
        "attributes" : map[string]interface{}{
            "category" : []string{ "Composite role" },
            "type" : []string{ "Role" },
            "creator" : []string{ fmt.Sprintf( "SAST2CX1 by %v", createdBy ) },
            "lastUpdate" : []int64{ time.Now().UnixMilli() },
        },
	}
    jsonBody, err := json.Marshal( data )
    if err != nil {
        c.logger.Errorf( "Failed to marshal data somehow: %s", err )
        return Role{}, err
    }
    _, err = c.sendRequestIAM( http.MethodPost, "/auth/admin", fmt.Sprintf( "/clients/%v/roles", c.GetASTAppID() ), bytes.NewReader(jsonBody), nil )
    if err != nil {
        c.logger.Errorf( "Failed to create a client role: %s", err )
        return Role{}, err
    }

    return c.GetRoleByClientAndName( c.GetASTAppID(), roleName ) 
}

// convenience function
func (c *Cx1Client) GetASTAppID() string {
    if astAppID == "" {
        client, err := c.GetClientByName( "ast-app" )
        if err != nil {
            c.logger.Warnf( "Error finding AST App ID: %s", err )
            return ""
        }

        astAppID = client.ClientID
    } 

    return astAppID
}

func (c *Cx1Client) GetASTRoles() ([]Role, error) {
    c.logger.Debug( "Getting roles set for ast-app client" )
    return c.GetRolesByClient( c.GetASTAppID() )
}

func (c *Cx1Client) GetASTRoleByName(name string) (Role, error) {
    c.logger.Debugf( "Getting role named %v in ast-app client", name )
    return c.GetRoleByClientAndName( c.GetASTAppID(), name )
}

// convenience function to get both KeyCloak (system) roles plus the AST-APP-specific roles
func (c *Cx1Client) GetCombinedRoles() ([]Role, error) {
    c.logger.Debug( "Getting System (KeyCloak) and Application (AST-APP) roles" )
    ast_roles, err := c.GetASTRoles()
    if err != nil {
        return ast_roles, err
    }
    system_roles, err := c.GetKeyCloakRoles()
    if err != nil {
        return ast_roles, err
    }

    ast_roles = append( ast_roles, system_roles... )
    return ast_roles, nil
}
func (c *Cx1Client) GetCombinedRoleByName( name string ) (Role, error) {
    c.logger.Debug( "Getting System (KeyCloak) and Application (AST-APP) role named: %v", name )

    role, err := c.GetASTRoleByName( name )
    if err == nil {
        return role, nil
    }
    role, err = c.GetKeyCloakRoleByName( name )
    if err == nil {
        return role, nil
    }

    return Role{}, errors.New( "Role not found" )
}




func (c *Cx1Client) String() string {
	return fmt.Sprintf( "%v on %v with token: %v", c.tenant, c.baseUrl, shortenGUID(c.authToken)  )
}


func (c *Cx1Client) ProjectLink( p *Project ) string {
    return fmt.Sprintf( "%v/projects/%v/overview", c.baseUrl, p.ProjectID )
}
func (c *Cx1Client) PresetLink( p *Preset ) string {
    return fmt.Sprintf( "%v/resourceManagement/presets?presetId=%d", c.baseUrl, p.PresetID )
}
func (c *Cx1Client) UserLink( u *User ) string {
    return fmt.Sprintf( "%v/auth/admin/%v/console/#/realms/%v/users/%v", c.iamUrl, c.tenant, c.tenant, u.UserID )
}
func (c *Cx1Client) RoleLink( r *Role ) string {
    return fmt.Sprintf( "%v/auth/admin/%v/console/#/realms/%v/roles/%v", c.iamUrl, c.tenant, c.tenant, r.RoleID )
}
func (c *Cx1Client) GroupLink( g *Group ) string {
    return fmt.Sprintf( "%v/auth/admin/%v/console/#/realms/%v/groups/%v", c.iamUrl, c.tenant, c.tenant, g.GroupID )
}

func shortenGUID( guid string ) string {
    return fmt.Sprintf( "%v..%v", guid[:2], guid[len(guid)-2:] )
}
