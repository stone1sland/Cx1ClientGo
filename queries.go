package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (c Cx1Client) GetQueryByID(qid uint64) (Query, error) {
	return Query{}, fmt.Errorf("this API call no longer exists")
	/*
		var q Query
		// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.
		response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/queries/%d", qid), nil, nil)
		if err != nil {
			return q, err
		}
		err = json.Unmarshal(response, &q)
		if err != nil {
			c.logger.Tracef("Failed to parse %v", string(response))
		}
		return q, err*/
}

func (c Cx1Client) GetQueryByName(level, language, group, query string) (AuditQuery, error) {
	c.logger.Debugf("Get %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/queries/%v/%v.cs", level, path), nil, nil)
	if err != nil {
		return AuditQuery{}, err
	}

	var q AuditQuery
	err = json.Unmarshal(response, &q)
	if err != nil {
		return q, err
	}
	q.ParsePath()
	q.LevelID = level
	return q, nil
}

func (c Cx1Client) GetQueriesByLevelID(level, levelId string) ([]AuditQuery, error) {
	c.logger.Debugf("Get all queries for %v", level)

	var url string
	var queries []AuditQuery
	switch level {
	case "Corp":
		url = "/cx-audit/queries"
	case "Project":
		url = fmt.Sprintf("/cx-audit/queries?projectId=%v", levelId)
	default:
		return queries, fmt.Errorf("invalid level %v, options are currently: Corp or Project", level)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return queries, err
	}

	err = json.Unmarshal(response, &queries)
	if err != nil {
		return queries, err
	}

	for id := range queries {
		queries[id].ParsePath()
	}

	return queries, nil
}

func FindQueryByName(queries []AuditQuery, level, language, group, name string) (AuditQuery, error) {
	for _, q := range queries {
		if q.Level == level && q.Language == language && q.Group == group && q.Name == name {
			return q, nil
		}
	}

	return AuditQuery{}, fmt.Errorf("no query found matching [%v] %v -> %v -> %v", level, language, group, name)
}

func (c Cx1Client) DeleteQuery(query AuditQuery) error {
	return c.DeleteQueryByName(query.Level, query.LevelID, query.Language, query.Group, query.Name)
}

func (c Cx1Client) DeleteQueryByName(level, levelID, language, group, query string) error {
	c.logger.Debugf("Delete %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/cx-audit/queries/%v/%v.cs", levelID, path), nil, nil)
	if err != nil {
		// currently there's a bug where the response can be error 500 even if it succeeded.

		q, err2 := c.GetQueryByName(levelID, language, group, query)
		if err2 != nil {
			c.logger.Warnf("error while deleting query (%s) followed by error while checking if the query was deleted (%s) - assuming the query was deleted", err, err2)
			return nil
		}

		if q.Level != level {
			c.logger.Warnf("While deleting the query an error was returned (%s) but the query was deleted", err)
			return nil
		} else {
			return fmt.Errorf("error while deleting query (%s) and the query %v still exists", err, q)
		}
	}

	return nil
}

func (c Cx1Client) AuditCreateSessionByID(projectId, scanId string) (string, error) {
	c.logger.Debugf("Trying to create audit session for project %v scan %v", projectId, scanId)
	available, _, err := c.AuditFindSessionsByID(projectId, scanId)
	if err != nil {
		return "", err
	}

	if !available {
		return "", fmt.Errorf("audit session not available")
	}

	body := map[string]interface{}{
		"projectId": projectId,
		"scanId":    scanId,
		"time":      30,
		"fromZip":   false,
	}

	jsonBody, _ := json.Marshal(body)

	response, err := c.sendRequest(http.MethodPost, "/cx-audit/sessions", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", err
	}

	var responseStruct struct {
		Id     string `json:"id"`
		Status string `json:"status"`
		ScanId string `json:"scanId"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return "", err
	}

	if responseStruct.Status == "ALLOCATED" {
		return responseStruct.Id, nil
	}

	return "", fmt.Errorf("failed to allocate audit session: %v", responseStruct)
}

func (c Cx1Client) AuditFindSessionsByID(projectId, scanId string) (bool, []string, error) {
	c.logger.Tracef("Checking for audit session for project %v scan %v", projectId, scanId)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions?projectId=%v&scanId=%v", projectId, scanId), nil, nil)
	if err != nil {
		return false, []string{}, err
	}

	var responseStruct struct {
		Available bool `json:"available"`
		Metadata  []struct {
			Session string `json:"session_id"`
		} `json:"metadata"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return false, []string{}, err
	}

	sessions := []string{}
	for _, s := range responseStruct.Metadata {
		sessions = append(sessions, s.Session)
	}

	return responseStruct.Available, sessions, nil
}

func (c Cx1Client) AuditGetEngineStatusByID(auditSessionId string) (bool, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/sast-status", auditSessionId), nil, nil)
	if err != nil {
		return false, err
	}

	var engineResponse struct {
		Ready   bool   `json:"ready"`
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &engineResponse)
	if err != nil {
		return false, err
	}

	if engineResponse.Ready {
		return true, nil
	}

	if engineResponse.Message == "the SAST Engine is not ready yet" {
		return false, nil
	}

	return false, fmt.Errorf("unknown cx-audit sast status response: %v", engineResponse.Message)
}

func (c Cx1Client) AuditEnginePollingByID(auditSessionId string) error {
	return c.AuditEnginePollingByIDWithTimeout(auditSessionId, c.consts.AuditEnginePollingDelaySeconds, c.consts.AuditEnginePollingMaxSeconds)
}

func (c Cx1Client) AuditEnginePollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) error {
	c.logger.Debugf("Polling status of cx-audit engine for session %v", auditSessionId)
	status := false
	var err error
	pollingCounter := 0

	for !status {
		status, err = c.AuditGetEngineStatusByID(auditSessionId)
		if err != nil {
			return err
		}
		pollingCounter += delaySeconds
		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return fmt.Errorf("audit engine polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}

		if status {
			return nil
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}

	return nil
}

func (c Cx1Client) AuditCheckLanguagesByID(auditSessionId string) error {
	c.logger.Infof("Triggering language check under audit session %v", auditSessionId)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/project/languages", auditSessionId), nil, nil)
	if err != nil {
		return err
	}
	if string(response) == "0" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	return fmt.Errorf("error: %v", responseStruct.Message)
}

func (c Cx1Client) AuditGetLanguagesByID(auditSessionId string) ([]string, error) {
	var languageResponse struct {
		Completed bool     `json:"completed"`
		Value     []string `json:"value"`
		Message   string   `json:"message"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/request-status?type=%d", auditSessionId, 0), nil, nil)
	if err != nil {
		return []string{}, err
	}
	err = json.Unmarshal(response, &languageResponse)
	if err != nil {
		return []string{}, err
	}

	if languageResponse.Completed {
		return languageResponse.Value, nil
	}

	if languageResponse.Message != "" {
		return []string{}, fmt.Errorf("error: %v", languageResponse.Message)
	}
	return languageResponse.Value, nil
}

func (c Cx1Client) AuditLanguagePollingByID(auditSessionId string) ([]string, error) {
	return c.AuditLanguagePollingByIDWithTimeout(auditSessionId, c.consts.AuditLanguagePollingDelaySeconds, c.consts.AuditLanguagePollingMaxSeconds)
}

func (c Cx1Client) AuditLanguagePollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) ([]string, error) {
	c.logger.Debugf("Polling status of language check for audit session %v", auditSessionId)
	languages := []string{}
	var err error
	pollingCounter := 0
	for len(languages) == 0 {
		languages, err = c.AuditGetLanguagesByID(auditSessionId)
		if err != nil {
			return languages, err
		}

		pollingCounter += delaySeconds
		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return languages, fmt.Errorf("audit languages polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}

		if len(languages) > 0 {
			return languages, nil
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}

	return languages, fmt.Errorf("unknown error")
}

func (c Cx1Client) AuditRunScanByID(auditSessionId string) error {
	c.logger.Infof("Triggering scan under audit session %v", auditSessionId)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/project/scan", auditSessionId), nil, nil)
	if err != nil {
		return err
	}

	if string(response) == "1" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}
	return fmt.Errorf("error: %v", responseStruct.Message)
}

func (c Cx1Client) AuditGetScanStatusByID(auditSessionId string) (bool, error) {
	var scanResponse struct {
		Completed bool     `json:"completed"`
		Value     []string `json:"value"`
		Message   string   `json:"message"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/request-status?type=%d", auditSessionId, 1), nil, nil)
	if err != nil {
		return false, err
	}
	err = json.Unmarshal(response, &scanResponse)
	if err != nil {
		return false, err
	}

	if scanResponse.Completed {
		return true, nil
	}

	if scanResponse.Message != "" {
		return false, fmt.Errorf("error: %v", scanResponse.Message)
	}
	return scanResponse.Completed, nil
}

func (c Cx1Client) AuditScanPollingByID(auditSessionId string) error {
	return c.AuditScanPollingByIDWithTimeout(auditSessionId, c.consts.AuditScanPollingDelaySeconds, c.consts.AuditScanPollingMaxSeconds)
}

func (c Cx1Client) AuditScanPollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) error {
	c.logger.Debugf("Polling status of scan for audit session %v", auditSessionId)
	status := false
	var err error
	pollingCounter := 0
	for !status {
		status, err = c.AuditGetScanStatusByID(auditSessionId)
		if err != nil {
			return err
		}
		pollingCounter += delaySeconds
		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return fmt.Errorf("audit scan polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}
		if status {
			return nil
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}

	return fmt.Errorf("unknown error")
}

func (c Cx1Client) AuditSessionKeepAlive(auditSessionId string) error {
	_, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/cx-audit/sessions/%v", auditSessionId), nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// Convenience function
func (c Cx1Client) GetAuditSessionByID(projectId, scanId string, fastInit bool) (string, error) {
	// TODO: convert the audit session to an object that also does the polling/keepalive
	c.logger.Infof("Creating an audit session for project %v scan %v", projectId, scanId)

	available, sessions, err := c.AuditFindSessionsByID(projectId, scanId)
	if err != nil {
		c.logger.Errorf("Failed to retrieve sessions: %s", err)
		return "", err
	}
	session := ""
	reusedSession := false
	if len(sessions) > 0 && (fastInit || !available) {
		if fastInit { // reuse existing
			c.logger.Debugf("FastInit: re-using the first session %v", sessions[0])
		} else { // !available
			c.logger.Warnf("No additional audit sessions are available, but %d matching sessions exist. Re-using the first session %v", len(sessions), sessions[0])
		}
		session = sessions[0]
		reusedSession = true
	} else {
		session, err = c.AuditCreateSessionByID(projectId, scanId)
		if err != nil {
			c.logger.Errorf("Error creating cxaudit session: %s", err)
			return "", err
		}
	}
	c.AuditSessionKeepAlive(session)

	err = c.AuditEnginePollingByID(session)
	if err != nil {
		c.logger.Errorf("Error while creating audit engine: %s", err)
		return "", err
	}

	if !fastInit || !reusedSession {
		err = c.AuditCheckLanguagesByID(session)
		if err != nil {
			c.logger.Errorf("Error while checking languages: %s", err)
			return "", err
		}
	}

	languages, err := c.AuditLanguagePollingByID(session)
	if err != nil {
		c.logger.Errorf("Error while getting languages: %s", err)
		return "", err
	}

	c.logger.Infof("Languages present: %v", languages)

	if !fastInit || !reusedSession {
		err = c.AuditRunScanByID(session)
		if err != nil {
			c.logger.Errorf("Error while triggering audit scan: %s", err)
			return "", err
		}
	}

	err = c.AuditScanPollingByID(session)
	if err != nil {
		c.logger.Errorf("Error while polling audit scan: %s", err)
		return "", err
	}

	c.AuditSessionKeepAlive(session) // one for the road

	return session, nil
}

func (c Cx1Client) AuditCompileQuery(auditSessionId string, query AuditQuery) error {
	// this wraps "compileQueryFull" and omits parameters that seem to be specific to the CxAudit UI
	return c.compileQueryFull(auditSessionId, query, false, "cxclientgo", "cxclientgo", "cxclientgo")
}
func (c Cx1Client) compileQueryFull(auditSessionId string, query AuditQuery, newquery bool, clientUniqID, fullEditorId, editorId string) error {
	// returns error if failed, else compiled successfully
	c.logger.Infof("Triggering compile for query %v under audit session %v", query.String(), auditSessionId)

	queryIdStr := strconv.FormatUint(query.QueryID, 10)
	type descriptionInfo struct {
		Cwe                int64  `json:"Cwe"`
		CxDescriptionID    int64  `json:"CxDescriptionID"`
		QueryDescriptionID string `json:"QueryDescriptionID"`
	}

	type queryInfo struct {
		Id           string          `json:"Id"`
		Name         string          `json:"name"`
		Group        string          `json:"group"`
		Lang         string          `json:"lang"`
		Path         string          `json:"path"`
		Level        string          `json:"level"` // Tenant, ProjectID, or later AppId?
		NewQuery     bool            `json:"newQuery"`
		IsExecutable bool            `json:"isExecutable"`
		ClientUniqId string          `json:"clientUniqId"`
		OriginalCode string          `json:"originalCode"`
		Code         string          `json:"code"`
		FullEditorId string          `json:"fullEditorId"`
		EditorId     string          `json:"editorId"`
		Id2          string          `json:"id"`     // no clue why this is duplicated
		Source       string          `json:"source"` // same as code?
		Data         descriptionInfo `json:"data"`
	}

	queryBody := make([]queryInfo, 1)
	queryBody[0] = queryInfo{
		Id:           queryIdStr,
		Name:         query.Name,
		Group:        query.Group,
		Lang:         query.Language,
		Path:         query.Path,
		Level:        query.Level,
		IsExecutable: query.IsExecutable,
		ClientUniqId: clientUniqID,
		OriginalCode: "",
		Code:         query.Source,
		FullEditorId: fullEditorId,
		EditorId:     editorId,
		Id2:          queryIdStr,
		Source:       query.Source,
		Data:         descriptionInfo{Cwe: query.Cwe, CxDescriptionID: query.CxDescriptionId, QueryDescriptionID: query.QueryDescriptionId},
	}

	jsonBody, _ := json.Marshal(queryBody)
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/cx-audit/sessions/%v/queries/compile", auditSessionId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	if string(response) == "2" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	return fmt.Errorf("error while compiling: %v", responseStruct.Message)
}

func (c Cx1Client) auditGetCompileStatusByID(sessionId string) (bool, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/request-status?type=%d", sessionId, 2), nil, nil)
	if err != nil {
		return false, err
	}

	var compileResponse struct {
		Completed bool `json:"completed"`
		Value     struct {
			FailedQueries []struct {
				QueryId string `json:"query_id"`
				Errors  []struct {
					Column  int    `json:"column"`
					Line    int    `json:"line"`
					Message string `json:"message"`
				} `json:"errors"`
			} `json:"failed_queries"`
			Success bool `json:"success"`
		} `json:"value"`
	}

	err = json.Unmarshal(response, &compileResponse)
	if err != nil {
		return false, err
	}

	if !compileResponse.Completed {
		return false, nil
	}

	if compileResponse.Value.Success {
		return true, nil
	}

	return false, fmt.Errorf("error compiling: %v", compileResponse.Value.FailedQueries)
}

func (c Cx1Client) AuditCompilePollingByID(auditSessionId string) error {
	return c.AuditCompilePollingByIDWithTimeout(auditSessionId, c.consts.AuditCompilePollingDelaySeconds, c.consts.AuditCompilePollingMaxSeconds)
}

func (c Cx1Client) AuditCompilePollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) error {
	c.logger.Infof("Polling status of compilation for audit session %v", auditSessionId)
	status := false
	var err error

	pollingCounter := 0
	for !status {
		status, err = c.auditGetCompileStatusByID(auditSessionId)
		if err != nil {
			return err
		}
		if status {
			return nil
		}

		pollingCounter += delaySeconds
		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return fmt.Errorf("audit query compilation polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}
		if status {
			return nil
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}
	return fmt.Errorf("unknown error")
}

func (q AuditQuery) CreateTenantOverride() AuditQuery {
	new_query := q
	new_query.Level = "Corp"
	new_query.LevelID = "Corp"
	return new_query
}
func (q AuditQuery) CreateProjectOverrideByID(projectId string) AuditQuery {
	new_query := q
	new_query.Level = "Project"
	new_query.LevelID = projectId
	return new_query
}
func (q AuditQuery) CreateApplicationOverrideByID(applicationId string) AuditQuery {
	new_query := q
	new_query.Level = "Team"
	new_query.LevelID = applicationId
	return new_query
}

/*

	WebAudit use cases:
		1. Create new Corp/Tenant-level query with no existing Cx (product default) query: AuditNewQuery function + AuditCreateCorpQuery (POST to /cx-audit/queries/:session)
		2. Create new Corp/Tenant-level over an existing Cx (product default) query: UpdateQuery function (PUT to /cx-audit/queries/Corp)
		3. Create new override on Project or Application level, where a Corp/Tenant or Cx-level base query already exists: UpdateQuery function (PUT to /cx-audit/queries/ProjectID or AppID)
		4. Update an existing override on Corp/Tenant, Project, or Application level: UpdateQuery function (PUT to /cx-audit/queries/:level

	Note: Application-level queries are not yet implemented in Cx1.

*/

func (c Cx1Client) AuditNewQuery(language, group, name string) (AuditQuery, error) {
	newQuery, err := c.GetQueryByName("Corp", language, "CxDefaultQueryGroup", "CxDefaultQuery")
	if err != nil {
		return newQuery, err
	}

	newQuery.Group = group
	newQuery.Name = name
	return newQuery, nil
}

func (c Cx1Client) AuditCreateCorpQuery(auditSessionId string, query AuditQuery) (AuditQuery, error) {
	folder := fmt.Sprintf("queries/%v/%v/", query.Language, query.Group)
	var qc struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		Source   string `json:"source"`
		Metadata struct {
			IsExecutable       bool
			Path               string
			QueryDescriptionID string
			Severity           uint
		} `json:"metadata"`
	}
	qc.Name = query.Name
	qc.Source = query.Source
	qc.Path = folder
	qc.Metadata.IsExecutable = query.IsExecutable
	qc.Metadata.Path = query.Path
	qc.Metadata.Severity = query.Severity

	jsonBody, _ := json.Marshal(qc)

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/cx-audit/queries/%v", auditSessionId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return AuditQuery{}, err
	}

	if string(response) != "" {
		return AuditQuery{}, fmt.Errorf("creating query returned error: %v", string(response))
	}
	return c.GetQueryByName("Corp", query.Language, query.Group, query.Name)
}

// updating queries via PUT is possible, but only allows changing the source code, not metadata around each query.
// this will be fixed in the future
// PUT is the only option to create an override on the project-level (and maybe in the future on application-level)
func (c Cx1Client) UpdateQuery(query AuditQuery) error { // level = projectId or "Corp"
	c.logger.Debugf("Saving query %v on level %v", query.Path, query.Level)

	q := QueryUpdate{
		Name:   query.Name,
		Path:   query.Path,
		Source: query.Source,
	}

	return c.UpdateQueries(query.LevelID, []QueryUpdate{q})
}

func (c Cx1Client) UpdateQueries(level string, queries []QueryUpdate) error {
	jsonBody, _ := json.Marshal(queries)
	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/cx-audit/queries/%v", level), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}
	if string(response) == "" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	if responseStruct.Type == "ERROR" {
		return fmt.Errorf("error while compiling queries: %v", responseStruct.Message)
	} else {
		return nil
	}
}

func (q AuditQuery) String() string {
	return fmt.Sprintf("[%d] %v: %v", q.QueryID, q.Level, q.Path)
}
func (q *AuditQuery) ParsePath() {
	s := strings.Split(q.Path, "/")
	q.Language = s[1]
	q.Group = s[2]
	q.Name = s[3]
}

func (c Cx1Client) GetQueries() (QueryCollection, error) {
	c.logger.Debug("Get Cx1 Queries Collection")
	var qc QueryCollection

	response, err := c.sendRequest(http.MethodGet, "/presets/queries", nil, nil)
	if err != nil {
		return qc, err
	}

	queries := []Query{}

	err = json.Unmarshal(response, &queries)
	if err != nil {
		c.logger.Tracef("Failed to parse %v", string(response))
	}

	for _, q := range queries {
		ql := qc.GetQueryLanguageByName(q.Language)

		if ql == nil {
			qc.QueryLanguages = append(qc.QueryLanguages, QueryLanguage{q.Language, []QueryGroup{}})
			ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
		}

		qg := ql.GetQueryGroupByName(q.Group)
		if qg == nil {
			ql.QueryGroups = append(ql.QueryGroups, QueryGroup{q.Group, q.Language, []Query{q}})
		} else {
			qg.Queries = append(qg.Queries, q)
		}
	}

	return qc, err
}

// convenience
func (c Cx1Client) GetSeverityID(severity string) uint {
	switch strings.ToUpper(severity) {
	case "INFO":
		return 0
	case "INFORMATION":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	}
	return 0
}

func (qg QueryGroup) GetQueryByName(name string) *Query {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (ql QueryLanguage) GetQueryGroupByName(name string) *QueryGroup {
	for id, qg := range ql.QueryGroups {
		if strings.EqualFold(qg.Name, name) {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}
func (qc QueryCollection) GetQueryLanguageByName(language string) *QueryLanguage {
	for id, ql := range qc.QueryLanguages {
		if strings.EqualFold(ql.Name, language) {
			return &qc.QueryLanguages[id]
		}
	}
	return nil
}
func (qc QueryCollection) GetQueryByName(language, group, query string) *Query {
	ql := qc.GetQueryLanguageByName(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil
	}
	return qg.GetQueryByName(query)
}

func (qc QueryCollection) GetQueryByID(qid uint64) *Query {
	for _, ql := range qc.QueryLanguages {
		for _, qg := range ql.QueryGroups {
			for id, q := range qg.Queries {
				if q.QueryID == qid {
					return &qg.Queries[id]
				}
			}
		}
	}
	return nil
}
func (q Query) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}
func (q QueryGroup) String() string {
	return fmt.Sprintf("%v -> %v", q.Language, q.Name)
}
func (q QueryLanguage) String() string {
	return q.Name
}

func (c Cx1Client) QueryLink(q *Query) string {
	return fmt.Sprintf("%v/audit/?queryid=%d", c.baseUrl, q.QueryID)
}

func (c Cx1Client) QueryGroupLink(q *QueryGroup) string {
	return fmt.Sprintf("%v/audit/?language=%v&group=%v", c.baseUrl, q.Language, q.Name)
}

func (c Cx1Client) QueryLanguageLink(q *QueryLanguage) string {
	return fmt.Sprintf("%v/audit/?language=%v", c.baseUrl, q.Name)
}
