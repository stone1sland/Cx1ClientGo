package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func (c Cx1Client) GetScan(scanID string) (Scan, error) {
	c.depwarn("GetScan", "GetScanByID")
	return c.GetScanByID(scanID)
}

func (c Cx1Client) GetScanByID(scanID string) (Scan, error) {
	var scan Scan

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scans/%v", scanID), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch scan with ID %v: %s", scanID, err)
		return scan, fmt.Errorf("failed to fetch scan with ID %v: %s", scanID, err)
	}

	json.Unmarshal([]byte(data), &scan)
	return scan, nil
}
func (c Cx1Client) DeleteScanByID(scanID string) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/scans/%v", scanID), nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete scan with ID %v: %s", scanID, err)
	}

	return nil
}

func (c Cx1Client) GetScanMetadata(scanID string) (ScanMetadata, error) {
	c.depwarn("GetScanMetadata", "GetScanMetadataByID")
	return c.GetScanMetadataByID(scanID)
}

func (c Cx1Client) GetScanMetadataByID(scanID string) (ScanMetadata, error) {
	var scanmeta ScanMetadata

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-metadata/%v", scanID), nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Failed to fetch metadata for scan with ID %v: %s", scanID, err)
		return scanmeta, fmt.Errorf("failed to fetch metadata for scan with ID %v: %s", scanID, err)
	}

	json.Unmarshal(data, &scanmeta)
	return scanmeta, nil
}

func (c Cx1Client) GetLastScansByStatus(status []string) ([]Scan, error) {
	scanFilter := ScanFilter{
		Statuses: status,
	}
	return c.GetLastScansFiltered(scanFilter)
}

func (c Cx1Client) GetLastScansFiltered(filter ScanFilter) ([]Scan, error) {
	var scanResponse struct {
		TotalCount         uint64
		FilteredTotalCount uint64
		Scans              []Scan
	}

	query := url.Values{
		"sort": {"+created_at"},
	}

	filter.AddURLValues(&query)

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scans?%v", query.Encode()), nil, nil)
	if err != nil {
		err = fmt.Errorf("failed to fetch scans matching filter %v: %s", query, err)
		c.logger.Tracef("Error: %s", err)
		return scanResponse.Scans, err
	}

	err = json.Unmarshal(data, &scanResponse)
	return scanResponse.Scans, err
}

func (s *ScanSummary) TotalCount() uint64 {
	var count uint64
	count = 0

	for _, c := range s.SASTCounters.StateCounters {
		count += c.Counter
	}

	return count
}

func (c Cx1Client) GetScanConfigurationByID(projectID, scanID string) ([]ConfigurationSetting, error) {
	c.logger.Debug("Getting project configuration")
	var scanConfigurations []ConfigurationSetting
	params := url.Values{
		"project-id": {projectID},
		"scan-id":    {scanID},
	}
	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/configuration/scan?%v", params.Encode()), nil, nil)

	if err != nil {
		c.logger.Tracef("Failed to get scan configuration for project ID %v, scan ID %v: %s", projectID, scanID, err)
		return scanConfigurations, err
	}

	err = json.Unmarshal([]byte(data), &scanConfigurations)
	return scanConfigurations, err
}

func (c Cx1Client) GetScanSummaryCounter() ([]ScanSummaryCount, error) {
	c.logger.Debug("Getting scan status counters")
	var scanSummaryCount []ScanSummaryCount

	data, err := c.sendRequest(http.MethodGet, fmt.Sprint("/scans/summary"), nil, nil)

	if err != nil {
		c.logger.Trace("Failed to get scan status counters")
		return scanSummaryCount, err
	}
	err = json.Unmarshal(data, &scanSummaryCount)
	return scanSummaryCount, err
}

func (c Cx1Client) GetScanSummary(scanID string) (ScanSummary, error) {
	c.depwarn("GetScanSummary", "GetScanSummaryByID")
	return c.GetScanSummaryByID(scanID)
}

func (c Cx1Client) GetScanSummaryByID(scanID string) (ScanSummary, error) {
	var ScansSummaries struct {
		ScanSum    []ScanSummary `json:"scansSummaries"`
		TotalCount uint64
	}

	params := url.Values{
		"scan-ids":                {scanID},
		"include-queries":         {"false"},
		"include-status-counters": {"true"},
		"include-files":           {"false"},
	}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scan-summary/?%v", params.Encode()), nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Failed to fetch metadata for scan with ID %v: %s", scanID, err)
		return ScanSummary{}, fmt.Errorf("failed to fetch metadata for scan with ID %v: %s", scanID, err)
	}

	err = json.Unmarshal(data, &ScansSummaries)

	if err != nil {
		return ScanSummary{}, err
	}
	if ScansSummaries.TotalCount == 0 {
		return ScanSummary{}, fmt.Errorf("failed to retrieve scan summary for scan ID %v", scanID)
	}

	if len(ScansSummaries.ScanSum) == 0 {
		c.logger.Tracef("Failed to parse data, 0-len ScanSum.\n%v", string(data))
		return ScanSummary{}, fmt.Errorf("Fail")
	}

	return ScansSummaries.ScanSum[0], nil
}

func (c Cx1Client) GetScanLogs(scanID, engine string) ([]byte, error) {
	c.depwarn("GetScanLogs", "GetScanLogsByID")
	return c.GetScanLogsByID(scanID, engine)
}
func (c Cx1Client) GetScanLogsByID(scanID, engine string) ([]byte, error) {
	c.logger.Debugf("Fetching scan logs for scan %v", scanID)

	response, err := c.sendRequestRawCx1(http.MethodGet, fmt.Sprintf("/logs/%v/%v", scanID, engine), nil, nil)

	if err != nil {
		c.logger.Tracef("Error retrieving scanlog url: %s", err)
		return []byte{}, err
	}

	enginelogURL := response.Header.Get("Location")
	if enginelogURL == "" {
		return []byte{}, fmt.Errorf("expected location header response not found")
	}

	//c.logger.Tracef("Retrieved url: %v", enginelogURL)
	data, err := c.sendRequestInternal(http.MethodGet, enginelogURL, nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to download logs from %v: %s", enginelogURL, err)
		return []byte{}, nil
	}

	return data, nil
}

func (c Cx1Client) GetScanWorkflowByID(scanID string) ([]WorkflowLog, error) {
	var workflow []WorkflowLog

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/scans/%v/workflow", scanID), nil, http.Header{})
	if err != nil {
		c.logger.Errorf("Failed to fetch workflow for scan with ID %v: %s", scanID, err)
		return []WorkflowLog{}, fmt.Errorf("failed to fetch workflow for scan with ID %v: %s", scanID, err)
	}

	err = json.Unmarshal(data, &workflow)
	return workflow, err
}

func (c Cx1Client) scanProject(scanConfig map[string]interface{}) (Scan, error) {
	scan := Scan{}

	jsonBody, err := json.Marshal(scanConfig)
	if err != nil {
		return scan, err
	}

	data, err := c.sendRequest(http.MethodPost, "/scans", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return scan, err
	}

	err = json.Unmarshal(data, &scan)
	return scan, err
}

func (c Cx1Client) ScanProjectZip(projectID, sourceUrl, branch string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	c.depwarn("ScanProjectZip", "ScanProjectZipByID")
	return c.ScanProjectZipByID(projectID, sourceUrl, branch, settings, tags)
}

func (c Cx1Client) ScanProjectZipByID(projectID, sourceUrl, branch string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	jsonBody := map[string]interface{}{
		"project": map[string]interface{}{"id": projectID},
		"type":    "upload",
		"tags":    tags,
		"handler": map[string]interface{}{
			"uploadurl": sourceUrl,
			"branch":    branch,
		},
		"config": settings,
	}

	scan, err := c.scanProject(jsonBody)
	if err != nil {
		return scan, fmt.Errorf("failed to start a zip scan for project %v: %s", projectID, err)
	}
	return scan, err
}

func (c Cx1Client) ScanProjectGit(projectID, repoUrl, branch string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	c.depwarn("ScanProjectGit", "ScanProjectGitByID")
	return c.ScanProjectGitByID(projectID, repoUrl, branch, settings, tags)
}

func (c Cx1Client) ScanProjectGitByID(projectID, repoUrl, branch string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	jsonBody := map[string]interface{}{
		"project": map[string]interface{}{"id": projectID},
		"type":    "git",
		"tags":    tags,
		"handler": map[string]interface{}{
			"repoUrl": repoUrl,
			"branch":  branch,
		},
		"config": settings,
	}

	scan, err := c.scanProject(jsonBody)
	if err != nil {
		return scan, fmt.Errorf("failed to start a git scan for project %v: %s", projectID, err)
	}
	return scan, err
}

// convenience function
func (c Cx1Client) ScanProject(projectID, sourceUrl, branch, scanType string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	c.depwarn("ScanProject", "ScanProjectByID")
	return c.ScanProjectByID(projectID, sourceUrl, branch, scanType, settings, tags)
}

func (c Cx1Client) ScanProjectByID(projectID, sourceUrl, branch, scanType string, settings []ScanConfiguration, tags map[string]string) (Scan, error) {
	if scanType == "upload" {
		return c.ScanProjectZipByID(projectID, sourceUrl, branch, settings, tags)
	} else if scanType == "git" {
		return c.ScanProjectGitByID(projectID, sourceUrl, branch, settings, tags)
	}

	return Scan{}, fmt.Errorf("invalid scanType provided, must be 'upload' or 'git'")
}

// convenience function
func (s *Scan) IsIncremental() (bool, error) {
	for _, scanconfig := range s.Metadata.Configs {
		if scanconfig.ScanType == "sast" {
			if val, ok := scanconfig.Values["incremental"]; ok {
				return val == "true", nil
			}
		}
	}
	return false, fmt.Errorf(fmt.Sprintf("Scan %v did not have a sast-engine incremental flag set", s.ScanID))
}

// convenience
func (c Cx1Client) ScanPolling(s *Scan) (Scan, error) {
	return c.ScanPollingWithTimeout(s, false, c.consts.ScanPollingDelaySeconds, c.consts.ScanPollingMaxSeconds)
}

func (c Cx1Client) ScanPollingDetailed(s *Scan) (Scan, error) {
	return c.ScanPollingWithTimeout(s, true, c.consts.ScanPollingDelaySeconds, c.consts.ScanPollingMaxSeconds)
}

func (c Cx1Client) ScanPollingWithTimeout(s *Scan, detailed bool, delaySeconds, maxSeconds int) (Scan, error) {
	c.logger.Infof("Polling status of scan %v", s.ScanID)

	pollingCounter := 0
	var err error
	scan := *s
	for !(scan.Status == "Failed" || scan.Status == "Partial" || scan.Status == "Completed" || scan.Status == "Canceled") { // scan is queueing or running
		scan, err = c.GetScanByID(scan.ScanID)
		if err != nil {
			c.logger.Tracef("Failed to get scan status: %s", err)
			return scan, err
		}
		if detailed {
			workflow, err := c.GetScanWorkflowByID(scan.ScanID)
			if err != nil {
				c.logger.Tracef("Failed to get scan workflow: %s", err)
				return scan, err
			}
			status := "no details"
			if len(workflow) > 0 {
				status = workflow[len(workflow)-1].Info
			}
			c.logger.Infof(" - %v: %v", scan.Status, status)
		} else {
			c.logger.Infof(" - %v", scan.Status)
		}
		if scan.Status == "Failed" || scan.Status == "Partial" || scan.Status == "Completed" || scan.Status == "Canceled" {
			break
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return scan, fmt.Errorf("scan polling reached %d seconds, aborting - use cx1client.get/setclientvars to change", pollingCounter)
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
	return scan, nil
}

func (c Cx1Client) GetUploadURL() (string, error) {
	c.logger.Debug("Get Cx1 Upload URL")
	response, err := c.sendRequest(http.MethodPost, "/uploads", nil, nil)

	if err != nil {
		c.logger.Tracef("Unable to get Upload URL: %s", err)
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(response, &jsonBody)
	if err != nil {
		c.logger.Tracef("Error: %s", err)
		c.logger.Tracef("Input was: %s", string(response))
		return "", err
	} else {
		return jsonBody["url"].(string), nil
	}
}

func (c Cx1Client) PutFile(URL string, filename string) (string, error) {
	res, err := c.PutFileRaw(URL, filename)
	if err != nil {
		c.logger.Tracef("Error: %s", err)
		return "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		c.logger.Tracef("Error: %s", err)
		return "", err
	}

	return string(resBody), nil
}

func (c Cx1Client) PutFileRaw(URL string, filename string) (*http.Response, error) {
	c.logger.Tracef("Putting file %v to %v", filename, URL)

	fileContents, err := os.ReadFile(filename)
	if err != nil {
		c.logger.Tracef("Failed to Read the File %v: %s", filename, err)
		return nil, err
	}

	header := http.Header{}
	header.Add("Content-Type", "application/zip")

	cx1_req, err := c.createRequest(http.MethodPut, URL, bytes.NewReader(fileContents), &header, nil)
	if err != nil {
		return nil, err
	}
	cx1_req.ContentLength = int64(len(fileContents))

	return c.httpClient.Do(cx1_req)
}

func (c Cx1Client) UploadBytesForProjectByID(projectID string, fileContents *[]byte) (string, error) {
	// this function exists only for compatibility with a generic interface supporting both SAST and Cx1
	return c.UploadBytes(fileContents)
}

// creates upload URL, uploads, returns upload URL
func (c Cx1Client) UploadBytes(fileContents *[]byte) (string, error) {
	uploadUrl, err := c.GetUploadURL()
	if err != nil {
		return "", err
	}

	header := http.Header{}
	header.Add("Content-Type", "application/zip")

	cx1_req, err := c.createRequest(http.MethodPut, uploadUrl, bytes.NewReader(*fileContents), &header, nil)
	if err != nil {
		return "", err
	}
	cx1_req.ContentLength = int64(len(*fileContents))

	res, err := c.httpClient.Do(cx1_req)
	if err != nil {
		c.logger.Tracef("Error: %s", err)
		return "", err
	}
	defer res.Body.Close()

	return uploadUrl, nil
}

func (s *Scan) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(s.ScanID), s.ProjectName)
}
