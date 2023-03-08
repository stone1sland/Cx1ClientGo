package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Reports
func (c *Cx1Client) RequestNewReport(scanID, projectID, branch, reportType string) (string, error) {
	c.depwarn("RequestNewReport", "RequestNewReportByID")
	return c.RequestNewReportByID(scanID, projectID, branch, reportType)
}

func (c *Cx1Client) RequestNewReportByID(scanID, projectID, branch, reportType string) (string, error) {
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
			"scanners": []string{"SAST"},
			"host":     "",
		},
	}

	jsonBody, err := json.Marshal(jsonData)
	if err != nil {
		return "", err
	}

	data, err := c.sendRequest(http.MethodPost, "/reports", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger report generation for scan %v: %s", scanID, err)
	}

	var reportResponse struct {
		ReportId string
	}
	err = json.Unmarshal([]byte(data), &reportResponse)

	return reportResponse.ReportId, err
}
func (c *Cx1Client) GetReportStatus(reportID string) (ReportStatus, error) {
	c.depwarn("GetReportStatus", "GetReportStatusByID")
	return c.GetReportStatusByID(reportID)
}

func (c *Cx1Client) GetReportStatusByID(reportID string) (ReportStatus, error) {
	var response ReportStatus

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/reports/%v", reportID), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch report status for reportID %v: %s", reportID, err)
		return response, fmt.Errorf("failed to fetch report status for reportID %v: %s", reportID, err)
	}

	err = json.Unmarshal([]byte(data), &response)
	return response, err
}

func (c *Cx1Client) DownloadReport(reportUrl string) ([]byte, error) {
	data, err := c.sendRequestInternal(http.MethodGet, reportUrl, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to download report from url %v: %s", reportUrl, err)
	}
	return data, nil
}
