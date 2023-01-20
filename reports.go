package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

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
		return "", errors.Wrapf(err, "Failed to trigger report generation for scan %v", scanID)
	}

	var reportResponse struct {
		ReportId string
	}
	err = json.Unmarshal([]byte(data), &reportResponse)

	return reportResponse.ReportId, err
}

func (c *Cx1Client) GetReportStatus(reportID string) (ReportStatus, error) {
	var response ReportStatus

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/reports/%v", reportID), nil, nil)
	if err != nil {
		c.logger.Errorf("Failed to fetch report status for reportID %v: %s", reportID, err)
		return response, errors.Wrapf(err, "failed to fetch report status for reportID %v", reportID)
	}

	err = json.Unmarshal([]byte(data), &response)
	return response, err
}

func (c *Cx1Client) DownloadReport(reportUrl string) ([]byte, error) {

	data, err := c.sendRequestInternal(http.MethodGet, reportUrl, nil, nil)
	if err != nil {
		return []byte{}, errors.Wrapf(err, "failed to download report from url: %v", reportUrl)
	}
	return data, nil
}
