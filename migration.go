package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (c Cx1Client) StartMigration(dataArchive, projectMapping []byte, encryptionKey string) (string, error) {
	dataUrl, err := c.UploadBytes(&dataArchive)
	if err != nil {
		return "", fmt.Errorf("error uploading migration data: %s", err)
	}

	c.logger.Debugf("Uploaded data archive to %v", dataUrl)
	dataFilename := getFilenameFromURL(dataUrl)

	mappingFilename := ""
	if len(projectMapping) != 0 {

		mappingUrl, err := c.UploadBytes(&projectMapping)
		mappingFilename = getFilenameFromURL(mappingUrl)
		if err != nil {
			return "", fmt.Errorf("error uploading project mapping data: %s", err)
		}

		c.logger.Debugf("Uploaded project mapping to %v", mappingUrl)
	}

	return c.StartImport(dataFilename, mappingFilename, encryptionKey)
}

func (c Cx1Client) StartImport(dataFilename, mappingFilename, encryptionKey string) (string, error) {
	jsonBody := map[string]interface{}{
		"fileName":                dataFilename,
		"projectsMappingFileName": mappingFilename,
		"encryptionKey":           encryptionKey,
	}

	body, _ := json.Marshal(jsonBody)
	response, err := c.sendRequest(http.MethodPost, "/imports", bytes.NewReader(body), nil)
	if err != nil {
		return "", err
	}

	var responseBody struct {
		MigrationId string `json:"migrationId"`
	}
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return "", err
	}

	return responseBody.MigrationId, nil
}

func (c Cx1Client) GetImports() ([]DataImport, error) {
	response, err := c.sendRequest(http.MethodGet, "/imports", nil, nil)
	var imports []DataImport
	if err != nil {
		return imports, err
	}

	err = json.Unmarshal(response, &imports)
	return imports, err
}

func (c Cx1Client) GetImportByID(importID string) (DataImport, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/imports/%v", importID), nil, nil)
	var di DataImport
	if err != nil {
		return di, err
	}

	err = json.Unmarshal(response, &di)
	return di, err
}

func (c Cx1Client) GetImportLogsByID(importID, engine string) ([]byte, error) {
	c.logger.Debugf("Fetching import logs for import %v", importID)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/imports/%v/logs/download", importID), nil, nil)
	return response, err
}

func (c Cx1Client) ImportPollingByID(importID string) (string, error) {
	return c.ImportPollingByIDWithTimeout(importID, c.consts.MigrationPollingDelaySeconds, c.consts.MigrationPollingMaxSeconds)
}

func (c Cx1Client) ImportPollingByIDWithTimeout(importID string, delaySeconds, maxSeconds int) (string, error) {
	pollingCounter := 0
	for {
		status, err := c.GetImportByID(importID)
		if err != nil {
			return "", err
		}

		switch status.Status {
		case "failed":
			return status.Status, fmt.Errorf("import failed: %s", status.Logs)
		case "completed":
			return status.Status, nil
		case "partial":
			return status.Status, nil
		}
		pollingCounter += delaySeconds
		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return "timeout", fmt.Errorf("import polling reached %d seconds, aborting - use cx1client.get/setclientvars to change", pollingCounter)
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}
}

func getFilenameFromURL(url string) string {
	if ind := strings.Index(url, "?"); ind > -1 {
		url = url[:ind]
	}
	if ind := strings.LastIndex(url, "/"); ind >= -1 {
		url = url[ind+1:]
	}
	return url
}
