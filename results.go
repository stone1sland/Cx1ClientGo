package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func (c *Cx1Client) GetScanResults(scanID string, limit uint64) ([]ScanResult, error) {
	c.logger.Debug("Get Cx1 Scan Results")
	var resultResponse struct {
		Results    []ScanResult
		TotalCount int
	}

	params := url.Values{
		"scan-id":  {scanID},
		"limit":    {fmt.Sprintf("%d", limit)},
		"state":    []string{},
		"severity": []string{},
		"status":   []string{},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/results/?%v", params.Encode()), nil, nil)
	if err != nil && len(response) == 0 {
		c.logger.Tracef("Failed to retrieve scan results for scan ID %v", scanID)
		return []ScanResult{}, err
	}

	err = json.Unmarshal(response, &resultResponse)
	if err != nil {
		c.logger.Tracef("Failed while parsing response: %s", err)
		c.logger.Tracef("Response contents: %s", string(response))
		return []ScanResult{}, err
	}
	c.logger.Debugf("Retrieved %d results", resultResponse.TotalCount)

	if len(resultResponse.Results) != resultResponse.TotalCount {
		c.logger.Warnf("Expected results total count %d but parsed only %d", resultResponse.TotalCount, len(resultResponse.Results))
		c.logger.Warnf("Response was: %v", string(response))
	}

	return resultResponse.Results, nil
}

func (c *Cx1Client) GetScanResultsCount(scanID string) (uint64, error) {
	c.logger.Debug("Get Cx1 Scan Results")
	var resultResponse struct {
		//Results    []ScanResult
		TotalCount uint64
	}

	params := url.Values{
		"scan-id":  {scanID},
		"limit":    {fmt.Sprintf("%d", 0)},
		"state":    []string{},
		"severity": []string{},
		"status":   []string{},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/results/?%v", params.Encode()), nil, nil)
	if err != nil && len(response) == 0 {
		c.logger.Tracef("Failed to retrieve scan results for scan ID %v", scanID)
		return 0, err
	}

	err = json.Unmarshal(response, &resultResponse)
	if err != nil {
		c.logger.Tracef("Failed while parsing response: %s", err)
		c.logger.Tracef("Response contents: %s", string(response))
		return 0, err
	}
	return resultResponse.TotalCount, nil
}

// results
func (c *Cx1Client) AddResultsPredicates(predicates []ResultsPredicates) error {
	c.logger.Debugf("Adding %d results predicates", len(predicates))

	jsonBody, err := json.Marshal(predicates)
	if err != nil {
		c.logger.Tracef("Failed to add results predicates: %s", err)
		return err
	}

	_, err = c.sendRequest(http.MethodPost, "/sast-results-predicates", bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) GetResultsPredicates(SimilarityID int64, ProjectID string) ([]ResultsPredicates, error) {
	c.logger.Debugf("Fetching results predicates for project %v similarityId %d", ProjectID, SimilarityID)

	var Predicates struct {
		PredicateHistoryPerProject []struct {
			ProjectID    string
			SimilarityID int64 `json:"similarityId,string"`
			Predicates   []ResultsPredicates
			TotalCount   uint
		}

		TotalCount uint
	}
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast-results-predicates/%d?project-ids=%v", SimilarityID, ProjectID), nil, nil)
	if err != nil {
		return []ResultsPredicates{}, err
	}

	err = json.Unmarshal(response, &Predicates)
	if err != nil {
		return []ResultsPredicates{}, err
	}

	if Predicates.TotalCount == 0 {
		return []ResultsPredicates{}, nil
	}

	return Predicates.PredicateHistoryPerProject[0].Predicates, err
}

func (r ScanResult) String() string {
	return fmt.Sprintf("%v (%d) - %v to %v - in file %v:%d", r.Data.QueryName, r.SimilarityID, r.Data.Nodes[0].Name, r.Data.Nodes[len(r.Data.Nodes)-1].Name, r.Data.Nodes[0].FileName, r.Data.Nodes[0].Line)
}

func addResultStatus(summary *ScanResultStatusSummary, result *ScanResult) {
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

func (c *Cx1Client) GetScanResultSummary(results []ScanResult) ScanResultSummary {
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
	return fmt.Sprintf("To Verify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d", s.ToVerify, s.Confirmed, s.Urgent, s.ProposedNotExploitable, s.NotExploitable)
}
func (s ScanResultSummary) String() string {
	return fmt.Sprintf("%v\n%v\n%v", fmt.Sprintf("\tHigh: %v\n\tMedium: %v\n\tLow: %v\n\tInfo: %v", s.High.String(), s.Medium.String(), s.Low.String(), s.Information.String()),
		fmt.Sprintf("\tTotal High: %d, Medium: %d, Low: %d, Info: %d", s.High.Total(), s.Medium.Total(), s.Low.Total(), s.Information.Total()),
		fmt.Sprintf("\tTotal ToVerify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d",
			s.High.ToVerify+s.Medium.ToVerify+s.Low.ToVerify+s.Information.ToVerify,
			s.High.Confirmed+s.Medium.Confirmed+s.Low.Confirmed+s.Information.Confirmed,
			s.High.Urgent+s.Medium.Urgent+s.Low.Urgent+s.Information.Urgent,
			s.High.ProposedNotExploitable+s.Medium.ProposedNotExploitable+s.Low.ProposedNotExploitable+s.Information.ProposedNotExploitable,
			s.High.NotExploitable+s.Medium.NotExploitable+s.Low.NotExploitable+s.Information.NotExploitable))
}
