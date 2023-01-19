package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"
)

// Presets

func (p *Preset) String() string {
	return fmt.Sprintf("[%d] %v", p.PresetID, p.Name)
}

func (c *Cx1Client) GetPresets() ([]Preset, error) {
	c.logger.Debug("Get Cx1 Presets")
	var presets []Preset
	response, err := c.sendRequest(http.MethodGet, "/queries/presets", nil, nil)
	if err != nil {
		return presets, err
	}

	err = json.Unmarshal(response, &presets)
	c.logger.Tracef("Got %d presets", len(presets))
	return presets, err
}

func (c *Cx1Client) GetPresetContents(p *Preset, queries *[]Query) error {
	c.logger.Tracef("Fetching contents for preset %v", p.PresetID)

	if len(*queries) == 0 {
		return errors.New("Queries list is empty")
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets/%v", p.PresetID), nil, nil)
	if err != nil {
		return err
	}

	var PresetContents struct {
		ID          uint64
		Name        string
		Description string
		Custom      bool
		QueryIDs    []string
	}

	err = json.Unmarshal(response, &PresetContents)
	if err != nil {
		return errors.Wrap(err, "Failed to parse preset contents")
	}

	c.logger.Tracef("Parsed preset %v with %d queries", PresetContents.Name, len(PresetContents.QueryIDs))

	p.Queries = make([]Query, 0)
	for _, qid := range PresetContents.QueryIDs {
		var u uint64
		u, _ = strconv.ParseUint(qid, 0, 64)
		q := c.GetQueryByID(u, queries)
		if q != nil {
			p.Queries = append(p.Queries, *q)
			c.logger.Tracef(" - linked query: %v", q.String())
		}
	}

	p.Filled = true
	return nil
}

func (c *Cx1Client) PresetLink(p *Preset) string {
	return fmt.Sprintf("%v/resourceManagement/presets?presetId=%d", c.baseUrl, p.PresetID)
}
