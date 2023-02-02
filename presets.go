package Cx1ClientGo

import (
	"bytes"
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

func (c *Cx1Client) GetPresetByName(name string) (Preset, error) {
	c.logger.Debugf("Get preset by name %v", name)
	var preset Preset
	var presets []Preset
	presets, err := c.GetPresets()
	if err != nil {
		return preset, err
	}

	for _, p := range presets {
		if p.Name == name {
			return p, nil
		}
	}
	return preset, errors.New("No such preset found")
}

func (c *Cx1Client) GetPresetByID(id uint64) (Preset, error) {
	c.logger.Debugf("Get preset by id %d", id)
	var preset Preset
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets/%d", id), nil, nil)
	if err != nil {
		return preset, err
	}

	err = json.Unmarshal(response, &preset)
	return preset, err
}

func (c *Cx1Client) GetPresetContents(p *Preset, queries *[]Query) error {
	c.logger.Tracef("Fetching contents for preset %v", p.PresetID)

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

	populate_queries := true
	if queries == nil || len(*queries) == 0 {
		c.logger.Tracef(" - GetPresetContents call was provided with an empty queries array, will not populate the Preset.Queries array")
		populate_queries = false
	} else {
		p.Queries = make([]Query, len(PresetContents.QueryIDs))
	}

	p.QueryIDs = make([]uint64, len(PresetContents.QueryIDs))
	for id, qid := range PresetContents.QueryIDs {
		var u uint64
		u, _ = strconv.ParseUint(qid, 0, 64)
		p.QueryIDs[id] = u
		if populate_queries {
			q := c.GetQueryByID(u, queries)
			if q != nil {
				p.Queries[id] = *q
				c.logger.Tracef(" - linked query: %v", q.String())
			}
		}
	}

	p.Filled = true
	p.Custom = PresetContents.Custom
	p.Description = PresetContents.Description

	return nil
}

func (c *Cx1Client) CreatePreset(name, description string, queryIDs []string) (Preset, error) {
	c.logger.Debugf("Creating preset %v", name)
	var preset Preset

	body := map[string]interface{}{
		"name":        name,
		"description": description,
		"queryIDs":    queryIDs,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return preset, err
	}

	response, err := c.sendRequest(http.MethodPost, "/presets", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return preset, err
	}

	var responseStruct struct {
		Id      uint64 `json:"id"`
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return preset, err
	}

	return c.GetPresetByID(responseStruct.Id)
}

func (p *Preset) AddQueryID(queryId uint64) {
	p.QueryIDs = append(p.QueryIDs, queryId)
}

func (c *Cx1Client) SavePreset(preset *Preset) error {
	c.logger.Debugf("Saving preset %v", preset.Name)

	qidstr := make([]string, len(preset.QueryIDs))

	for id, q := range preset.QueryIDs {
		qidstr[id] = fmt.Sprintf("%d", q)
	}

	body := map[string]interface{}{
		"name":        preset.Name,
		"description": preset.Description,
		"queryIds":    qidstr,
	}

	json, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/presets/%d", preset.PresetID), bytes.NewReader(json), nil)
	return err
}

func (c *Cx1Client) RemovePreset(preset *Preset) error {
	c.logger.Debugf("Removing preset %v", preset.Name)
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/presets/%d", preset.PresetID), nil, nil)
	return err
}

func (c *Cx1Client) PresetLink(p *Preset) string {
	return fmt.Sprintf("%v/resourceManagement/presets?presetId=%d", c.baseUrl, p.PresetID)
}
