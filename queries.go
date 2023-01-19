package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (c *Cx1Client) GetQueries() ([]Query, error) {
	c.logger.Debug("Get Cx1 Queries")
	var queries []Query

	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.
	response, err := c.sendRequest(http.MethodGet, "/presets/queries", nil, nil)
	if err != nil {
		return queries, err
	}

	err = json.Unmarshal(response, &queries)
	if err != nil {
		c.logger.Errorf("Failed to parse %v", string(response))
	}
	return queries, err
}

// convenience
func (c *Cx1Client) GetQueryGroups(queries *[]Query) []QueryGroup {
	qgs := make([]QueryGroup, 0)

	for id, q := range *queries {
		qg := c.GetQueryGroup(q.Group, q.Language, &qgs)
		if qg == nil {
			qgs = append(qgs, QueryGroup{q.Group, q.Language, []*Query{&(*queries)[id]}})
		} else {
			qg.Queries = append(qg.Queries, &(*queries)[id])
		}
	}
	return qgs
}
func (c *Cx1Client) GetQueryGroup(name string, language string, qgs *[]QueryGroup) *QueryGroup {
	for id, qg := range *qgs {
		if qg.Name == name {
			return &(*qgs)[id]
		}
	}
	return nil
}
func (c *Cx1Client) GetQueryByID(qid uint64, queries *[]Query) *Query {
	for id, q := range *queries {
		if q.QueryID == qid {
			return &(*queries)[id]
		}
	}
	return nil
}
func (q *Query) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}
