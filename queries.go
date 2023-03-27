package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (c Cx1Client) GetQueryByID(qid uint64) (Query, error) {
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
	return q, err
}

func (c Cx1Client) GetQueries() (QueryCollection, error) {
	c.logger.Debug("Get Cx1 Queries Collection")
	var qc QueryCollection

	// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.
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

func (qg *QueryGroup) GetQueryByName(name string) *Query {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (ql *QueryLanguage) GetQueryGroupByName(name string) *QueryGroup {
	for id, qg := range ql.QueryGroups {
		if strings.EqualFold(qg.Name, name) {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}
func (qc *QueryCollection) GetQueryLanguageByName(language string) *QueryLanguage {
	for id, ql := range qc.QueryLanguages {
		if strings.EqualFold(ql.Name, language) {
			return &qc.QueryLanguages[id]
		}
	}
	return nil
}
func (qc *QueryCollection) GetQueryByName(language, group, query string) *Query {
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

func (qc *QueryCollection) GetQueryByID(qid uint64) *Query {
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
func (q *Query) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}
func (q *QueryGroup) String() string {
	return fmt.Sprintf("%v -> %v", q.Language, q.Name)
}
func (q *QueryLanguage) String() string {
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
