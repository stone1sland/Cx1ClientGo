package Cx1ClientGo

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type Cx1Client struct {
	httpClient *http.Client
	//authToken  string
	baseUrl string
	iamUrl  string
	tenant  string
	logger  *logrus.Logger
}

type Application struct {
	ApplicationID string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Criticality   uint              `json:"criticality"`
	Rules         []ApplicationRule `json:"rules"`
	Tags          map[string]string `json:"tags"`
	CreatedAt     string            `json:"createdAt"`
	UpdatedAt     string            `json:"updatedAt"`
}

type ApplicationRule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Group struct {
	GroupID string `json:"id"`
	Name    string
	//	Path string // ignoring for now
	//  SubGroups string // ignoring for now
}

type Preset struct {
	PresetID uint64 `json:"id"`
	Name     string `json:"name"`
	Filled   bool
	Queries  []Query
}

type Project struct {
	ProjectID   string            `json:"id"`
	Name        string            `json:"name"`
	CreatedAt   string            `json:"createdAt"`
	UpdatedAt   string            `json:"updatedAt"`
	Groups      []string          `json:"groups"`
	Tags        map[string]string `json:"tags"`
	RepoUrl     string            `json:"repoUrl"`
	MainBranch  string            `json:"mainBranch"`
	Origin      string            `json:"origin"`
	Criticality uint              `json:"criticality"`
}

type ProjectConfigurationSetting struct {
	Key             string `json:"key"`
	Name            string `json:"name"`
	Category        string `json:"category"`
	OriginLevel     string `json:"originLevel"`
	Value           string `json:"value"`
	ValueType       string `json:"valuetype"`
	ValueTypeParams string `json:"valuetypeparams"`
	AllowOverride   bool   `json:"allowOverride"`
}

type Query struct {
	QueryID            uint64 `json:"queryID,string"`
	Name               string `json:"queryName"`
	Group              string
	Language           string
	Severity           string
	CweID              int64
	QueryDescriptionId int64
	Custom             bool
}

type QueryGroup struct {
	Name     string
	Language string
	Queries  []*Query
}

type ReportStatus struct {
	ReportID  string `json:"reportId"`
	Status    string `json:"status"`
	ReportURL string `json:"url"`
}

type RunningScan struct {
	ScanID    string
	Status    string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ResultsPredicates struct {
	PredicateID  string `json:"ID"`
	SimilarityID int64  `json:"similarityId,string"`
	ProjectID    string `json:"projectId"`
	State        string `json:"state"`
	Comment      string `json:"comment"`
	Severity     string `json:"severity"`
	CreatedBy    string `json:"createdBy"`
	CreatedAt    string `json:"createdAt"`
}

type KeyCloakClient struct {
	ClientID string `json:"id"`
	Name     string `json:"clientId"`
	Enabled  bool
}
type Role struct {
	RoleID      string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Attributes  struct {
		Creator    []string
		Type       []string
		Category   []string
		LastUpdate []string // it is returned as [ "uint",... ]
	} `json:"attributes"`
	Composite  bool `json:"composite"`
	ClientRole bool `json:"clientRole"`
}

type Scan struct {
	ScanID        string              `json:"id"`
	Status        string              `json:"status"`
	StatusDetails []ScanStatusDetails `json:"statusDetails"`
	Branch        string              `json:"branch"`
	CreatedAt     string              `json:"createdAt"`
	UpdatedAt     string              `json:"updatedAt"`
	ProjectID     string              `json:"projectId"`
	ProjectName   string              `json:"projectName"`
	UserAgent     string              `json:"userAgent"`
	Initiator     string              `json:"initiator"`
	Tags          map[string]string   `json:"tags"`
	Metadata      struct {
		Type    string              `json:"type"`
		Configs []ScanConfiguration `json:"configs"`
	} `json:"metadata"`
	Engines      []string `json:"engines"`
	SourceType   string   `json:"sourceType"`
	SourceOrigin string   `json:"sourceOrigin"`
}

type ScanConfiguration struct {
	ScanType string            `json:"type"`
	Values   map[string]string `json:"value"`
}

type ScanMetadata struct {
	ScanID                string
	ProjectID             string
	LOC                   uint64
	FileCount             uint64
	IsIncremental         bool
	IsIncrementalCanceled bool
	PresetName            string `json:"queryPreset"`
}

type ScanResultData struct {
	QueryID      uint64
	QueryName    string
	Group        string
	ResultHash   string
	LanguageName string
	Nodes        []ScanResultNodes
}

type ScanResultNodes struct {
	ID          string
	Line        uint64
	Name        string
	Column      uint64
	Length      uint64
	Method      string
	NodeID      uint64
	DOMType     string
	FileName    string
	FullName    string
	TypeName    string
	MethodLine  uint64
	Definitions string
}

type ScanResult struct {
	Type                 string
	ResultID             string `json:"id"`
	SimilarityID         int64  `json:"similarityId,string"`
	Status               string
	State                string
	Severity             string
	CreatedAt            string `json:"created"`
	FirstFoundAt         string
	FoundAt              string
	FirstScanId          string
	Description          string
	Data                 ScanResultData
	VulnerabilityDetails ScanResultDetails
}

type ScanResultDetails struct {
	CweId       int
	Compliances []string
}

type ScanStatusDetails struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type ScanResultStatusSummary struct {
	ToVerify               uint64
	NotExploitable         uint64
	Confirmed              uint64
	ProposedNotExploitable uint64
	Urgent                 uint64
}

type ScanResultSummary struct {
	High        ScanResultStatusSummary
	Medium      ScanResultStatusSummary
	Low         ScanResultStatusSummary
	Information ScanResultStatusSummary
}

// Very simplified for now
type ScanSummary struct {
	TenantID     string
	ScanID       string
	SASTCounters struct {
		//QueriesCounters           []?
		//SinkFileCounters          []?
		LanguageCounters []struct {
			Language string
			Counter  uint64
		}
		ComplianceCounters []struct {
			Compliance string
			Counter    uint64
		}
		SeverityCounters []struct {
			Severity string
			Counter  uint64
		}
		StatusCounters []struct {
			Status  string
			Counter uint64
		}
		StateCounters []struct {
			State   string
			Counter uint64
		}
		TotalCounter        uint64
		FilesScannedCounter uint64
	}
	// ignoring the other counters
	// KICSCounters
	// SCACounters
	// SCAPackagesCounters
	// SCAContainerCounters
	// APISecCounters
}

type Status struct {
	ID      int               `json:"id"`
	Name    string            `json:"name"`
	Details ScanStatusDetails `json:"details"`
}

type User struct {
	Enabled   bool     `json:"enabled"`
	UserID    string   `json:"id,omitempty"`
	FirstName string   `json:"firstName"`
	LastName  string   `json:"lastName"`
	UserName  string   `json:"username"`
	Email     string   `json:"email"`
	Groups    []string `json:"groups"`
}

type WorkflowLog struct {
	Source    string `json:"Source"`
	Info      string `json:"Info"`
	Timestamp string `json:"Timestamp"`
}
