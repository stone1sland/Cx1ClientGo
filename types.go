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
	flags   map[string]bool // initial implementation ignoring "payload" part of the flag
}

type AccessAssignment struct {
	TenantID     string   `json:"tenantID"`
	EntityID     string   `json:"entityID"`
	EntityType   string   `json:"entityType"`
	EntityName   string   `json:"entityName"`
	EntityRoles  []string `json:"entityRoles"`
	ResourceID   string   `json:"resourceID"`
	ResourceType string   `json:"resourceType"`
	ResourceName string   `json:"resourceName"`
	CreatedAt    string   `json:"createdAt"`
}

type AccessibleResource struct {
	ResourceID   string   `json:"resourceId"`
	ResourceType string   `json:"resourceType"`
	Roles        []string `json:"roles"`
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

type AuditQuery struct {
	QueryID            uint64 `json:"Id,string"`
	Level              string
	Path               string
	Modified           string
	Source             string
	Cwe                int64
	Severity           uint
	IsExecutable       bool
	CxDescriptionId    int64
	QueryDescriptionId string

	Language string `json:"-"`
	Group    string `json:"-"`
	Name     string `json:"-"`
	LevelID  string `json:"-"`
}

type AuditQueryMetadata struct {
	Cwe                int64
	CxDescriptionID    int64
	IsExecutable       bool
	Modified           string
	Path               string
	QueryDescriptionID string
	Severity           uint
}

type DataImport struct {
	MigrationId string   `json:"migrationId"`
	Status      string   `json:"status"`
	CreatedAt   string   `json:"createdAt"`
	Logs        []string `json:"logs"`
}

type Group struct {
	GroupID     string              `json:"id"`
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	SubGroups   []Group             `json:"subGroups"`
	ClientRoles map[string][]string `json:"clientRoles"`
	Filled      bool                `json:"-"`
}

type OIDCClient struct {
	ID           string `json:"id"`
	ClientID     string `json:"clientId"`
	Enabled      bool   `json:"enabled"`
	ClientSecret string `json:"secret"`
	Creator      string `json:"-"`
}

type OIDCClientScope struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
}

type Preset struct {
	PresetID    uint64   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Custom      bool     `json:"custom"`
	QueryIDs    []uint64 `json:"-"`
	Filled      bool     `json:"-"`
	Queries     []Query
}

type Project struct {
	ProjectID     string                        `json:"id"`
	Name          string                        `json:"name"`
	CreatedAt     string                        `json:"createdAt"`
	UpdatedAt     string                        `json:"updatedAt"`
	Groups        []string                      `json:"groups"`
	Tags          map[string]string             `json:"tags"`
	RepoUrl       string                        `json:"repoUrl"`
	MainBranch    string                        `json:"mainBranch"`
	Origin        string                        `json:"origin"`
	Criticality   uint                          `json:"criticality"`
	Configuration []ProjectConfigurationSetting `json:"-"`
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
	Group              string `json:"group"`
	Language           string `json:"language"`
	Severity           string `json:"severity"`
	CweID              int64  `json:"cweID"`
	QueryDescriptionId int64  `json:"queryDescriptionId"`
	Custom             bool   `json:"custom"`
}

type QueryGroup struct {
	Name     string
	Language string
	Queries  []Query
}

type QueryLanguage struct {
	Name        string
	QueryGroups []QueryGroup
}

type QueryCollection struct {
	QueryLanguages []QueryLanguage
}

type QueryUpdate struct { // used when saving queries in Cx1
	Name   string `json:"name"`
	Path   string `json:"path"`
	Source string `json:"source"`
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

/*
type KeyCloakClient struct {
	ClientID string `json:"id"`
	Name     string `json:"clientId"`
	Enabled  bool
}*/

type Role struct {
	ClientID    string `json:"containerId"` // the 'client' in Keycloak - AST roles with have the "ast-app" client ID
	RoleID      string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Attributes  struct {
		Creator    []string
		Type       []string
		Category   []string
		LastUpdate []string // it is returned as [ "uint",... ]
	} `json:"attributes"`
	Composite  bool   `json:"composite"`
	ClientRole bool   `json:"clientRole"`
	SubRoles   []Role `json:"-"`
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

type ScanFilter struct {
	Limit     int      `json:"limit"`
	Offset    int      `json:"offset"`
	TagKeys   []string `json:"tags-keys"`
	TagValues []string `json:"tags-values"`
	Statuses  []string `json:"statuses"`
	Branches  []string `json:"branches"`
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
	Enabled   bool    `json:"enabled"`
	UserID    string  `json:"id,omitempty"`
	FirstName string  `json:"firstName"`
	LastName  string  `json:"lastName"`
	UserName  string  `json:"username"`
	Email     string  `json:"email"`
	Groups    []Group `json:"-"` // only returned from regular /auth/realms/../user endpoint, as string IDs
	Roles     []Role  `json:"-"` // only returned from regular /auth/realms/../user endpoint, as string IDs
}

type WhoAmI struct {
	UserID string `json:"userId"`
	Name   string `json:"displayName"`
}

type WorkflowLog struct {
	Source    string `json:"Source"`
	Info      string `json:"Info"`
	Timestamp string `json:"Timestamp"`
}
