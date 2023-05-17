package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.TraceLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	if len(os.Args) < 5 {
		log.Fatalf("Usage: go run . <cx1 url> <iam url> <tenant> <api key>")
	}

	logger.Info("Starting")

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]

	proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	httpClient := &http.Client{}
	httpClient.Transport = transport

	cx1client, err := Cx1ClientGo.NewAPIKeyClient(httpClient, base_url, iam_url, tenant, api_key, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	project, err := cx1client.GetProjectByName("ssba-anotheraudittest")
	if err != nil {
		logger.Fatalf("Error getting project: %s", err)
	}

	lastscans, err := cx1client.GetLastScansByStatusAndID(project.ProjectID, 1, []string{"Completed"})
	if err != nil {
		logger.Fatalf("Error getting last scan: %s", err)
	}

	lastscan := lastscans[0]

	session, err := cx1client.GetAuditSessionByID(project.ProjectID, lastscan.ScanID, false)
	if err != nil {
		logger.Fatalf("Error getting an audit session: %s", err)
	}

	newCorpOverride(cx1client, logger, session)
	newProjectOverride(cx1client, logger, session, project.ProjectID)
	newCorpQuery(cx1client, logger, session)

}

func newCorpOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session string) {
	// First query: Tenant-level override of an existing query
	baseQuery, err := cx1client.GetQueryByName("Cx", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Error getting query: %s", err)
	}

	newCorpOverride := baseQuery.CreateTenantOverride()
	newCorpOverride.Source = "result = base.Spring_Missing_Expect_CT_Header(); // corp override"

	err = cx1client.AuditCompileQuery(session, newCorpOverride)
	if err != nil {
		logger.Fatalf("Error triggering query compile: %s", err)
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Fatalf("Error while polling compiler: %s", err)
	}

	err = cx1client.UpdateQuery(newCorpOverride)
	if err != nil {
		logger.Fatalf("Error saving new query: %s", err)
	} else {
		logger.Infof("Saved new query %v", newCorpOverride.String())
	}

	nq, err := cx1client.GetQueryByName("Corp", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Failed to get new corp query: %s", err)
	}

	logger.Infof("Created new corp override: %v", nq)

	// now delete it
	//err = cx1client.DeleteQueryByName( "Corp", lang, group, query )
	err = cx1client.DeleteQuery(newCorpOverride)
	if err != nil {
		logger.Fatalf("Error deleting query: %s", err)
	} else {
		logger.Infof("Query deleted")
	}
}

func newProjectOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session, projectId string) {
	// First query: Tenant-level override of an existing query
	baseQuery, err := cx1client.GetQueryByName("Cx", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Error getting query: %s", err)
	}
	// Second query: project-level override of existing query
	cx1client.AuditSessionKeepAlive(session)
	newProjectOverride := baseQuery.CreateProjectOverrideByID(projectId)
	newProjectOverride.Source = "result = base.Spring_Missing_Expect_CT_Header(); // project override"

	err = cx1client.AuditCompileQuery(session, newProjectOverride)
	if err != nil {
		logger.Fatalf("Error triggering query compile: %s", err)
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Fatalf("Error while polling compiler: %s", err)
	}

	err = cx1client.UpdateQuery(newProjectOverride)
	if err != nil {
		logger.Fatalf("Error saving new query: %s", err)
	} else {
		logger.Infof("Saved new query %v", newProjectOverride.String())
	}

	nq, err := cx1client.GetQueryByName(projectId, "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Failed to get new project override: %s", err)
	}

	logger.Infof("Created new corp query: %v", nq)

	// now delete it
	//err = cx1client.DeleteQueryByName( project.ProjectID, lang, group, query )
	err = cx1client.DeleteQuery(newProjectOverride)
	if err != nil {
		logger.Fatalf("Error deleting query: %s", err)
	} else {
		logger.Infof("Query deleted")
	}
}

func newCorpQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session string) {
	// Third query: create new corp/tenant query
	cx1client.AuditSessionKeepAlive(session)
	newQuery, err := cx1client.AuditNewQuery("Java", "Java_Spring", "TestQuery")
	if err != nil {
		logger.Fatalf("Error creating query: %s", err)
	}

	newQuery.Source = "result = All.NewCxList(); // TestQuery"
	newQuery.IsExecutable = true
	newQuery, err = cx1client.AuditCreateCorpQuery(session, newQuery)
	if err != nil {
		logger.Fatalf("Error creating new corp-level query: %s", err)
	}

	err = cx1client.AuditCompileQuery(session, newQuery)
	if err != nil {
		logger.Fatalf("Error triggering query compile: %s", err)
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Fatalf("Error while polling compiler: %s", err)
	}

	err = cx1client.UpdateQuery(newQuery)
	if err != nil {
		logger.Fatalf("Error creating new corp query: %s", err)
	} else {
		logger.Infof("Saved override %v", newQuery.String())
	}

	nq, err := cx1client.GetQueryByName("Corp", "Java", "Java_Spring", "TestQuery")
	if err != nil {
		logger.Fatalf("Failed to get new corp query: %s", err)
	}

	logger.Infof("Created new corp query: %v", nq)

	// now delete it
	//err = cx1client.DeleteQueryByName( "Corp", lang, group, query )
	err = cx1client.DeleteQuery(newQuery)
	if err != nil {
		logger.Fatalf("Error deleting query: %s", err)
	} else {
		logger.Infof("Query deleted")
	}
}
