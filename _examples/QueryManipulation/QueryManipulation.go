package main

import (
	"crypto/tls"
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

	logger.Info("Starting")

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]

	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	httpClient := &http.Client{}
	//httpClient.Transport = transport

	cx1client, err := Cx1ClientGo.NewAPIKeyClient(httpClient, base_url, iam_url, tenant, api_key, logger)
	if err != nil {
		logger.Error("Error creating client: " + err.Error())
		return
	}

	project, err := cx1client.GetProjectByName("simple-javascript-xss-burger")
	if err != nil {
		logger.Errorf("Error getting project: %s", err)
		return
	}

	lastscans, err := cx1client.GetLastScansByStatusAndID(project.ProjectID, 1, []string{"Completed"})
	if err != nil {
		logger.Errorf("Error getting last scan: %s", err)
		return
	}

	lastscan := lastscans[0]

	session, err := cx1client.GetAuditSessionByID(project.ProjectID, lastscan.ScanID)
	if err != nil {
		logger.Errorf("Error getting an audit session: %s", err)
		return
	}

	// First query: project-level override of an existing query
	baseQuery, err := cx1client.GetQueryByName("Cx", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Errorf("Error getting query: %s", err)
		return
	}

	newCorpOverride := baseQuery.CreateOverride("Corp")
	newCorpOverride.Source = "result = base.Spring_Missing_Expect_CT_Header();"

	err = cx1client.AuditCompileQuery(session, newCorpOverride)
	if err != nil {
		logger.Errorf("Error triggering query compile: %s", err)
		return
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Errorf("Error while polling compiler: %s", err)
		return
	}

	err = cx1client.UpdateQuery(session, newCorpOverride)
	if err != nil {
		logger.Errorf("Error saving new query: %s", err)
		return
	} else {
		logger.Infof("Saved new query %v", newCorpOverride.String())
	}

	// now delete it

	//err = cx1client.DeleteQueryByName( project.ProjectID, lang, group, query )
	err = cx1client.DeleteQuery(newCorpOverride)
	if err != nil {
		logger.Errorf("Error deleting query: %s", err)
		return
	} else {
		logger.Infof("Query deleted")
	}

	// Second query: create new corp/tenant query
	newQuery, err := cx1client.AuditCreateQuery("Java", "Java_Spring", "TestQuery")
	newQuery.Source = "result = All.NewCxList(); // TestQuery"

	err = cx1client.AuditCompileQuery(session, newQuery)
	if err != nil {
		logger.Errorf("Error triggering query compile: %s", err)
		return
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Errorf("Error while polling compiler: %s", err)
		return
	}

	err = cx1client.UpdateQuery(session, newQuery)
	if err != nil {
		logger.Errorf("Error creating new corp query: %s", err)
		return
	} else {
		logger.Infof("Saved override %v", newQuery.String())
	}

	// now delete it

	//err = cx1client.DeleteQueryByName( "Corp", lang, group, query )
	err = cx1client.DeleteQuery(newQuery)
	if err != nil {
		logger.Errorf("Error deleting query: %s", err)
		return
	} else {
		logger.Infof("Query deleted")
	}

}
