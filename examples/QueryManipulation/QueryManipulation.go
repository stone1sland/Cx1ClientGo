package main

import (
	"os"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"

	//	"time"
	//fmt"
	"crypto/tls"
	"net/http"
	"net/url"

	"github.com/t-tomalak/logrus-easy-formatter"
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

	available, sessions, err := cx1client.AuditFindSessionsByID(project.ProjectID, lastscan.ScanID)
	session := ""
	if !available && len(sessions) > 0 {
		logger.Warnf("No additional audit sessions are available, but %d matching sessions exist. Re-using the first session %v", len(sessions), sessions[0])
		session = sessions[0]
	} else {

		session, err = cx1client.AuditCreateSessionByID(project.ProjectID, lastscan.ScanID)
		if err != nil {
			logger.Errorf("Error creating cxaudit session: %s", err)
			return
		}
	}

	err = cx1client.AuditEnginePollingByID(session)
	if err != nil {
		logger.Errorf("Error while creating audit engine: %s", err)
		return
	}

	logger.Infof("Engine is ready")

	err = cx1client.AuditCheckLanguagesByID(session)
	if err != nil {
		logger.Errorf("Error while checking languages: %s", err)
		return
	}

	languages, err := cx1client.AuditLanguagePollingByID(session)
	if err != nil {
		logger.Errorf("Error while getting languages: %s", err)
		return
	}

	logger.Infof("Languages present: %v", languages)

	err = cx1client.AuditRunScanByID(session)
	if err != nil {
		logger.Errorf("Error while triggering audit scan: %s", err)
		return
	}

	err = cx1client.AuditScanPollingByID(session)
	if err != nil {
		logger.Errorf("Error while polling audit scan: %s", err)
		return
	}

	// First query: project-level override of an existing query

	code := "base.Spring_Missing_Expect_CT_Header();"
	lang := "Java"
	group := "Java_Spring"
	query := "Spring_Missing_Expect_CT_Header"
	auditQuery, err := cx1client.GetQueryByName("Cx", lang, group, query)
	if err != nil {
		logger.Errorf("Error getting query ID: %s", err)
		return
	}

	err = cx1client.AuditCompileQuery(session, auditQuery.QueryID, project.ProjectID, lang, group, query, code, true, -1, -1)
	if err != nil {
		logger.Errorf("Error triggering query compile: %s", err)
		return
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Errorf("Error while polling compiler: %s", err)
		return
	}

	err = cx1client.UpdateQuery(project.ProjectID, lang, group, query, code)
	if err != nil {
		logger.Errorf("Error saving new query: %s", err)
		return
	} else {
		logger.Infof("Saved new query %v", query)
	}

	// now delete it
	err = cx1client.DeleteQueryByName(project.ProjectID, lang, group, query)
	if err != nil {
		logger.Errorf("Error deleting query: %s", err)
		return
	} else {
		logger.Infof("Query deleted")
	}

	// Second query: create new corp/tenant query
	code = "// test new query"
	lang = "Java"
	group = "Java_Spring"
	query = "TestQuery"
	auditQuery, err = cx1client.GetQueryByName("Cx", lang, "CxDefaultQueryGroup", "CxDefaultQuery")

	err = cx1client.AuditCompileQuery(session, auditQuery.QueryID, "Corp", lang, group, query, code, true, -1, -1)
	if err != nil {
		logger.Errorf("Error triggering query compile: %s", err)
		return
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Errorf("Error while polling compiler: %s", err)
		return
	}

	err = cx1client.AuditCreateQuery(session, lang, group, query, code) // creating a new query is only on Corp level, otherwise it's Update
	if err != nil {
		logger.Errorf("Error overriding old query: %s", err)
		return
	} else {
		logger.Infof("Saved override %v", query)
	}

	// now delete it
	err = cx1client.DeleteQueryByName("Corp", lang, group, query)
	if err != nil {
		logger.Errorf("Error deleting query: %s", err)
		return
	} else {
		logger.Infof("Query deleted")
	}

}
