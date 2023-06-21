package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

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

	accessAssignments, err := cx1client.CheckAccessibleResources([]string{"tenant", "project", "application"}, "ast-scanner")
	if err != nil {
		logger.Fatalf("Failed to check current user access assignments: %s", err)
	}

	logger.Infof("Current user has the following access: ")
	for _, a := range accessAssignments {
		logger.Infof(" - %v %v: %v", a.ResourceType, a.ResourceName, strings.Join(a.EntityRoles, ", "))
	}

	tenantId := cx1client.GetTenantID()
	hasAccess, err := cx1client.CheckAccessToResourceByID(tenantId, "tenant", "ast-scanner")
	if err != nil {
		logger.Fatalf("Failed to check current user's access to tenant %v: %s", tenantId, err)
	}

	logger.Infof("Current user has ast-scanner access to tenant %v: %b", tenantId, hasAccess)

	//	testclient, err := cx1client.CreateClient("cx1clientgo-test")

}
