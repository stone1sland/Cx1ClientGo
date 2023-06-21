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

	allAccess, accessibleResources, err := cx1client.CheckAccessibleResources([]string{"tenant", "project", "application"}, "ast-scanner")
	if err != nil {
		logger.Fatalf("Failed to check current user access assignments: %s", err)
	}

	logger.Infof("Current user has access to all: %t", allAccess)
	logger.Infof("Current user has the following resources accessible: ")
	for _, a := range accessibleResources {
		logger.Infof(" - %v %v: %v", a.ResourceType, a.ResourceID)
	}

	tenantId := cx1client.GetTenantID()
	hasAccess, err := cx1client.CheckAccessToResourceByID(tenantId, "tenant", "ast-scanner")
	if err != nil {
		logger.Fatalf("Failed to check current user's access to tenant %v: %s", tenantId, err)
	}

	logger.Infof("Current user has ast-scanner access to tenant %v: %t", tenantId, hasAccess)

	/*testclient, err := cx1client.CreateClient("cx1clientgo_test")
	if err != nil {
		logger.Errorf("Failed to create oidc client 'cx1clientgo_test': %s", err)
	}*/
	testclient, err := cx1client.GetClientByName("cx1clientgo_test")
	if err != nil {
		logger.Fatalf("Failed to find existing OIDC Client 'cx1clientgo_test' - please create this OIDC client. Error: %s", err)
	}

	user, err := cx1client.GetServiceAccountByID(testclient.ID)
	if err != nil {
		logger.Fatalf("Failed to get service account for oidc client 'cx1clientgo_test': %s", err)
	}

	logger.Infof("cx1clientgo_test oidc client service account user is: %v", user.String())

	scanner_role, err := cx1client.GetRoleByName("ast-scanner")
	if err != nil {
		logger.Fatalf("Failed to find 'ast-scanner' role: %s", err)
	}

	err = cx1client.AddUserRoles(&user, &[]Cx1ClientGo.Role{scanner_role})
	if err != nil {
		logger.Fatalf("Failed to add 'ast-scanner' role to user: %s", err)
	}

	access := Cx1ClientGo.AccessAssignment{
		TenantID:     tenantId,
		ResourceID:   tenantId,
		ResourceType: "tenant",
		ResourceName: tenant,
		EntityID:     user.UserID,
		EntityType:   "user",
		EntityName:   "cx1clientgo_test",
	}
	err = cx1client.AddAccessAssignment(access)
	if err != nil {
		logger.Fatalf("Failed to assign access: %s", err)
	}

	accessAssignment, err := cx1client.GetEntitiesAccessToResourceByID(tenantId, "tenant")
	if err != nil {
		logger.Fatalf("Failed to get entities with access to tenant: %s", err)
	}

	logger.Info("The following access assignments exist for tenant:")
	for _, a := range accessAssignment {
		logger.Infof(" - Entity %v has roles %v", a.EntityID, strings.Join(a.EntityRoles, ", "))
	}

	/*err = cx1client.DeleteClientByID(testclient.ID)
	if err != nil {
		logger.Fatalf("Failed to delete oidc client 'cx1clientgo_test': %s", err)
	}*/

}
