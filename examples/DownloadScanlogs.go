package main

import (
	"github.com/cxpsemea/CxSASTClientGo"
	log "github.com/sirupsen/logrus"
	"os"
	"net/http"
//	"time"
	"net/url"
	"crypto/tls"
)

func main() {
	logger := log.New()
	logger.SetLevel( log.TraceLevel )
	logger.Info( "Starting" )

	server_url := os.Args[1]
	username := os.Args[2]
	password := os.Args[3]

	proxyURL, err := url.Parse( "http://127.0.0.1:8080" )
	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{ InsecureSkipVerify: true, }
	
	httpClient := &http.Client{}
	//httpClient.Transport = transport

	sastclient, err := CxSASTClientGo.NewTokenClient( httpClient, server_url, username, password, logger )
	if err != nil {
		log.Error( "Error creating client: " + err.Error() )
		return 
	}


	

}