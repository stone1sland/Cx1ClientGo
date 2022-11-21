This is a basic CheckmarxOne REST API client written in GoLang

There are many gaps in the functionality so this is best used as an example for custom work, however if you wish to contribute then feel free to submit additions.

Example usage:


```golang
package main

import (
	"github.com/cxpsemea/Cx1ClientGo"
	log "github.com/sirupsen/logrus"
	"os"
    "net/http"
)

func main() {
	logger := log.New()
	logger.Info( "Starting" )

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]

	cx1client, err := Cx1ClientGo.NewAPIKeyClient( &http.Client{}, base_url, iam_url, tenant, api_key, logger )
	if err != nil {
		log.Error( "Error creating client: " + err.Error() )
		return 
	}

	// no err means that the client is initialized
	logger.Info( "Client initialized: " + cx1client.ToString() )
}
```