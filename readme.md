This is a basic CheckmarxOne REST API client written in GoLang

There are many gaps in the functionality so this is best used as an example for custom work, however if you wish to contribute then feel free to submit additions.

Example usage:


package main

import (
	"github.com/cxpsemea/Cx1ClientGo"
	"fmt"
	"os"
)

func main() {
	fmt.Println( "Starting" )

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]

	cx1client, err := Cx1ClientGo.NewAPIKeyClient( base_url, iam_url, tenant, api_key )
	if err != nil {
		fmt.Println( "Error creating client: " + err.Error() )
	}

	// no err means that the client is initialized
	fmt.Println( "Client initialized: " + cx1client.ToString() )
}