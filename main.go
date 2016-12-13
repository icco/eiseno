package main

import (
	"log"

	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeutils"
)

func main() {
	domains := []string{"ops.party"}

	for _, domain := range domains {
		if !acmeutils.ValidateHostname(domain) {
			log.Fatal("%s is not a valid domain", domain)
		}
	}
}
