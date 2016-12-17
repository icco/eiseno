package main

import (
	"log"

	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeutils"
)

func main() {
	hostnames := []string{"ops.party"}

	// Ensure all hostnames provided are valid.
	for idx := range hostnames {
		norm, err := acmeutils.NormalizeHostname(hostnames[idx])
		if err != nil {
			log.Fatalf("invalid hostname: %#v: %v", hostnames[idx], err)
			return
		}
		hostnames[idx] = norm
	}

}
