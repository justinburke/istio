// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"log"
	"time"

	"istio.io/istio/security/pkg/caclient"
	"istio.io/istio/security/pkg/caclient/protocol"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/istio/security/pkg/platform"
)

var (
	caAddr    = flag.String("caAddr", "", "CA API endpoint. Eg.: api.example.com:443")
	rootCerts = flag.String("rootCerts", "", "Root certificate trust store file")
	jsonFile  = flag.String("jsonFile", "", "Service account JSON credentials file")
)

func startManagement() {
	log.Printf("Starting Node Agent")

	platformClient, err := platform.NewClient("saJWT", *rootCerts, *jsonFile, "unused certChainFile", *caAddr)
	if err != nil {
		log.Fatalf("Error creating platform client: %v", err)
	}

	dialOptions, err := platformClient.GetDialOptions()
	if err != nil {
		log.Fatalf("Error creating gRPC dial options: %v", err)
	}

	caProtocol, err := protocol.NewGrpcConnection(*caAddr, dialOptions)
	if err != nil {
		log.Fatalf("Error configuring gRPC connection: %v", err)
	}

	maxRetries := 1
	interval := time.Hour
	client, err := caclient.NewCAClient(platformClient, caProtocol, maxRetries, interval)
	if err != nil {
		log.Fatalf("Error creating CA client: %v", err)
	}

	log.Printf("Retrieving certificate using client with type %v", client)
	certChain, privateKey, err := client.Retrieve(&util.CertOptions{
		Host:       "spiffe://accounts.google.com/1234123412341234",
		IsCA:       false,
		RSAKeySize: 2048,
	})

	if err != nil {
		log.Fatalf("Error retrieving certificate: %v", err)
	} else {

		log.Printf("certChain = %s", certChain)
		log.Printf("privateKey = %s", privateKey)
	}
}

func main() {
	flag.Parse()
	startManagement()
}
