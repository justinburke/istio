package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/metadata"
	pb "istio.io/istio/security/proto/istioca"
)

const defaultName = "world"

var (
	addr         = flag.String("addr", "127.0.0.1:50051", "Address of grpc server.")
	key          = flag.String("api-key", "", "API key.")
	token        = flag.String("token", "", "Authentication token.")
	keyfile      = flag.String("keyfile", "", "Path to a Google service account key file.")
	audience     = flag.String("audience", "", "Audience.")
	rootCertFile = flag.String("rootCertFile", "", "Root certificates file.")
)

func main() {
	flag.Parse()

	// Set up a connection to the server.
	creds, err := credentials.NewClientTLSFromFile(*rootCertFile, "")
	if err != nil {
		log.Fatalf("Unable to read root certificate file")
	}

	scope := "https://www.googleapis.com/auth/xapi.zoo"
	perRPC, _ := oauth.NewServiceAccountFromFile(*keyfile, scope)

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(perRPC))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewIstioCertificateServiceClient(conn)

	if *keyfile != "" {
		log.Printf("Authenticating using Google service account key in %s", *keyfile)
		keyBytes, err := ioutil.ReadFile(*keyfile)
		if err != nil {
			log.Fatalf("Unable to read service account key file %s: %v", *keyfile, err)
		}

		tokenSource, err := google.JWTAccessTokenSourceFromJSON(keyBytes, *audience)
		if err != nil {
			log.Fatalf("Error building JWT access token source: %v", err)
		}
		jwt, err := tokenSource.Token()
		if err != nil {
			log.Fatalf("Unable to generate JWT token: %v", err)
		}
		*token = jwt.AccessToken
		// NOTE: the generated JWT token has a 1h TTL.
		// Make sure to refresh the token before it expires by calling TokenSource.Token() for each outgoing requests.
		// Calls to this particular implementation of TokenSource.Token() are cheap.
	}

	ctx := context.Background()
	if *key != "" {
		log.Printf("Using API key: %s", *key)
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-api-key", *key))
	}
	if *token != "" {
		log.Printf("Using authentication token: %s", *token)
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", fmt.Sprintf("Bearer %s", *token)))
	}

	// Contact the server and print out its response.
	r, err := c.CreateCertificate(ctx, &pb.IstioCertificateRequest{SubjectId: "foo"})
	if err != nil {
		log.Fatalf("Call failed: %v", err)
	}
	log.Printf("Result: %s", r.CertChain)
}
