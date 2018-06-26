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

package platform

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

type SAJWTClientImpl struct {
	rootCertFile string
	caAddr       string
	keyFile      string
	scope        string
}

func NewSAJwtClientImpl(rootCertFile, keyFile, caAddr string) *SAJWTClientImpl {
	const scope = "https://www.googleapis.com/auth/xapi.zoo"
	return &SAJWTClientImpl{
		rootCertFile: rootCertFile,
		caAddr:       caAddr,
		keyFile:      keyFile, // TODO read in contents of the file here
		scope:        scope,
	}
}

func (saClient *SAJWTClientImpl) GetDialOptions() ([]grpc.DialOption, error) {
	creds, err := credentials.NewClientTLSFromFile(saClient.rootCertFile, "")
	if err != nil {
		return nil, err
	}

	perRPC, err := oauth.NewServiceAccountFromFile(saClient.keyFile, saClient.scope)
	if err != nil {
		return nil, err
	}

	options := []grpc.DialOption{grpc.WithPerRPCCredentials(perRPC),
		grpc.WithTransportCredentials(creds)}
	return options, nil
}

func (saClient *SAJWTClientImpl) IsProperPlatform() bool {
	return true
}

func (saClient *SAJWTClientImpl) GetServiceIdentity() (string, error) {
	// GetServiceIdentity() is used in nodeagent/vm/nodeagent.go to return
	// the identity of the Node Agent. Since there is no Node Agent identity
	// in this context, we have nothing useful to return.
	return "", fmt.Errorf("GetServiceIdentity() not implemented")
}

func (saClient *SAJWTClientImpl) GetAgentCredential() ([]byte, error) {
	// GetAgentCredential() is used in nodeagent/vm/nodeagent.go to return
	// the credentials of the Node Agent. Since there is no Node Agent credential
	// in this context, we have nothing useful to return.
	return nil, fmt.Errorf("GetAgentCredential() not implemented")
}

func (saClient *SAJWTClientImpl) GetCredentialType() string {
	return "saJWT"
}
