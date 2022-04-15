// MIT License
//
// (C) Copyright [2022] Hewlett Packard Enterprise Development LP
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
	"fmt"
	"io/ioutil"

	compcredentials "github.com/Cray-HPE/hms-compcredentials"
	"github.com/Cray-HPE/hms-creds-control/internal/http_logger"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/namsral/flag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	dns_dhcp "github.com/Cray-HPE/hms-dns-dhcp/pkg"
	securestorage "github.com/Cray-HPE/hms-securestorage"
	rf "github.com/Cray-HPE/hms-smd/pkg/redfish"
)

var (
	hsmURL = flag.String("hsm_url", "http://cray-smd", "State Manager URL")

	httpClient *retryablehttp.Client

	atomicLevel zap.AtomicLevel
	logger      *zap.Logger

	dhcpdnsClient dns_dhcp.DNSDHCPHelper

	secureStorage securestorage.SecureStorage
	hsmCredentialStore *compcredentials.CompCredStore
)

type RedfishEndpointArray struct {
	RedfishEndpoints []rf.RedfishEPDescription `json:"RedfishEndpoints"`
}

func setupLogging() {
	logLevel := os.Getenv("LOG_LEVEL")
	logLevel = strings.ToUpper(logLevel)

	atomicLevel = zap.NewAtomicLevel()

	encoderCfg := zap.NewProductionEncoderConfig()
	logger = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		atomicLevel,
	))

	switch logLevel {
	case "DEBUG":
		atomicLevel.SetLevel(zap.DebugLevel)
	case "INFO":
		atomicLevel.SetLevel(zap.InfoLevel)
	case "WARN":
		atomicLevel.SetLevel(zap.WarnLevel)
	case "ERROR":
		atomicLevel.SetLevel(zap.ErrorLevel)
	case "FATAL":
		atomicLevel.SetLevel(zap.FatalLevel)
	case "PANIC":
		atomicLevel.SetLevel(zap.PanicLevel)
	default:
		atomicLevel.SetLevel(zap.InfoLevel)
	}
}

func setupVault() (err error) {
	secureStorage, err = securestorage.NewVaultAdapter(os.Getenv("VAULT_BASE_PATH"))
	if err != nil {
		return
	}

	hsmCredentialStore = compcredentials.NewCompCredStore("hms-creds", secureStorage)

	return
}

func getRedfishEndpointsFromHSM() (endpoints []rf.RedfishEPDescription) {
	url := fmt.Sprintf("%s/Inventory/RedfishEndpoints", *hsmURL)

	response, err := httpClient.Get(url)
	if err != nil {
		logger.Error("Failed to get RedfishEndpoints from HSM:", zap.Error(err))
	}

	if response.StatusCode != http.StatusOK {
		logger.Error("Unexpected status code from HSM:", zap.Int("response.StatusCode", response.StatusCode))
	}

	jsonBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Error("Failed to read body:", zap.Error(err))
		return
	}
	defer response.Body.Close()

	var redfishEndpoints RedfishEndpointArray
	err = json.Unmarshal(jsonBytes, &redfishEndpoints)
	if err != nil {
		logger.Error("Failed to unmarshal HSM Redfish endpoints json:", zap.Error(err))
		return
	}

	for _, endpoint := range redfishEndpoints.RedfishEndpoints {
	    endpoints = append(endpoints, endpoint)
	}
	return
}

func main() {
	// Parse the arguments.
	flag.Parse()

	*hsmURL = *hsmURL + "/hsm/v1"

	setupLogging()

	// For performance reasons we'll keep the client that was created for this base request and reuse it later.
	httpClient = retryablehttp.NewClient()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient.HTTPClient.Transport = transport

	httpClient.RetryMax = 2
	httpClient.RetryWaitMax = time.Second * 2

	// Also, since we're using Zap logger it make sense to set the logger to use the one we've already setup.
	httpLogger := http_logger.NewHTTPLogger(logger)
	httpClient.Logger = httpLogger

	// Setup the DHCP/DNS client.
	dhcpdnsClient = dns_dhcp.NewDHCPDNSHelper(*hsmURL, httpClient)

	logger.Info("Start creds control process.",
		zap.String("hsmURL", *hsmURL),
	)

    err := setupVault()
	if err != nil {
	    logger.Error("Unable to setup Vault:", zap.Error(err))
	    return
	}

	redfishEndpoints := getRedfishEndpointsFromHSM()
	for _, endpoint := range redfishEndpoints {
		logger.Info(endpoint.ID)
	}

	logger.Info("Finished creds control process.")
}
