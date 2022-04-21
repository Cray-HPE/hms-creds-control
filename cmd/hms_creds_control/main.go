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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	base "github.com/Cray-HPE/hms-base"
	compcredentials "github.com/Cray-HPE/hms-compcredentials"
	"github.com/Cray-HPE/hms-creds-control/internal/http_logger"
	dns_dhcp "github.com/Cray-HPE/hms-dns-dhcp/pkg"
	securestorage "github.com/Cray-HPE/hms-securestorage"
	rf "github.com/Cray-HPE/hms-smd/pkg/redfish"
	trsapi "github.com/Cray-HPE/hms-trs-app-api/pkg/trs_http_api"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	hsmURL = flag.String("hsm_url", "http://cray-smd", "State Manager URL")

	httpClient *retryablehttp.Client

	atomicLevel zap.AtomicLevel
	logger      *zap.Logger

	dhcpdnsClient dns_dhcp.DNSDHCPHelper

	secureStorage      securestorage.SecureStorage
	hsmCredentialStore *compcredentials.CompCredStore

	serviceName string

	baseTrsTask trsapi.HttpTask
	trsRf       trsapi.TrsAPI
)

type RedfishEndpointArray struct {
	RedfishEndpoints []rf.RedfishEPDescription `json:"RedfishEndpoints"`
}

type HmsCreds struct {
	Xname    string `json:"Xname"`
	Username string `json:"Username"`
	Password string `json:"password"`
}

type Hardware struct {
	Xname       string
	Endpoint    rf.RedfishEPDescription
	Credentials HmsCreds
	AccountUris []string
}

type RedfishAccounts struct {
	Name    string `json:"Name"`
	Count   int    `json:"Members@odata.count"`
	Members []struct {
		Path string `json:"@odata.id"`
	}
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

func setupTrs() (err error) {
	serviceName, err := base.GetServiceInstanceName()
	if err != nil {
		serviceName = "CredsControl"
		logger.Info("WARNING: could not get service name. Using the default name: " + serviceName)
	}
	logger.Info("Service name: " + serviceName)

	baseTrsTask.ServiceName = serviceName
	baseTrsTask.Timeout = 40 * time.Second
	baseTrsTask.Request, _ = http.NewRequest("GET", "", nil)
	baseTrsTask.Request.Header.Set("Content-Type", "application/json")
	baseTrsTask.Request.Header.Add("HMS-Service", baseTrsTask.ServiceName)

	logy := logrus.New()
	logy.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logy.SetLevel(logrus.InfoLevel)
	logy.SetReportCaller(true)
	trsImplementation := os.Getenv("TRS_IMPLEMENTATION")
	if trsImplementation == "REMOTE" {
		tmpTrsRf := &trsapi.TRSHTTPRemote{}
		tmpTrsRf.Logger = logy
		trsRf = tmpTrsRf
	} else {
		tmpTrsRf := &trsapi.TRSHTTPLocal{}
		tmpTrsRf.Logger = logy
		trsRf = tmpTrsRf
	}

	trsRf.Init(serviceName, logy)
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
	nodes := make(map[string]Hardware)

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

	err = setupTrs()
	if err != nil {
		logger.Error("Unable to setup trs:", zap.Error(err))
		return
	}

	redfishEndpoints := getRedfishEndpointsFromHSM()
	for _, endpoint := range redfishEndpoints {
		status := endpoint.DiscInfo.LastStatus
		xname := endpoint.ID
		logger.Info("endpoint: " + xname + " status: " + status)
		path := "hms-creds/" + xname

		if status == "DiscoverOK" {
			var creds HmsCreds
			e := hsmCredentialStore.SS.Lookup(path, &creds)
			if e != nil {
				logger.Error("Vault "+path+":", zap.Error(err))
			} else {
				logger.Info("hms-creds:",
					zap.String("xname:", creds.Xname),
					zap.String("username:", creds.Username))

				nodes[xname] = Hardware{
					Xname:       endpoint.ID,
					Credentials: creds,
					Endpoint:    endpoint,
				}
			}
		}
	}

	nodeKeys := make([]string, 0)
	for key, _ := range nodes {
		nodeKeys = append(nodeKeys, key)
	}

	trsTasks := trsRf.CreateTaskList(&baseTrsTask, len(nodeKeys))

	for i, key := range nodeKeys {
		hardware := nodes[key]
		trsTasks[i].Request.URL, _ = url.Parse("https://" + path.Join(hardware.Xname, "/redfish/v1/AccountService/Accounts"))
		trsTasks[i].Timeout = time.Second * 40
		trsTasks[i].RetryPolicy.Retries = 1
		trsTasks[i].Request.SetBasicAuth(hardware.Credentials.Username, hardware.Credentials.Password)
	}

	responseChannel, err := trsRf.Launch(&trsTasks)
	if err != nil {
		logger.Error("Error launching tasks for /redfish/v1/AccountService/Accounts:", zap.Error(err))
		return
	}
	for range nodeKeys {
		taskResponse := <-responseChannel
		if *taskResponse.Err != nil {
			logger.Error("Error getting accounts:",
				zap.String("uri:", taskResponse.Request.RequestURI),
				zap.Error(*taskResponse.Err),
			)
			continue
		}

		if taskResponse.Request.Response.StatusCode != http.StatusOK {
			logger.Error("Failure getting Accounts",
				zap.String("uri:", taskResponse.Request.RequestURI),
				zap.String("statusCode:", strconv.Itoa(taskResponse.Request.Response.StatusCode)),
			)
			continue
		}

		if taskResponse.Request.Response.Body == nil {
			logger.Error("Failure getting Accounts. Response body was empty",
				zap.String("uri:", taskResponse.Request.RequestURI),
				zap.String("statusCode:", strconv.Itoa(taskResponse.Request.Response.StatusCode)),
			)
			continue
		}

		body, err := ioutil.ReadAll(taskResponse.Request.Response.Body)
		if err != nil {
			logger.Error("Failure getting Accounts. Error reading response body",
				zap.String("uri:", taskResponse.Request.RequestURI),
				zap.String("statusCode:", strconv.Itoa(taskResponse.Request.Response.StatusCode)),
			)
			continue
		}

		var data RedfishAccounts
		err = json.Unmarshal(body, &data)
		if err != nil {
			logger.Error("Failure getting Accounts. Error parsing response body",
				zap.String("uri:", taskResponse.Request.RequestURI),
				zap.String("statusCode:", strconv.Itoa(taskResponse.Request.Response.StatusCode)),
			)
			continue
		}

		// u, err := url.Parse(taskResponse.Request.RequestURI)
		// if err != nil {
		// 	logger.Error("Failure getting Accounts. Error parsing URI",
		// 		zap.String("uri:", taskResponse.Request.RequestURI),
		// 		zap.Error(err),
		// 	)
		// 	continue
		// }

		// xname := u.Host
		xname := taskResponse.Request.Host
		hardware := nodes[xname]
		for _, member := range data.Members {
			hardware.AccountUris = append(hardware.AccountUris, member.Path)
			logger.Info("account uri",
				zap.String("uri:", taskResponse.Request.RequestURI),
				zap.String("host:", taskResponse.Request.Host),
				zap.String("xname:", xname),
				zap.String("account uri:", member.Path),
			)
		}
	}

	logger.Info("Finished creds control process.")
}
