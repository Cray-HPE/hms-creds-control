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
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	compcredentials "github.com/Cray-HPE/hms-compcredentials"
	"github.com/Cray-HPE/hms-creds-control/internal/http_logger"
	dns_dhcp "github.com/Cray-HPE/hms-dns-dhcp/pkg"
	securestorage "github.com/Cray-HPE/hms-securestorage"
	rf "github.com/Cray-HPE/hms-smd/pkg/redfish"
	trsapi "github.com/Cray-HPE/hms-trs-app-api/pkg/trs_http_api"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/namsral/flag"
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
	bmcCredentialStore *compcredentials.CompCredStore

	serviceName string

	baseTrsTask trsapi.HttpTask
	trsRf       trsapi.TrsAPI

	passwordLength     int
	passwordCharacters []rune
)

type RedfishEndpointArray struct {
	RedfishEndpoints []rf.RedfishEPDescription `json:"RedfishEndpoints"`
}

type Hardware struct {
	Xname             string
	IsDiscoverOk      bool
	Endpoint          *rf.RedfishEPDescription
	HasCredentials    bool
	ComponentUsername string
	ComponentPassword string
	AccountUris       []string
	Accounts          []map[string]interface{}
	Usernames         []UserAccount
}

type UserAccount struct {
	Xname string
	Name  string
	Uri   string
}

type RedfishAccounts struct {
	Name    string `json:"Name"`
	Count   int    `json:"Members@odata.count"`
	Members []struct {
		Path string `json:"@odata.id"`
	}
}

type namePattern struct {
	Include       string
	Exclude       string
	IncludeRegexp *regexp.Regexp
	ExcludeRegexp *regexp.Regexp
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
	bmcCredentialStore = compcredentials.NewCompCredStore("bmc-creds", secureStorage)

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

func endpointsToHardware(endpoints []rf.RedfishEPDescription) map[string]Hardware {
	nodes := make(map[string]Hardware)
	for _, endpoint := range endpoints {
		xname := endpoint.ID
		isDiscoverOk := endpoint.DiscInfo.LastStatus == "DiscoverOK"

		nodes[xname] = Hardware{
			Xname:          xname,
			IsDiscoverOk:   isDiscoverOk,
			Endpoint:       &endpoint,
			HasCredentials: false,
			AccountUris:    make([]string, 0),
			Accounts:       make([]map[string]interface{}, 0),
		}
	}
	return nodes
}

func setupConfigRegexp() (xnamePattern namePattern, usernamePattern namePattern, err error) {
	xnamePattern.Include = os.Getenv("XNAME_INCLUDE")
	xnamePattern.Exclude = os.Getenv("XNAME_EXCLUDE")
	usernamePattern.Include = os.Getenv("USERNAME_INCLUDE")
	usernamePattern.Exclude = os.Getenv("USERNAME_EXCLUDE")
	logger.Info("hms-creds-control-config", zap.String("xname_include", xnamePattern.Include))
	logger.Info("hms-creds-control-config", zap.String("xname_exclude", xnamePattern.Exclude))
	logger.Info("hms-creds-control-config", zap.String("username_include", usernamePattern.Include))
	logger.Info("hms-creds-control-config", zap.String("username_exclude", usernamePattern.Exclude))
	xnamePattern.IncludeRegexp, err = regexp.Compile(xnamePattern.Include)
	if err != nil {
		logger.Error("Failed to parse xname_include: "+xnamePattern.Include, zap.Error(err))
		return
	}
	xnamePattern.ExcludeRegexp, err = regexp.Compile(xnamePattern.Exclude)
	if err != nil {
		logger.Error("Failed to parse xname_exclude: "+xnamePattern.Exclude, zap.Error(err))
		return
	}
	usernamePattern.IncludeRegexp, err = regexp.Compile(usernamePattern.Include)
	if err != nil {
		logger.Error("Failed to parse username_include: "+usernamePattern.Include, zap.Error(err))
		return
	}
	usernamePattern.ExcludeRegexp, err = regexp.Compile(usernamePattern.Exclude)
	if err != nil {
		logger.Error("Failed to parse username_exclude: "+usernamePattern.Exclude, zap.Error(err))
		return
	}

	return
}

func match(pattern namePattern, value string) bool {
	include := false
	exclude := false
	if pattern.Include != "" {
		include = pattern.IncludeRegexp.Match([]byte(value))
	}

	if pattern.Exclude != "" {
		exclude = pattern.ExcludeRegexp.Match([]byte(value))
	}

	if exclude {
		return false
	}
	return include
}

func makeListOfAccountsToModify(nodes map[string]Hardware, xnamePattern namePattern, usernamePattern namePattern) (accountsToModify []UserAccount) {
	for xname, hardware := range nodes {
		matchedXname := match(xnamePattern, xname)
		if matchedXname {
			for _, username := range hardware.Usernames {
				matchedUsername :=
					match(usernamePattern, username.Name) &&
						username.Name != "root" &&
						username.Name != hardware.ComponentUsername
				if matchedUsername {
					accountsToModify = append(accountsToModify, username)
				}
			}
		}
	}
	return
}

func logHardwareInfo(nodes map[string]Hardware) {
	xnames := make([]string, 0, len(nodes))
	for xname := range nodes {
		xnames = append(xnames, xname)
	}
	sort.Strings(xnames)

	for _, xname := range xnames {
		hardware := nodes[xname]

		logger.Info("Summary Hardware",
			zap.String("xname:", xname),
			zap.String("status:", hardware.Endpoint.DiscInfo.LastStatus),
			zap.Bool("hasCreds:", hardware.HasCredentials),
			zap.Int("userCount:", len(hardware.Usernames)),
		)
		for _, username := range hardware.Usernames {
			logger.Info("Summary User",
				zap.String("xname:", username.Xname),
				zap.String("username:", username.Name),
				zap.String("Uri:", username.Uri),
			)
		}
	}
}

func collectVaultCredentials(nodes map[string]Hardware) {
	for key, hardware := range nodes {
		if hardware.IsDiscoverOk {
			compCreds, err := hsmCredentialStore.GetCompCred(hardware.Xname)
			if err != nil {
				logger.Error("Vault failed to get component creds for "+hardware.Xname+":", zap.Error(err))
				continue
			}
			hardware.ComponentUsername = compCreds.Username
			hardware.ComponentPassword = compCreds.Password
			hardware.HasCredentials = true
			nodes[key] = hardware
		}
	}
}

func main() {
	flag.Parse()

	*hsmURL = *hsmURL + "/hsm/v1"

	setupLogging()

	readEnabledString := os.Getenv("READ_ENABLED")
	readEnabled := strings.ToLower(readEnabledString) == "true"
	logger.Info("hms-creds-control-config",
		zap.String("read_enabled", readEnabledString),
		zap.Bool("boolean", readEnabled))

	writeEnabledString := os.Getenv("WRITE_ENABLED")
	writeEnabled := strings.ToLower(writeEnabledString) == "true"
	logger.Info("hms-creds-control-config",
		zap.String("write_enabled", writeEnabledString),
		zap.Bool("boolean", writeEnabled))

	xnamePattern, usernamePattern, err := setupConfigRegexp()
	if err != nil {
		logger.Error("Aborting process due to an invalid config map value", zap.Error(err))
		return
	}

	passwordLengthString := os.Getenv("PASSWORD_LENGTH")
	logger.Info("hms-creds-control-config", zap.String("password_length", passwordLengthString))
	passwordLength, err = strconv.Atoi(passwordLengthString)
	if err != nil {
		logger.Error("Failure parsing password_length from the configmap, hms-creds-control-config. It was not a valid integer",
			zap.Error(err))
		return
	}

	passwordCharacters = []rune(os.Getenv("PASSWORD_CHARACTERS"))
	logger.Info("hms-creds-control-config", zap.String("password_characters", string(passwordCharacters)))
	if len(passwordLengthString) == 0 {
		logger.Error("Failure password_characters had zero characters. This must have at least one character. Set can be set by the configmap: hms-creds-control-config")
		return
	}

	if !readEnabled {
		logger.Info("Did nothing. Reading is disabled by the read_enabled field in the configmap hms-creds-control-config")
		return
	}

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

	err = setupVault()
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
	nodes := endpointsToHardware(redfishEndpoints)

	collectVaultCredentials(nodes)

	collectAccountsUris(nodes)

	collectAccounts(nodes)

	logHardwareInfo(nodes)

	accountsToModify := makeListOfAccountsToModify(nodes, xnamePattern, usernamePattern)

	for _, userAccount := range accountsToModify {
		logger.Info("Modify",
			zap.String("xname", userAccount.Xname),
			zap.String("username", userAccount.Name),
			zap.String("uri", userAccount.Uri))
	}

	if writeEnabled {
		logger.Info("Starting to set the passwords")

		setPasswords(accountsToModify, nodes)

		logger.Info("Finished setting the passwords")
	} else {
		logger.Info("Made no modifications. Modifications are disabled by the write_enabled field in the configmap hms-creds-control-config")
		return
	}

	logger.Info("Finished creds control process.")
}
