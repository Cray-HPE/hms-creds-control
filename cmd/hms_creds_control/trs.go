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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	base "github.com/Cray-HPE/hms-base"
	trsapi "github.com/Cray-HPE/hms-trs-app-api/pkg/trs_http_api"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

type RedfishRequest struct {
	Uri      string
	Username string
	Password string
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

func setAccountsUris(nodes map[string]Hardware) {
	count := 0
	for _, hardware := range nodes {
		if hardware.HasCredentials {
			count++
		}
	}
	tasks := trsRf.CreateTaskList(&baseTrsTask, count)

	i := 0
	for _, hardware := range nodes {
		if hardware.HasCredentials {
			tasks[i].Request.URL, _ = url.Parse("https://" + path.Join(hardware.Xname, "/redfish/v1/AccountService/Accounts"))
			tasks[i].Timeout = time.Second * 40
			tasks[i].RetryPolicy.Retries = 1
			tasks[i].Request.SetBasicAuth(hardware.Credentials.Username, hardware.Credentials.Password)
			i++
		}
	}

	responseChannel, err := trsRf.Launch(&tasks)
	if err != nil {
		logger.Error("Error launching tasks for /redfish/v1/AccountService/Accounts:", zap.Error(err))
		return
	}
	for range tasks {
		taskResponse := <-responseChannel
		if *taskResponse.Err != nil {
			logger.Error("Error getting accounts:",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Error(*taskResponse.Err),
			)
			continue
		}

		if taskResponse.Request.Response.StatusCode != http.StatusOK {
			logger.Error("Failure getting Accounts",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Int("statusCode:", taskResponse.Request.Response.StatusCode),
			)
			continue
		}

		if taskResponse.Request.Response.Body == nil {
			logger.Error("Failure getting Accounts. Response body was empty",
				zap.Any("uri:", taskResponse.Request.URL),
			)
			continue
		}

		body, err := ioutil.ReadAll(taskResponse.Request.Response.Body)
		if err != nil {
			logger.Error("Failure getting Accounts. Error reading response body",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Error(err),
			)
			continue
		}

		var data RedfishAccounts
		err = json.Unmarshal(body, &data)
		if err != nil {
			logger.Error("Failure getting Accounts. Error parsing response body",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Any("body:", body),
			)
			continue
		}

		xname := taskResponse.Request.URL.Host
		hardware := nodes[xname]
		for _, member := range data.Members {
			hardware.AccountUris = append(hardware.AccountUris, member.Path)
		}
		nodes[xname] = hardware
	}
}

func setAccounts(nodes map[string]Hardware) {
	requests := make([]RedfishRequest, 0)
	for _, hardware := range nodes {
		for _, accountUri := range hardware.AccountUris {
			request := RedfishRequest{
				Uri:      path.Join(hardware.Xname, accountUri),
				Username: hardware.Credentials.Username,
				Password: hardware.Credentials.Password,
			}
			requests = append(requests, request)
		}
	}

	tasks := trsRf.CreateTaskList(&baseTrsTask, len(requests))
	for i, request := range requests {
		tasks[i].Request.URL, _ = url.Parse("https://" + request.Uri)
		tasks[i].Timeout = time.Second * 40
		tasks[i].RetryPolicy.Retries = 1
		tasks[i].Request.SetBasicAuth(request.Username, request.Password)
	}

	responseChannel, err := trsRf.Launch(&tasks)
	if err != nil {
		logger.Error("Error launching tasks for /redfish/v1/AccountService/Accounts/id:", zap.Error(err))
		return
	}

	for range tasks {
		taskResponse := <-responseChannel
		if *taskResponse.Err != nil {
			logger.Error("Error getting account:",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Error(*taskResponse.Err),
			)
			continue
		}

		if taskResponse.Request.Response.StatusCode != http.StatusOK {
			logger.Error("Failure getting account",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Int("statusCode:", taskResponse.Request.Response.StatusCode),
			)
			continue
		}

		if taskResponse.Request.Response.Body == nil {
			logger.Error("Failure getting account. Response body was empty",
				zap.Any("uri:", taskResponse.Request.URL),
			)
			continue
		}

		body, err := ioutil.ReadAll(taskResponse.Request.Response.Body)
		if err != nil {
			logger.Error("Failure getting account. Error reading response body",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Error(err),
			)
			continue
		}

		var data map[string]interface{}
		err = json.Unmarshal(body, &data)
		if err != nil {
			logger.Error("Failure getting Accounts. Error parsing response body",
				zap.Any("uri:", taskResponse.Request.URL),
				zap.Any("body:", body),
			)
			continue
		}

		xname := taskResponse.Request.URL.Host
		hardware := nodes[xname]
		hardware.Accounts = append(hardware.Accounts, data)
		nodes[xname] = hardware
	}
}
