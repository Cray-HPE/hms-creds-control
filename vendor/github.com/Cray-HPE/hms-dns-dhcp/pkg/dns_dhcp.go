// MIT License
//
// (C) Copyright [2019, 2021] Hewlett Packard Enterprise Development LP
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

package dns_dhcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/Cray-HPE/hms-base"
	"github.com/Cray-HPE/hms-smd/pkg/sm"
)

type DNSDHCPHelper struct {
    HSMURL string
    HTTPClient *retryablehttp.Client
}

var serviceName string

func NewDHCPDNSHelper(HSMURL string, HTTPClient *retryablehttp.Client) (helper DNSDHCPHelper) {
    helper.HSMURL = HSMURL

    if HTTPClient != nil {
        helper.HTTPClient = HTTPClient
    } else {
        helper.HTTPClient = retryablehttp.NewClient()
    }

    if (serviceName == "") {
        var err error
        serviceName,err = os.Hostname()
        if (err != nil) {
            serviceName = "DNS_DHCP"
        }
    }

    return
}

func NewDHCPDNSHelperInstance(HSMURL string, HTTPClient *retryablehttp.Client, svcName string) (helper DNSDHCPHelper) {
	serviceName = svcName
	return NewDHCPDNSHelper(HSMURL, HTTPClient)
}

func rtGet(helper *DNSDHCPHelper, url string) (*http.Response, error) {
	req,err := http.NewRequest("GET",url,nil)
	if (err != nil) {
		return nil,err
	}
	base.SetHTTPUserAgent(req,serviceName)
	rtReq,rtErr := retryablehttp.FromRequest(req)
	if (rtErr != nil) {
		return nil,rtErr
	}
	rsp, rspErr := helper.HTTPClient.Do(rtReq)
	if (rspErr != nil) {
		return nil,rspErr
	}
	return rsp,nil
}

func (helper *DNSDHCPHelper) GetUnknownComponents() (unknownComponents []sm.CompEthInterface, err error) {
    url := fmt.Sprintf("%s/Inventory/EthernetInterfaces?ComponentID", helper.HSMURL)

    response, err := rtGet(helper,url)
    if err != nil {
        return
    }

    jsonBytes, err := ioutil.ReadAll(response.Body)
    defer response.Body.Close()

    if response.StatusCode != http.StatusOK {
        err = fmt.Errorf("unexpected status code from HSM: %d", response.StatusCode)
        return
    }

    if err != nil {
        return
    }

    err = json.Unmarshal(jsonBytes, &unknownComponents)

    return
}

func (helper *DNSDHCPHelper) GetAllEthernetInterfaces() (unknownComponents []sm.CompEthInterface, err error) {
    url := fmt.Sprintf("%s/Inventory/EthernetInterfaces", helper.HSMURL)

    response, err := helper.HTTPClient.Get(url)
    if err != nil {
        return
    }

    jsonBytes, err := ioutil.ReadAll(response.Body)
    defer response.Body.Close()

    if response.StatusCode != http.StatusOK {
        err = fmt.Errorf("unexpected status code from HSM: %d", response.StatusCode)
        return
    }

    if err != nil {
        return
    }

    err = json.Unmarshal(jsonBytes, &unknownComponents)

    return
}

func (helper *DNSDHCPHelper) AddNewEthernetInterface(newInterface sm.CompEthInterface, patchIfConflict bool) (
    err error) {
    payloadBytes, marshalErr := json.Marshal(newInterface)
    if marshalErr != nil {
        err = fmt.Errorf("failed to marshal interface: %w", marshalErr)
        return
    }

    url := fmt.Sprintf("%s/Inventory/EthernetInterfaces", helper.HSMURL)

    request, requestErr := retryablehttp.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
    if requestErr != nil {
        err = fmt.Errorf("failed to construct request: %w", requestErr)
        return
    }
    request.Header.Set("Content-Type", "application/json")

    response, doErr := helper.HTTPClient.Do(request)
    if doErr != nil {
        err = fmt.Errorf("failed to execute POST request: %w", doErr)
        return
    }

    if (response.Body != nil) {
        _,_ = ioutil.ReadAll(response.Body)
        defer response.Body.Close()
    }

    if response.StatusCode == http.StatusConflict {
        if patchIfConflict {
            err = helper.PatchEthernetInterface(newInterface)
        } else {
            err = fmt.Errorf("failed to add new interface because it already exists")
        }
    } else if response.StatusCode != http.StatusCreated {
        err = fmt.Errorf("unexpected status code (%d): %s", response.StatusCode, response.Status)
    }

    return
}

func (helper *DNSDHCPHelper) PatchEthernetInterface(theInterface sm.CompEthInterface) (err error) {
    payloadBytes, marshalErr := json.Marshal(theInterface)
    if marshalErr != nil {
        err = fmt.Errorf("failed to marshal interface: %w", marshalErr)
        return
    }

    macID := strings.ReplaceAll(theInterface.MACAddr, ":", "")
    url := fmt.Sprintf("%s/Inventory/EthernetInterfaces/%s", helper.HSMURL, macID)

    request, requestErr := retryablehttp.NewRequest("PATCH", url, bytes.NewBuffer(payloadBytes))
    if requestErr != nil {
        err = fmt.Errorf("failed to construct request: %w", requestErr)
        return
    }
    request.Header.Set("Content-Type", "application/json")

    response, doErr := helper.HTTPClient.Do(request)
    if doErr != nil {
        err = fmt.Errorf("failed to execute PATCH request: %w", doErr)
        return
    }
    if (response.Body != nil) {
        _,_ = ioutil.ReadAll(response.Body)
        defer response.Body.Close()
    }

    if response.StatusCode != http.StatusOK {
        err = fmt.Errorf("unexpected status code (%d): %s", response.StatusCode, response.Status)
    }

    return
}
