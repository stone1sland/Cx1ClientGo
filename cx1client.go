package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	//"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var cxOrigin = "Cx1-Golang-Client"
var astAppID string

func init() {

}

// Main entry for users of this client:
func NewOAuthClient(client *http.Client, base_url string, iam_url string, tenant string, client_id string, client_secret string, logger *logrus.Logger) (*Cx1Client, error) {
	token, err := getTokenOIDC(client, iam_url, tenant, client_id, client_secret, logger)
	if err != nil {
		return nil, err
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	cli := Cx1Client{client, token, base_url, iam_url, tenant, logger}
	return &cli, nil
}

func NewAPIKeyClient(client *http.Client, base_url string, iam_url string, tenant string, api_key string, logger *logrus.Logger) (*Cx1Client, error) {
	token, err := getTokenAPIKey(client, iam_url, tenant, api_key, logger)
	if err != nil {
		return nil, err
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	cli := Cx1Client{client, token, base_url, iam_url, tenant, logger}
	return &cli, nil
}

func getTokenOIDC(client *http.Client, iam_url string, tenant string, client_id string, client_secret string, logger *logrus.Logger) (string, error) {
	login_url := fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", client_id)
	data.Set("client_secret", client_secret)

	logger.Infof("Authenticating with Cx1 at: %v", login_url)

	cx1_req, err := http.NewRequest(http.MethodPost, login_url, strings.NewReader(data.Encode()))
	cx1_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		logger.Errorf("Error: %s", err)
		return "", err
	}

	res, err := client.Do(cx1_req)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		logger.Errorf("Error: %s", err)
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if err == nil {
		if jsonBody["access_token"] == nil {
			logger.Errorf("Response does not contain access token: %v", string(resBody))
			return "", errors.New("Response does not contain access token")
		} else {
			return jsonBody["access_token"].(string), nil
		}
	} else {
		logger.Errorf("Error parsing response: %s", err)
		logger.Tracef("Input was: %s", string(resBody))
		return "", err
	}
}

func getTokenAPIKey(client *http.Client, iam_url string, tenant string, api_key string, logger *logrus.Logger) (string, error) {
	login_url := fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", "ast-app")
	data.Set("refresh_token", api_key)

	logger.Infof("Authenticating with Cx1 at: %v", login_url)

	cx1_req, err := http.NewRequest(http.MethodPost, login_url, strings.NewReader(data.Encode()))
	cx1_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		logger.Errorf("Error: %s", err)
		return "", err
	}

	res, err := client.Do(cx1_req)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		logger.Errorf("Error: %s", err)
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if err == nil {
		if jsonBody["access_token"] == nil {
			logger.Errorf("Response does not contain access token: %v", string(resBody))
			return "", errors.New("Response does not contain access token")
		} else {
			return jsonBody["access_token"].(string), nil
		}
	} else {
		logger.Errorf("Error parsing response: %s", err)
		logger.Tracef("Input was: %v", string(resBody))
		return "", err
	}
}

func (c *Cx1Client) GetToken() string {
	return c.authToken
}

func (c *Cx1Client) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

	for name, headers := range *header {
		for _, h := range headers {
			request.Header.Add(name, h)
		}
	}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.authToken))
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0")
	}

	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

	return request, nil
}

func (c *Cx1Client) sendRequestInternal(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	var requestBody io.Reader
	var bodyBytes []byte

	c.logger.Debugf("Sending request to URL %v", url)

	if body != nil {
		closer := io.NopCloser(body)
		bodyBytes, _ := io.ReadAll(closer)
		requestBody = bytes.NewBuffer(bodyBytes)
		defer closer.Close()
	}

	request, err := c.createRequest(method, url, requestBody, &header, nil)
	if err != nil {
		c.logger.Errorf("Unable to create request: %s", err)
		return []byte{}, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		resBody, _ := io.ReadAll(response.Body)
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		c.logger.Errorf("HTTP request failed with error: %s", err)
		return resBody, err
	}
	if response.StatusCode >= 400 {
		resBody, _ := io.ReadAll(response.Body)
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		c.logger.Errorf("HTTP response indicates error: %v", response.Status)
		return resBody, errors.New("HTTP Response: " + response.Status)
	}

	resBody, err := io.ReadAll(response.Body)

	if err != nil {
		if err.Error() == "remote error: tls: user canceled" {
			c.logger.Warnf("HTTP request encountered error: %s", err)
			return resBody, nil
		} else {
			c.logger.Errorf("Error reading response body: %s", err)
		}
		c.logger.Tracef("Parsed: %v", string(resBody))
	}

	return resBody, nil
}

func (c *Cx1Client) sendRequestRaw(method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	var requestBody io.Reader
	var bodyBytes []byte

	c.logger.Debugf("Sending request to URL %v", url)

	if body != nil {
		closer := io.NopCloser(body)
		bodyBytes, _ := io.ReadAll(closer)
		requestBody = bytes.NewBuffer(bodyBytes)
		defer closer.Close()
	}

	request, err := c.createRequest(method, url, requestBody, &header, nil)
	if err != nil {
		c.logger.Errorf("Unable to create request: %s", err)
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		var resBody []byte
		if response.Body != nil {
			resBody, _ = io.ReadAll(response.Body)
		}
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		c.logger.Errorf("HTTP request failed with error: %s", err)
		return nil, err
	}
	if response.StatusCode >= 400 {
		resBody, _ := io.ReadAll(response.Body)
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		c.logger.Errorf("HTTP response indicates error: %v", response.Status)
		return nil, errors.New("HTTP Response: " + response.Status)
	}

	return response, nil
}

func (c *Cx1Client) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	cx1url := fmt.Sprintf("%v/api%v", c.baseUrl, url)
	return c.sendRequestInternal(method, cx1url, body, header)
}

func (c *Cx1Client) sendRequestRawCx1(method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	cx1url := fmt.Sprintf("%v/api%v", c.baseUrl, url)
	return c.sendRequestRaw(method, cx1url, body, header)
}

func (c *Cx1Client) sendRequestIAM(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
}

func (c *Cx1Client) sendRequestRawIAM(method, base, url string, body io.Reader, header http.Header) (*http.Response, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestRaw(method, iamurl, body, header)
}

// not sure what to call this one? used for /console/ calls, not part of the /realms/ path
func (c *Cx1Client) sendRequestOther(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
}

func (c *Cx1Client) recordRequestDetailsInErrorCase(requestBody []byte, responseBody []byte) {
	if len(requestBody) != 0 {
		c.logger.Errorf("Request body: %s", string(requestBody))
	}
	if len(responseBody) != 0 {
		c.logger.Errorf("Response body: %s", string(responseBody))
	}
}

// convenience function
func (c *Cx1Client) GetASTAppID() string {
	if astAppID == "" {
		client, err := c.GetClientByName("ast-app")
		if err != nil {
			c.logger.Warnf("Error finding AST App ID: %s", err)
			return ""
		}

		astAppID = client.ClientID
	}

	return astAppID
}

func (c *Cx1Client) String() string {
	return fmt.Sprintf("%v on %v with token: %v", c.tenant, c.baseUrl, ShortenGUID(c.authToken))
}

func ShortenGUID(guid string) string {
	if len(guid) <= 2 {
		return ".."
	}
	return fmt.Sprintf("%v..%v", guid[:2], guid[len(guid)-2:])
}
