package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/starkandwayne/shield/plugin"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	p := S3ElasticSearchPlugin{
		Name:    "S3 ElasticSearch Plugin",
		Author:  "Stark & Wayne",
		Version: "0.0.1",
		Features: plugin.PluginFeatures{
			Target: "no",
			Store:  "yes",
		},
	}

	plugin.Run(p)
}

type S3ElasticSearchPlugin plugin.PluginInfo

type S3ConnectionInfo struct {
	//	Host              string
	SkipSSLValidation bool
	AccessKey         string
	SecretKey         string
	Bucket            string
	PathPrefix        string
}

type ElasticSearchEndpoint struct {
	LogsearchRepository string `json:"repository"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	URL                 string `json:"url"`
	SkipSSLValidation   bool   `json:"SkipSSLValidation"`
	Restore             bool   `json:"restore"`
}

type ElasticSearchTargetEndpoint struct {
	LogsearchRepository string `json:"es_name"`
	Username            string `json:"es_username"`
	Password            string `json:"es_password"`
	URL                 string `json:"es_url"`
	SkipSSLValidation   bool   `json:"skip_ssl_validation"`
}
type ElasticSearchOptions struct {
	Type       string `json:"type"`
	ESSettings `json:"settings"`
}

type ESSettings struct {
	Bucket    string `json:"bucket"`
	Protocol  string `json:"protocol"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Prefix    string `json:"base_path"`
	Compress  bool   `json:"compress"`
}

func (p S3ElasticSearchPlugin) Meta() plugin.PluginInfo {
	return plugin.PluginInfo(p)
}

func (p S3ElasticSearchPlugin) Backup(endpoint plugin.ShieldEndpoint) error {
	return plugin.UNIMPLEMENTED
}

func (p S3ElasticSearchPlugin) Restore(endpoint plugin.ShieldEndpoint) error {
	return plugin.UNIMPLEMENTED
}

func (p S3ElasticSearchPlugin) Store(endpoint plugin.ShieldEndpoint) (string, error) {
	// Read in LogSearch details
	var endPoint ElasticSearchEndpoint

	passedIn, err := ioutil.ReadAll(os.Stdin)

	if err := json.Unmarshal(passedIn, &endPoint); err != nil {
		log.Fatalf("JSON unmarshaling failed: %s", err)
	}

	if endPoint.Restore != false {
		log.Fatalf("Store called with Restore Endpoint")
	}

	//Collect S3 details
	s3, err := getS3ConnInfo(endpoint)
	if err != nil {
		return "", err
	}

	//TODO check if Repository Exists

	// Prep Snapshot Repository
	host := endPoint.URL
	url := "/_snapshot/" + endPoint.LogsearchRepository

	var settings ElasticSearchOptions

	settings.Type = "s3"
	settings.ESSettings.Bucket = s3.Bucket
	settings.ESSettings.AccessKey = s3.AccessKey
	settings.ESSettings.SecretKey = s3.SecretKey
	settings.ESSettings.Prefix = s3.PathPrefix
	if endPoint.SkipSSLValidation == true {
		settings.ESSettings.Protocol = "http"
	} else {
		settings.ESSettings.Protocol = "https"
	}
	settings.Compress = true

	data, _ := json.MarshalIndent(settings, "", "  ")
	fmt.Printf("URL: %s\n\nBody:\n%s\n\n", url, data)

	resp, err := makeRequest("PUT", fmt.Sprintf("%s%s", host, url), bytes.NewBuffer(data), endPoint.Username, endPoint.Password, endPoint.SkipSSLValidation)
	if err != nil {
		return "", err
	}

	fmt.Printf("Create Repository Response: %s\n", resp.Status)
	//Fire Snapshot

	backup_name := genBackupName(endPoint.LogsearchRepository)
	url = "/_snapshot/" + backup_name + "?wait_for_completion=true"

	fmt.Printf("URL: %s\n\nBody:\n%s\n\n", url, data)

	resp, err = makeRequest("PUT", fmt.Sprintf("%s%s", host, url), bytes.NewBuffer(data), endPoint.Username, endPoint.Password, endPoint.SkipSSLValidation)
	if err != nil {
		return "", err
	}

	fmt.Printf("Snapshot Response: %s\n", resp.Status)
	return backup_name, nil
}

func (p S3ElasticSearchPlugin) Retrieve(endpoint plugin.ShieldEndpoint, file string) error {
	var endPoint ElasticSearchEndpoint

	passedIn, err := ioutil.ReadAll(os.Stdin)

	if err := json.Unmarshal(passedIn, &endPoint); err != nil {
		log.Fatalf("JSON unmarshaling failed: %s", err)
	}

	if endPoint.Restore != true {
		log.Fatalf("Retrieve called with Backup Endpoint")
	}

	host := endPoint.URL

	url := "/_snapshot/" + file + "/_restore"

	fmt.Printf("URL: %s\n\n", url)

	resp, err := makeRequest("POST", fmt.Sprintf("%s%s", host, url), nil, endPoint.Username, endPoint.Password, endPoint.SkipSSLValidation)
	if err != nil {
		return err
	}
	fmt.Printf("Restore Response: %s\n", resp.Status)
	return nil
}

func (p S3ElasticSearchPlugin) Purge(endpoint plugin.ShieldEndpoint, file string) error {
	var targetEndPoint ElasticSearchTargetEndpoint

	fmt.Println("Environment Variables")
	for _, e := range os.Environ() {
		fmt.Println(e)
	}

	targetString, _ := os.LookupEnv("SHIELD_TARGET_ENDPOINT")

	if err := json.Unmarshal([]byte(targetString), &targetEndPoint); err != nil {
		log.Fatalf("JSON unmarshaling failed: %s", err)
	}

	//fmt.Println("Json: %v", targetEndPoint)

	host := targetEndPoint.URL

	url := "/_snapshot/" + file

	fmt.Printf("Host: %s\nURL: %s\n\n", host, url)

	resp, r_err := makeRequest("DELETE", fmt.Sprintf("%s%s", host, url), nil, targetEndPoint.Username, targetEndPoint.Password, targetEndPoint.SkipSSLValidation)
	if r_err != nil {
		return r_err
	}
	fmt.Printf("Purge Response: %s\n", resp.Status)
	return nil
}

func genBackupName(logSearchName string) string {
	t := time.Now()
	year, mon, day := t.Date()
	hour, min, sec := t.Clock()
	uuid := plugin.GenUUID()
	return fmt.Sprintf("%s/%04d-%02d-%02d-%02d%02d%02d-%s", logSearchName, year, mon, day, hour, min, sec, uuid)
}

func makeRequest(method string, url string, body io.Reader, username string, password string, skipSSLValidation bool) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Add("Content-Type", "application/json")

	httpClient := http.Client{}
	httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: skipSSLValidation}}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		plugin.DEBUG("%#v", resp)
		return nil, fmt.Errorf("Got '%d' response while retrieving RMQ definitions", resp.StatusCode)
	}

	return resp, nil
}

func getS3ConnInfo(e plugin.ShieldEndpoint) (S3ConnectionInfo, error) {
	//	host, err := e.StringValue("s3_host")
	//	if err != nil {
	//		return S3ConnectionInfo{}, err
	//	}

	insecure_ssl, err := e.BooleanValue("skip_ssl_validation")
	if err != nil {
		return S3ConnectionInfo{}, err
	}

	key, err := e.StringValue("access_key_id")
	if err != nil {
		return S3ConnectionInfo{}, err
	}

	secret, err := e.StringValue("secret_access_key")
	if err != nil {
		return S3ConnectionInfo{}, err
	}

	bucket, err := e.StringValue("bucket")
	if err != nil {
		return S3ConnectionInfo{}, err
	}

	prefix, err := e.StringValue("prefix")
	if err != nil {
		return S3ConnectionInfo{}, err
	}

	return S3ConnectionInfo{
		//		Host:              host,
		SkipSSLValidation: insecure_ssl,
		AccessKey:         key,
		SecretKey:         secret,
		Bucket:            bucket,
		PathPrefix:        prefix,
	}, nil
}
