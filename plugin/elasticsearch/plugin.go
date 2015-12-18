package main

import (
	"encoding/json"
	"fmt"
	"github.com/starkandwayne/shield/plugin"
	"os"
)

func main() {
	p := ElasticSearchPlugin{
		Name:    "ElasticSearch Backup Plugin",
		Author:  "Stark & Wayne",
		Version: "0.0.1",
		Features: plugin.PluginFeatures{
			Target: "yes",
			Store:  "yes",
		},
	}

	plugin.Run(p)
}

type ElasticSearchPlugin plugin.PluginInfo

type ElasticSearchEndpoint struct {
	LogsearchRepository string `json:"repository"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	URL                 string `json:"url"`
	SkipSSLValidation   bool   `json:"SkipSSLValidation"`
	Restore             bool   `json:"restore"`
}

func (p ElasticSearchPlugin) Meta() plugin.PluginInfo {
	return plugin.PluginInfo(p)
}

func (p ElasticSearchPlugin) Backup(endpoint plugin.ShieldEndpoint) error {
	es, err := getElasticSearchEndpoint(endpoint)
	if err != nil {
		return err
	}

	es.Restore = false

	data, _ := json.Marshal(es)
	fmt.Fprintf(os.Stdout, "%s\n", string(data))

	return nil
}

func (p ElasticSearchPlugin) Restore(endpoint plugin.ShieldEndpoint) error {
	es, err := getElasticSearchEndpoint(endpoint)
	if err != nil {
		return err
	}

	es.Restore = true

	data, _ := json.Marshal(es)
	fmt.Fprintf(os.Stdout, "%s\n", string(data))

	return nil
}

func (p ElasticSearchPlugin) Store(endpoint plugin.ShieldEndpoint) (string, error) {
	return "", plugin.UNIMPLEMENTED
}

func (p ElasticSearchPlugin) Retrieve(endpoint plugin.ShieldEndpoint, file string) error {
	return plugin.UNIMPLEMENTED
}

func (p ElasticSearchPlugin) Purge(endpoint plugin.ShieldEndpoint, file string) error {
	return plugin.UNIMPLEMENTED
}

func getElasticSearchEndpoint(endpoint plugin.ShieldEndpoint) (ElasticSearchEndpoint, error) {
	logsearchRepository, err := endpoint.StringValue("es_name")
	if err != nil {
		return ElasticSearchEndpoint{}, err
	}

	url, err := endpoint.StringValue("es_url")
	if err != nil {
		return ElasticSearchEndpoint{}, err
	}

	user, err := endpoint.StringValue("es_username")
	if err != nil {
		user = "" // user is optional
	}

	passwd, err := endpoint.StringValue("es_password")
	if err != nil {
		passwd = "" // passwd is optional
	}

	sslValidate, err := endpoint.BooleanValue("skip_ssl_validation")
	if err != nil {
		sslValidate = false
	}

	return ElasticSearchEndpoint{
		LogsearchRepository: logsearchRepository,
		Username:            user,
		Password:            passwd,
		URL:                 url,
		SkipSSLValidation:   sslValidate,
	}, nil
}
