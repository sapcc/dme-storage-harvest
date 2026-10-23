/*
 * Copyright NetApp Inc, 2024 All rights reserved
 */

package securityrole

import (
	"fmt"
	"github.com/netapp/harvest/v2/cmd/collectors"
	"github.com/netapp/harvest/v2/cmd/poller/plugin"
	"github.com/netapp/harvest/v2/cmd/tools/rest"
	"github.com/netapp/harvest/v2/pkg/collector"
	"github.com/netapp/harvest/v2/pkg/conf"
	"github.com/netapp/harvest/v2/pkg/errs"
	"github.com/netapp/harvest/v2/pkg/matrix"
	"github.com/netapp/harvest/v2/third_party/tidwall/gjson"
	"log/slog"
	"time"
)

type SecurityRole struct {
	*plugin.AbstractPlugin
	client *rest.Client
	query  string
}

func New(p *plugin.AbstractPlugin) plugin.Plugin {
	return &SecurityRole{AbstractPlugin: p}
}

func (s *SecurityRole) Init(remote conf.Remote) error {
	var err error

	if err := s.InitAbc(); err != nil {
		return err
	}

	clientTimeout := s.ParentParams.GetChildContentS("client_timeout")
	if clientTimeout == "" {
		clientTimeout = rest.DefaultTimeout
	}
	timeout, err := time.ParseDuration(clientTimeout)
	if err != nil {
		s.SLogger.Info("Using default timeout", slog.String("timeout", rest.DefaultTimeout))
	}
	if s.client, err = rest.New(conf.ZapiPoller(s.ParentParams), timeout, s.Auth); err != nil {
		return fmt.Errorf("failed to connect err=%w", err)
	}

	if err := s.client.Init(5, remote); err != nil {
		return err
	}

	s.query = "api/security/roles"
	return nil
}

func (s *SecurityRole) Run(dataMap map[string]*matrix.Matrix) ([]*matrix.Matrix, *collector.Metadata, error) {
	var (
		result []gjson.Result
		err    error
	)

	data := dataMap[s.Object]
	href := rest.NewHrefBuilder().
		APIPath(s.query).
		Fields([]string{"privileges"}).
		MaxRecords(collectors.DefaultBatchSize).
		Build()

	s.client.Metadata.Reset()
	if result, err = collectors.InvokeRestCall(s.client, href); err != nil {
		return nil, nil, err
	}

	for _, role := range result {
		roleName := role.Get("name").ClonedString()
		svm := role.Get("owner.name").ClonedString()

		if !role.IsObject() {
			return nil, nil, errs.New(errs.ErrNoInstance, "security role is not an object. type="+role.Type.String())
		}

		roleKey := roleName + svm
		roleInstance := data.GetInstance(roleKey)
		if roleInstance == nil {
			continue
		}
		roleInstance.SetExportable(false)

		privileges := role.Get("privileges")
		if !privileges.Exists() {
			continue
		}

		for _, priv := range privileges.Array() {
			path := priv.Get("path").ClonedString()
			query := priv.Get("query").ClonedString()
			access := priv.Get("access").ClonedString()

			var newInstance *matrix.Instance
			instanceKey := roleKey + path
			if newInstance, err = data.NewInstance(instanceKey); err != nil {
				return nil, nil, fmt.Errorf("add instance failed for key %s err: %w", instanceKey, err)
			}

			for k, v := range roleInstance.GetLabels() {
				newInstance.SetLabel(k, v)
			}
			newInstance.SetLabel("command_directory_name", path)
			newInstance.SetLabel("role_query", query)
			newInstance.SetLabel("access_level", access)
		}
	}

	return []*matrix.Matrix{data}, s.client.Metadata, nil
}
