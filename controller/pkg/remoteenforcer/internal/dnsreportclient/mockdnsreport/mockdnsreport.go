// Code generated by MockGen. DO NOT EDIT.
// Source: interfaces.go

// Package mock_dnsreportclient is a generated GoMock package.
package mockdnsreportclient

import (
	context "context"

	"github.com/golang/mock/gomock"
)

// MockDNSReportClient is a mock of DNSReportClient interface
type MockDNSReportClient struct {
}

// NewMockDNSReportClient creates a new mock instance
func NewMockDNSReportClient(ctrl *gomock.Controller) *MockDNSReportClient {
	mock := &MockDNSReportClient{}
	return mock
}

func (m *MockDNSReportClient) Run(ctx context.Context) error {
	return nil
}
