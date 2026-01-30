package output

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

type PrinterConfig struct {
	Format   string
	FilePath string
}

type Vulnerability struct {
	Type       string
	ObjectDN   string
	ObjectType string
	RiskLevel  string
}

type Printer interface {
	Print(entries []*ldap.Entry) error
	StreamPrint(entriesChan <-chan *ldap.Entry) error
}

func NewPrinter(config PrinterConfig) (Printer, error) {
	switch config.Format {
	case "text":
		return NewTextPrinter(config), nil
	case "json":
		return NewJSONPrinter(config), nil
	case "csv":
		return NewCSVPrinter(config), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", config.Format)
	}
}
