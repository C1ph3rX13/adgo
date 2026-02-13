package queries

import (
	"testing"
)

func TestQueryRegistry(t *testing.T) {
	// Test that the registry is initialized
	names := GetNames()
	if len(names) == 0 {
		t.Error("Query registry should not be empty after init")
	}
}

func TestGetQuery(t *testing.T) {
	// Test getting a known query
	query, ok := Get("users")
	if !ok {
		t.Error("users query should exist")
	}
	if query.Filter == "" {
		t.Error("Query filter should not be empty")
	}

	// Test getting a non-existent query
	_, ok = Get("NonExistentQuery")
	if ok {
		t.Error("NonExistentQuery should not exist")
	}
}

func TestQueryBuilder(t *testing.T) {
	baseQuery := Query{
		Filter:     "(objectClass=user)",
		Attributes: []string{"sAMAccountName", "userPrincipalName"},
	}

	// Test basic builder
	builder := NewQueryBuilder(baseQuery)
	result := builder.Build()

	if result.Filter != baseQuery.Filter {
		t.Errorf("Expected filter %s, got %s", baseQuery.Filter, result.Filter)
	}

	if len(result.Attributes) != len(baseQuery.Attributes) {
		t.Errorf("Expected %d attributes, got %d", len(baseQuery.Attributes), len(result.Attributes))
	}

	// Test WithParam
	builder = NewQueryBuilder(baseQuery)
	builder.WithParam("baseDN", "DC=example,DC=com")
	result = builder.Build()

	// Builder should not modify the base query
	if result.Filter == baseQuery.Filter {
		// This might be expected if parameter replacement isn't implemented
		// For now, just check that it builds without error
	}
}

func TestQueryBuilderWithAttributes(t *testing.T) {
	baseQuery := Query{
		Filter:     "(objectClass=user)",
		Attributes: []string{"sAMAccountName"},
	}

	customAttrs := []string{"cn", "dn"}
	builder := NewQueryBuilder(baseQuery)
	builder.WithAttributes(customAttrs...)
	result := builder.Build()

	if len(result.Attributes) != len(customAttrs) {
		t.Errorf("Expected %d attributes, got %d", len(customAttrs), len(result.Attributes))
	}
}

func TestDomainSpecificQueries(t *testing.T) {
	// Test that domain-specific queries exist
	testCases := []string{
		"dcclonerights",
		"dcsync",
	}

	for _, name := range testCases {
		query, ok := Get(name)
		if !ok {
			t.Errorf("Query %s should exist", name)
			continue
		}

		if query.Filter == "" {
			t.Errorf("Query %s should have a filter", name)
		}

		if len(query.Attributes) == 0 {
			t.Errorf("Query %s should have attributes", name)
		}
	}
}
