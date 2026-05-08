package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expected    string
		expectedErr error
	}{
		{
			name:        "valid api key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expected:    "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "missing authorization header",
			headers:     http.Header{},
			expected:    "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong scheme - Bearer instead of ApiKey",
			headers:     http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expected:    "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "missing key after ApiKey",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expected:    "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if got != tt.expected {
				t.Errorf("expected key %q, got %q", tt.expected, got)
			}

			if tt.expectedErr != nil && err == nil {
				t.Errorf("expected error %q, got nil", tt.expectedErr)
			}

			if tt.expectedErr == nil && err != nil {
				t.Errorf("expected no error, got %q", err)
			}
		})
	}
}
