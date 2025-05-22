package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSanitizeURL verifies that the sanitizeURL function correctly masks
// credentials in URLs. It ensures that URLs containing user credentials
// are sanitized by replacing them with asterisks, while URLs without
// credentials remain unchanged.
func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name                 string
		inputURL             string
		expectedSanitizedURL string
	}{
		{
			name: "url with credentials",
			inputURL: "https://user:pass@github.com/" +
				"OWNER/REPO.git",
			expectedSanitizedURL: "https://%2A%2A%2A%2A%2A@" +
				"github.com/OWNER/REPO.git",
		},
		{
			name: "url without credentials",
			inputURL: "https://github.com/OWNER/REPO" +
				".git",
			expectedSanitizedURL: "https://github.com/OWNER/REPO" +
				".git",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualSanitizedURL := SanitizeURL(tc.inputURL)
			assert.Equal(t, tc.expectedSanitizedURL,
				actualSanitizedURL, "Sanitized URL does not "+
					"match expected result")
		})
	}
}
