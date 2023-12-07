package ciliumidentity

import (
	"testing"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/stretchr/testify/assert"
)

func TestValidateCIDName(t *testing.T) {
	midID, maxID := 10, 20
	a := NewGlobalIDAllocator(idpool.ID(midID), idpool.ID(maxID))

	type tc struct {
		description string
		cidName     string
		expectedID  int64
		expectErr   bool
	}

	testCases := []tc{
		{
			description: "The ID cannot be negative",
			cidName:     "-1",
			expectedID:  0,
			expectErr:   true,
		},
		{
			description: "The ID cannot be outside the ID pool",
			cidName:     "9",
			expectedID:  0,
			expectErr:   true,
		},
		{
			description: "The ID cannot be outside the ID pool",
			cidName:     "21",
			expectedID:  0,
			expectErr:   true,
		},
		{
			description: "The ID is inside the ID pool",
			cidName:     "10",
			expectedID:  10,
			expectErr:   false,
		},
		{
			description: "The ID is inside the ID pool",
			cidName:     "15",
			expectedID:  15,
			expectErr:   false,
		},
		{
			description: "The ID is inside the ID pool",
			cidName:     "20",
			expectedID:  20,
			expectErr:   false,
		},
	}

	for _, tc := range testCases {
		id, err := a.ValidateCIDName(tc.cidName)
		hasErr := err != nil

		assert.Equal(t, tc.expectedID, id, tc.description)
		assert.Equal(t, tc.expectErr, hasErr, tc.description)
	}
}
