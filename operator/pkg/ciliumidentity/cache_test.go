package ciliumidentity

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/stretchr/testify/assert"
)

var (
	k8sLables_A           = map[string]string{"a1": "1", "a2": "2"}
	k8sLables_B           = map[string]string{"b1": "1", "b2": "2"}
	k8sLables_B_duplicate = map[string]string{"b1": "1", "b2": "2"}
	k8sLables_C           = map[string]string{"c1": "1", "c2": "2"}
	k8sLables_D           = map[string]string{"d1": "1", "d2": "2"}
)

func TestCIDState(t *testing.T) {
	labelsFilterSetup()
	state := NewCIDState()

	k := GetCIDKeyFromK8sLabels(k8sLables_A)
	state.Upsert("1", k)

	expectedState := &CIDState{
		idToLabels: map[string]*key.GlobalIdentity{"1": k},
		labelsToID: map[string]*SecIDs{
			k.GetKey(): {
				selectedID: "1",
				ids:        map[string]bool{"1": true},
			},
		},
	}

	assert.NoError(t, validateCIDState(state, expectedState), "cid 1 added")

	k = GetCIDKeyFromK8sLabels(k8sLables_B)
	state.Upsert("2", k)

	expectedState.idToLabels["2"] = k
	expectedState.labelsToID[k.GetKey()] = &SecIDs{
		selectedID: "2",
		ids:        map[string]bool{"2": true},
	}

	assert.NoError(t, validateCIDState(state, expectedState), "cid 2 added")

	k = GetCIDKeyFromK8sLabels(k8sLables_B_duplicate)
	state.Upsert("3", k)

	expectedState.idToLabels["3"] = k
	expectedState.labelsToID[k.GetKey()] = &SecIDs{
		selectedID: "2",
		ids:        map[string]bool{"2": true, "3": true},
	}

	assert.NoError(t, validateCIDState(state, expectedState), "cid 3 added - duplicate")

	cidKey, exists := state.LookupByID("0")
	assert.Equal(t, false, exists, "cid 0 LookupByID - not found")

	cidKey, exists = state.LookupByID("1")
	assert.Equal(t, true, exists, "cid 1 LookupByID - found")
	assert.Equal(t, GetCIDKeyFromK8sLabels(k8sLables_A), cidKey, "cid 1 LookupByID - correct key")

	_, exists = state.LookupByKey(GetCIDKeyFromK8sLabels(k8sLables_C))
	assert.Equal(t, false, exists, "labels C LookupByKey - not found")

	cidName, exists := state.LookupByKey(GetCIDKeyFromK8sLabels(k8sLables_A))
	assert.Equal(t, true, exists, "labels C LookupByKey - not found")
	assert.Equal(t, "1", cidName, "labels C LookupByKey - correct CID")

	state.Remove("2")

	delete(expectedState.idToLabels, "2")
	expectedState.labelsToID[GetCIDKeyFromK8sLabels(k8sLables_B).GetKey()] = &SecIDs{
		selectedID: "3",
		ids:        map[string]bool{"3": true},
	}

	assert.NoError(t, validateCIDState(state, expectedState), "cid 2 removed")

	cidKey, exists = state.LookupByID("2")
	assert.Equal(t, false, exists, "cid 2 LookupByID - not found")

	state.Remove("3")
	delete(expectedState.idToLabels, "3")
	delete(expectedState.labelsToID, GetCIDKeyFromK8sLabels(k8sLables_B_duplicate).GetKey())

	assert.NoError(t, validateCIDState(state, expectedState), "cid 3 removed")
}

func validateCIDState(state, expectedState *CIDState) error {
	if !reflect.DeepEqual(state.idToLabels, expectedState.idToLabels) {
		return fmt.Errorf("failed to validate the state, expected idToLabels %v, got %v", expectedState.idToLabels, state.idToLabels)
	}

	if !reflect.DeepEqual(state.labelsToID, expectedState.labelsToID) {
		return fmt.Errorf("failed to validate the state, expected labelsToID %v, got %v", expectedState.labelsToID, state.labelsToID)
	}

	return nil
}

func labelsFilterSetup() {
	labelsfilter.ParseLabelPrefixCfg(nil, "")
}
