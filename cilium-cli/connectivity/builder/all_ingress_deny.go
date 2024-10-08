// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type allIngressDeny struct{}

func (t allIngressDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy denies all ingresses by default.
	//
	// 1. Pod to Pod fails because there is no egress policy (so egress traffic originating from a pod is allowed),
	//    but then at the destination there is ingress policy that denies the traffic.
	// 2. Egress to world works because there is no egress policy (so egress traffic originating from a pod is allowed),
	//    then when replies come back, they are considered as "replies" to the outbound connection.
	//    so they are not subject to ingress policy.
	newTest("all-ingress-deny", ct).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithScenarios(tests.PodToPod(), tests.PodToCIDR(tests.WithRetryAll())).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIP)) == ct.Params().ExternalOtherIP ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIP)) == ct.Params().ExternalIP {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})
}
