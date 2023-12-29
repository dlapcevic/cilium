// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	CIDControllerPrefix = "cid_controller"
	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelOpcode indicates the kind of CES metric, could be CEP insert or remove
	LabelOpcode = "opcode"

	// LabelWorkqueue indicates workqueues that the metrics are attributed to.
	LabelWorkqueue = "workqueue"

	// LabelPhase indicates the phases the metrics are attributed to.
	LabelPhase = "period"

	// Label values

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelValueCEPInsert is used to indicate the number of CEPs inserted in a CES
	LabelValueCEPInsert = "cepinserted"

	// LabelValueCEPRemove is used to indicate the number of CEPs removed from a CES
	LabelValueCEPRemove = "cepremoved"

	LabelValueCIDWorkqueue = "cilium-identity"

	LabelValuePodWorkqueue = "pod"

	LabelValueNSWorkqueue = "namespace"

	LabelValueEnqueuedLatency = "enqueued"

	LabelValueProcessingLatency = "processing"

	LabelValueRateLimitLatency = "rate-limit"
)

func NewMetrics() *Metrics {
	return &Metrics{
		CiliumEndpointSliceDensity: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "number_of_ceps_per_ces",
			Help:      "The number of CEPs batched in a CES",
			Buckets:   []float64{1, 10, 25, 50, 100, 200, 500, 1000},
		}),

		CiliumEndpointsChangeCount: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "number_of_cep_changes_per_ces",
			Help:      "The number of changed CEPs in each CES update",
		}, []string{LabelOpcode}),

		CiliumEndpointSliceSyncErrors: metric.NewCounter(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_sync_errors_total",
			Help:      "Number of CES sync errors",
		}),

		CiliumEndpointSliceSyncTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_sync_total",
			Help:      "The number of completed CES syncs by outcome",
		}, []string{LabelOutcome}),

		CiliumEndpointSliceQueueDelay: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_queueing_delay_seconds",
			Help:      "CiliumEndpointSlice queueing delay in seconds",
			Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}),
		//########
		//########
		//########
		CIDControllerWorkqueueEventCount: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_workqueue_event_count",
			Help:      "Number processed successful and failed events by Cilium Identity controller workqueues",
		}, []string{LabelWorkqueue, LabelOutcome}),

		CIDControllerWorkqueueLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_workqueue_latency",
			Help:      "Duration of Cilium Identity controller workqueues enqueuing and processing latencies in seconds",
			Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}, []string{LabelWorkqueue, LabelPhase}),
	}
}

type Metrics struct {
	// CiliumEndpointSliceDensity indicates the number of CEPs batched in a CES and it used to
	// collect the number of CEPs in CES at various buckets.
	CiliumEndpointSliceDensity metric.Histogram

	// CiliumEndpointsChangeCount indicates the total number of CEPs changed for every CES request sent to k8s-apiserver.
	// This metric is used to collect number of CEP changes happening at various buckets.
	CiliumEndpointsChangeCount metric.Vec[metric.Observer]

	// CiliumEndpointSliceSyncTotal indicates the total number of completed CES syncs with k8s-apiserver by success/fail outcome.
	CiliumEndpointSliceSyncTotal metric.Vec[metric.Counter]

	// CiliumEndpointSliceSyncErrors used to track the total number of errors occurred during syncing CES with k8s-apiserver.
	// This metric is going to be deprecated in Cilium 1.14 and removed in 1.15.
	// It is replaced by CiliumEndpointSliceSyncTotal metric.
	CiliumEndpointSliceSyncErrors metric.Counter

	// CiliumEndpointSliceQueueDelay measures the time spent by CES's in the workqueue. This measures time difference between
	// CES insert in the workqueue and removal from workqueue.
	CiliumEndpointSliceQueueDelay metric.Histogram
	//########
	//########
	//########
	CIDControllerWorkqueueEventCount *prometheus.CounterVec

	CIDControllerWorkqueueLatency prometheus.ObserverVec
}
