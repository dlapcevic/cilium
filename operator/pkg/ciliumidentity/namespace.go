package ciliumidentity

import (
	"context"
	"time"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

func (c *Controller) processNamespaceEvents(ctx context.Context) error {
	for event := range c.namespaces.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.K8sNamespace: event.Key.String()}).Debug("Got Upsert Namespace event")
			c.onNamespaceUpdate(event.Object)
			event.Done(nil)
		}
	}
	return nil
}

func (c *Controller) onNamespaceUpdate(ns *slim_core_v1.Namespace) {
	newLabels := getNamespaceLabels(ns)

	oldIdtyLabels := c.oldNSSecurityLabels[ns.Name]
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

	// Do not perform any other operations if labels did not change.
	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
		return
	}

	c.oldNSSecurityLabels[ns.Name] = newIdtyLabels
	c.enqueueNSReconciliation(nsResourceKey(ns.Name))
}

func getNamespaceLabels(ns *slim_core_v1.Namespace) labels.Labels {
	lbls := ns.GetLabels()
	labelMap := make(map[string]string, len(lbls))
	for k, v := range lbls {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}

func (c *Controller) initNSQueue() {
	log.WithFields(logrus.Fields{
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CID controller workqueue configuration for Namespace")

	c.nsQueue = workqueue.NewRateLimitingQueueWithConfig(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		workqueue.RateLimitingQueueConfig{Name: "namespace"})
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same CID
// at the same time
func (c *Controller) runNSWorker() {
	for c.processNextNSQueueItem() {
	}
}

func (c *Controller) processNextNSQueueItem() bool {
	processingStartTime := time.Now()

	item, quit := c.nsQueue.Get()
	if quit {
		return false
	}
	defer c.nsQueue.Done(item)

	nsItem := item.(queueItem)
	err := c.reconciler.reconcileNS(nsItem.key)
	c.handleNSErr(err, item)

		enqueuedLatency := processingStartTime.Sub(nsItem.enqueueTime).Seconds()
		c.Metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueNSWorkqueue, LabelValueEnqueuedLatency).Observe(enqueuedLatency)

		processingLatency := time.Since(processingStartTime).Seconds()
		c.Metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueNSWorkqueue, LabelValueProcessingLatency).Observe(processingLatency)

	return true
}

func (c *Controller) handleNSErr(err error, item interface{}) {
	if err == nil {
			c.Metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValueNSWorkqueue, LabelValueOutcomeSuccess).Inc()

		c.nsQueue.Forget(item)
		return
	}

		c.Metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValueNSWorkqueue, LabelValueOutcomeFail).Inc()
	log.Infof("Failed to process Namespace: %v", err)

	if c.nsQueue.NumRequeues(item) < maxProcessRetries {
		c.nsQueue.AddRateLimited(item)
		return
	}

	// Drop the namespace from queue, we maxed out retries.
	log.WithError(err).WithFields(logrus.Fields{
		logfields.K8sNamespace: item,
	}).Error("Dropping the Namespace from queue, exceeded maxRetries")
	c.nsQueue.Forget(item)
}

func nsResourceKey(namespace string) resource.Key {
	return resource.Key{Name: namespace}
}

func (c *Controller) enqueueNSReconciliation(nsKey resource.Key) {
	if len(nsKey.String()) == 0 {
		return
	}

	item := queueItem{
		key: nsKey,
		enqueueTime: time.Now(),
	}

	c.nsQueue.Add(item)
}


// func (c *Controller) onNamespaceUpdate(ns *slim_core_v1.Namespace) {
// 	newLabels := getNamespaceLabels(ns)

// 	oldIdtyLabels := c.oldNSSecurityLabels[ns.Name]
// 	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

// 	// Do not perform any other operations if labels did not change.
// 	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
// 		return
// 	}

// 	c.oldNSSecurityLabels[ns.Name] = newIdtyLabels
// 	c.enqueueNSReconciliation(nsResourceKey(ns.Name))
// }

// func getNamespaceLabels(ns *slim_core_v1.Namespace) labels.Labels {
// 	lbls := ns.GetLabels()
// 	labelMap := make(map[string]string, len(lbls))
// 	for k, v := range lbls {
// 		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
// 	}
// 	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
// }

// func (c *Controller) initNSQueue() {
// 	log.WithFields(logrus.Fields{
// 		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
// 	}).Info("CID controller workqueue configuration for Namespace")

// 	c.nsQueue = workqueue.NewRateLimitingQueueWithConfig(
// 		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
// 		workqueue.RateLimitingQueueConfig{Name: "namespace"})
// }

// // runWorker runs a worker thread that just dequeues items, processes them, and
// // marks them done. You may run as many of these in parallel as you wish; the
// // workqueue guarantees that they will not end up processing the same CID
// // at the same time
// func (c *Controller) runNSWorker() {
// 	for c.processNextNSQueueItem() {
// 	}
// }

// func (c *Controller) processNextNSQueueItem() bool {
// 	item, quit := c.nsQueue.Get()
// 	if quit {
// 		return false
// 	}
// 	defer c.nsQueue.Done(item)

// 	nsItem := item.(queueItem)
// 	err := c.reconciler.reconcileNS(nsItem.key)
// 	c.handleNSErr(err, item)

// 	return true
// }

// func (c *Controller) handleNSErr(err error, item interface{}) {
// 	if err == nil {
// 		c.nsQueue.Forget(item)
// 		return
// 	}

// 	// TODO: CID metrics to be added.
// 	// Increment error count for sync errors
// 	//if operatorOption.Config.EnableMetrics {
// 	//	metrics.CiliumEndpointSliceSyncErrors.Inc()
// 	//}

// 	log.Infof("Failed to process Namespace: %v", err)

// 	if c.nsQueue.NumRequeues(item) < maxProcessRetries {
// 		c.nsQueue.AddRateLimited(item)
// 		return
// 	}

// 	// Drop the CES from queue, we maxed out retries.
// 	log.WithError(err).WithFields(logrus.Fields{
// 		logfields.K8sNamespace: item,
// 	}).Error("Dropping the Namespace from queue, exceeded maxRetries")
// 	c.nsQueue.Forget(item)
// }

// func nsResourceKey(namespace string) resource.Key {
// 	return resource.Key{Name: namespace}
// }

// func (c *Controller) enqueueNSReconciliation(nsKey resource.Key) {
// 	if len(nsKey.String()) == 0 {
// 		return
// 	}

// 	item := queueItem{
// 		key: nsKey,
// 		enqueueTime: time.Now(),
// 	}

// 	c.cidQueue.Add(item)
// }
