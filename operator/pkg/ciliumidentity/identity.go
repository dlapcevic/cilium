package ciliumidentity

import (
	"context"
	"time"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

const (
	ByKeyIndex = "by-key-index"
)

func (c *Controller) processCiliumIdentityEvents(ctx context.Context) error {
	for event := range c.ciliumIdentities.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Upsert Cilium Identity event")
			c.onCiliumIdentityUpdate(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Delete Cilium Identity event")
			c.onCiliumIdentityDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) onCiliumIdentityUpdate(cid *cilium_api_v2.CiliumIdentity) {
	c.enqueueCIDReconciliation(cidResourceKey(cid.Name))
}

func (c *Controller) onCiliumIdentityDelete(cid *cilium_api_v2.CiliumIdentity) {
	c.enqueueCIDReconciliation(cidResourceKey(cid.Name))
}

func (c *Controller) initCIDQueue() {
	if c.cidQueueQpsLimit <= 0 {
		c.cidQueueQpsLimit = defaultCIDQueueQPSLimit
	}

	if c.cidQueueBurstLimit <= 0 {
		c.cidQueueBurstLimit = defaultCIDQueueBurstLimit
	}

	log.WithFields(logrus.Fields{
		logfields.WorkQueueQPSLimit:    c.cidQueueQpsLimit,
		logfields.WorkQueueBurstLimit:  c.cidQueueBurstLimit,
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CID controller workqueue configuration for Cilium Identity")

	c.cidQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff), "cilium_identity")
	c.cidQueue = workqueue.NewRateLimitingQueueWithConfig(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		workqueue.RateLimitingQueueConfig{Name: "cilium_identity"})
}

func (c *Controller) rateLimitCIDProcessing() {
	delay := c.cidQueueRateLimiter.Reserve().Delay()
	c.Metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueCIDWorkqueue, LabelValueRateLimitLatency).Observe(delay.Seconds())

	select {
	case <-c.context.Done():
	case <-time.After(delay):
	}
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same CID
// at the same time
func (c *Controller) runCIDWorker() {
	log.Infof("Starting CID worker in CID controller")

	for c.processNextCIDQueueItem() {
	}

	log.Infof("Stopping CID worker in CID controller")
}

func (c *Controller) processNextCIDQueueItem() bool {
	c.rateLimitCIDProcessing()

	processingStartTime := time.Now()

	item, quit := c.cidQueue.Get()
	if quit {
		return false
	}
	defer c.cidQueue.Done(item)

	cidItem := item.(queueItem)
	err := c.reconciler.reconcileCID(cidItem.key)
	c.handleCIDErr(err, item)

	enqueuedLatency := processingStartTime.Sub(cidItem.enqueueTime).Seconds()
	c.Metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueCIDWorkqueue, LabelValueEnqueuedLatency).Observe(enqueuedLatency)

	processingLatency := time.Since(processingStartTime).Seconds()
	c.Metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueCIDWorkqueue, LabelValueProcessingLatency).Observe(processingLatency)

	return true
}

func (c *Controller) handleCIDErr(err error, item interface{}) {
	if err == nil {
		c.Metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValueCIDWorkqueue, LabelValueOutcomeSuccess).Inc()
		c.cidQueue.Forget(item)
		return
	}

	c.Metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValueCIDWorkqueue, LabelValueOutcomeFail).Inc()
	log.Infof("Failed to process CID: %v", err)

	if c.cidQueue.NumRequeues(item) < maxProcessRetries {
		c.cidQueue.AddRateLimited(item)
		return
	}

	// Drop the CID from queue, we maxed out retries.
	log.WithError(err).WithFields(logrus.Fields{
		logfields.CIDName: item,
	}).Error("Dropping the Cilium Identity from queue, exceeded maxRetries")
	c.cidQueue.Forget(item)
}

func cidResourceKey(cidName string) resource.Key {
	return resource.Key{Name: cidName}
}

func (c *Controller) enqueueCIDReconciliation(cidKey resource.Key) {
	if len(cidKey.String()) == 0 {
		return
	}

	item := queueItem{
		key:         cidKey,
		enqueueTime: time.Now(),
	}

	c.cidQueue.Add(item)
}

// func (c *Controller) onCiliumIdentityUpdate(cid *cilium_api_v2.CiliumIdentity) {
// 	c.enqueueCIDReconciliation(cidResourceKey(cid.Name))
// }

// func (c *Controller) onCiliumIdentityDelete(cid *cilium_api_v2.CiliumIdentity) {
// 	c.enqueueCIDReconciliation(cidResourceKey(cid.Name))
// }

// func (c *Controller) initCIDQueue() {
// 	if c.cidQueueQpsLimit <= 0 {
// 		c.cidQueueQpsLimit = defaultCIDQueueQPSLimit
// 	}

// 	if c.cidQueueBurstLimit <= 0 {
// 		c.cidQueueBurstLimit = defaultCIDQueueBurstLimit
// 	}

// 	log.WithFields(logrus.Fields{
// 		logfields.WorkQueueQPSLimit:    c.cidQueueQpsLimit,
// 		logfields.WorkQueueBurstLimit:  c.cidQueueBurstLimit,
// 		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
// 	}).Info("CID controller workqueue configuration for Cilium Identity")

// 	c.cidQueue = workqueue.NewRateLimitingQueueWithConfig(
// 		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
// 		workqueue.RateLimitingQueueConfig{Name: "cilium_identity"})
// 	c.cidQueueRateLimiter = rate.NewLimiter(rate.Limit(c.cidQueueQpsLimit), c.cidQueueBurstLimit)
// }

// func (c *Controller) rateLimitCIDProcessing() {
// 	delay := c.cidQueueRateLimiter.Reserve().Delay()

// 	select {
// 	case <-c.context.Done():
// 	case <-time.After(delay):
// 	}
// }

// // runWorker runs a worker thread that just dequeues items, processes them, and
// // marks them done. You may run as many of these in parallel as you wish; the
// // workqueue guarantees that they will not end up processing the same CID
// // at the same time
// func (c *Controller) runCIDWorker() {
// 	for c.processNextCIDQueueItem() {
// 	}
// }

// func (c *Controller) processNextCIDQueueItem() bool {
// 	c.rateLimitCIDProcessing()

// 	item, quit := c.cidQueue.Get()
// 	if quit {
// 		return false
// 	}
// 	defer c.cidQueue.Done(item)

// 	cidItem := item.(queueItem)
// 	err := c.reconciler.reconcileCID(cidItem.key)
// 	c.handleCIDErr(err, item)

// 	return true
// }

// func (c *Controller) handleCIDErr(err error, item interface{}) {
// 	if err == nil {
// 		c.cidQueue.Forget(item)
// 		return
// 	}

// 	// TODO: CID metrics to be added.
// 	// Increment error count for sync errors
// 	//if operatorOption.Config.EnableMetrics {
// 	//	metrics.CiliumEndpointSliceSyncErrors.Inc()
// 	//}

// 	log.Infof("Failed to process CID: %v", err)

// 	if c.cidQueue.NumRequeues(item) < maxProcessRetries {
// 		c.cidQueue.AddRateLimited(item)
// 		return
// 	}

// 	// Drop the CES from queue, we maxed out retries.
// 	log.WithError(err).WithFields(logrus.Fields{
// 		logfields.CIDName: item,
// 	}).Error("Dropping the Cilium Identity from queue, exceeded maxRetries")
// 	c.cidQueue.Forget(item)
// }

// func cidResourceKey(cidName string) resource.Key {
// 	return resource.Key{Name: cidName}
// }

// func (c *Controller) enqueueCIDReconciliation(cidKey resource.Key) {
// 	if len(cidKey.String()) == 0 {
// 		return
// 	}

// 	item := queueItem{
// 		key: cidKey,
// 		enqueueTime: time.Now(),
// 	}

// 	c.cidQueue.Add(item)
// }
