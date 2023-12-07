package ciliumidentity

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

func (c *Controller) processPodEvents(ctx context.Context) error {
	for event := range c.pods.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.K8sPodName: event.Key.String()}).Debug("Got Upsert Pod event")
			c.onPodUpdate(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.K8sPodName: event.Key.String()}).Debug("Got Upsert Pod event")
			c.onPodUpdate(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// onPodUpdate pushes a CID create to the CID work queue if there is no matching
// CID for the security labels.
func (c *Controller) onPodUpdate(pod *slim_core_v1.Pod) {
	c.enqueuePodReconciliation(podResourceKey(pod.Name, pod.Namespace))
}

func (c *Controller) initPodQueue() {
	log.WithFields(logrus.Fields{
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CID controller workqueue configuration for Pod")

	c.podQueue = workqueue.NewRateLimitingQueueWithConfig(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		workqueue.RateLimitingQueueConfig{Name: "pods"})
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same Pod at the
// same time.
func (c *Controller) runPodWorker() {
	for c.processNextPodQueueItem() {
	}
}

func (c *Controller) processNextPodQueueItem() bool {
	item, quit := c.podQueue.Get()
	if quit {
		return false
	}
	defer c.podQueue.Done(item)

	key := item.(resource.Key)
	err := c.reconciler.reconcilePod(key)
	c.handlePodErr(err, item)

	return true
}

func (c *Controller) handlePodErr(err error, key interface{}) {
	if err == nil {
		c.podQueue.Forget(key)
		return
	}

	// TODO: Pod metrics to be added.
	// Increment error count for sync errors
	//if operatorOption.Config.EnableMetrics {
	//	metrics.CiliumEndpointSliceSyncErrors.Inc()
	//}

	log.Infof("Failed to process Pod: %v", err)

	if c.podQueue.NumRequeues(key) < maxProcessRetries {
		c.podQueue.AddRateLimited(key)
		return
	}

	// Drop the CES from queue, we maxed out retries.
	log.WithError(err).WithFields(logrus.Fields{
		logfields.K8sPodName: key,
	}).Error("Dropping the Pod from queue, exceeded maxRetries")
	c.podQueue.Forget(key)
}

func podResourceKey(podName, podNamespace string) resource.Key {
	return resource.Key{Name: podName, Namespace: podNamespace}
}

func (c *Controller) enqueuePodReconciliation(podKey resource.Key) {
	if len(podKey.String()) == 0 {
		return
	}

	c.podQueue.Add(podKey)
}
