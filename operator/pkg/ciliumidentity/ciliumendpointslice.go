package ciliumidentity

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

// CID controller also watches for CESs. The only reason is to keep a cache of
// what CIDs are used in CESs. This is required only when CESs are enabled.
// CID controller won't delete a CID until it is no longer present in any CESs.

func (c *Controller) processCiliumEndpointSliceEvents(ctx context.Context) error {
	if !c.cesEnabled {
		return nil
	}

	for event := range c.ciliumEndpointSlice.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Upsert Cilium Identity event")
			c.onCiliumEndpointSliceUpdate(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Delete Cilium Identity event")
			c.onCiliumEndpointSliceDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) onCiliumEndpointSliceUpdate(ces *v2alpha1.CiliumEndpointSlice) {
	c.reconciler.cidUsageInCES.ProcessCESUpsert(ces)
}

func (c *Controller) onCiliumEndpointSliceDelete(ces *v2alpha1.CiliumEndpointSlice) {
	c.reconciler.cidUsageInCES.ProcessCESDelete(ces)
}
