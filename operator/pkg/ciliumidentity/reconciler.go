package ciliumidentity

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type reconciler struct {
	logger logrus.FieldLogger
	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientset k8sClient.Clientset
	// Cache of Cilium Identities formed from kube-apiserver watcher.
	idAllocator     *GlobalIDAllocator
	desiredCIDState *CIDState
	cidUsageInPods  *CIDUsageInPods
	cidUsageInCES   *CIDUsageInCES
	queueOps        queueOperations

	nsStore  resource.Store[*slim_corev1.Namespace]
	podStore resource.Store[*slim_corev1.Pod]
	cidStore resource.Store[*cilium_api_v2.CiliumIdentity]
	cesStore resource.Store[*v2alpha1.CiliumEndpointSlice]

	// Ensures no CID duplicates are created while allocating CIDs in parallel.
	cidCreateLock lock.RWMutex

	cesEnabled bool
}

func newReconciler(
	ctx context.Context,
	logger logrus.FieldLogger,
	clientset k8sClient.Clientset,
	namespaces resource.Resource[*slim_corev1.Namespace],
	pods resource.Resource[*slim_corev1.Pod],
	ciliumIdentities resource.Resource[*cilium_api_v2.CiliumIdentity],
	ciliumEndpointSlices resource.Resource[*v2alpha1.CiliumEndpointSlice],
	cesEnabled bool,
	queueOps queueOperations,
) *reconciler {
	log.Info("Creating Cilium Identity reconciler")

	nsStore, _ := namespaces.Store(ctx)
	podStore, _ := pods.Store(ctx)
	cidStore, _ := ciliumIdentities.Store(ctx)
	cesStore, _ := ciliumEndpointSlices.Store(ctx)
	idAllocator := NewGlobalIDAllocator(defaultMinIDValue, defaultMaxIDValue)

	return &reconciler{
		logger:          logger,
		clientset:       clientset,
		idAllocator:     idAllocator,
		desiredCIDState: NewCIDState(),
		cidUsageInPods:  NewCIDUsageInPods(),
		cidUsageInCES:   NewCIDUsageInCES(),
		queueOps:        queueOps,
		nsStore:         nsStore,
		podStore:        podStore,
		cidStore:        cidStore,
		cesStore:        cesStore,
		cesEnabled:      cesEnabled,
	}
}

func (r *reconciler) calcDesiredStateOnStartup() error {
	if err := r.syncCIDsOnStartup(); err != nil {
		return err
	}
	r.syncCESsOnStartup()
	return r.syncPodsOnStartup()
}

func (r *reconciler) syncCIDsOnStartup() error {
	for _, cid := range r.cidStore.List() {
		cidKey := GetCIDKeyFromSecurityLabels(cid.SecurityLabels)

		if err := r.addCIDToCache(cid.Name, cidKey); err != nil {
			log.Warningf("Failed to add CID %s to cache: %v", cid.Name, err)
		}
	}

	return nil
}

func (r *reconciler) syncCESsOnStartup() {
	if !r.cesEnabled {
		return
	}

	for _, ces := range r.cesStore.List() {
		r.cidUsageInCES.ProcessCESUpsert(ces)
	}
}

// syncPodsOnStartup ensures that all pods have a CID for their labels, and that
// all non-used CIDs are deleted. Non used CIDs are those that aren't in use by
// any of the pods and also don't exist in CESs (if CES is enabled).
func (r *reconciler) syncPodsOnStartup() error {
	var lastError error

	for _, pod := range r.podStore.List() {
		if err := r.reconcilePod(podResourceKey(pod.Name, pod.Namespace)); err != nil {
			lastError = err
		}
	}

	return lastError
}

// reconcileCID ensures that the desired state for the CID is reached, by
// comparing the CID in desired state cache and watcher's store and doing one of
// the following:
// 1. Nothing - If CID doesn't exist in both desired state cache and watcher's
// store.
// 2. Deletes CID - If CID only exists in the watcher's store.
// 3. Creates CID - If CID only exists in the desired state cache.
// 4. Updates CID - If CIDs in the desired state cache and watcher's store are
// not the same.
func (r *reconciler) reconcileCID(cidResourceKey resource.Key) error {
	cidName := cidResourceKey.Name
	storeCID, existsInStore, err := r.cidStore.GetByKey(cidResourceKey)
	if err != nil {
		return fmt.Errorf("failed to get CID %q from the CID watcher store: %v", cidName, err)
	}

	cidKey, existsInCache := r.desiredCIDState.LookupByID(cidName)
	if !existsInCache && !existsInStore {
		return nil
	}

	if !existsInCache {
		return r.deleteCID(cidName)
	}

	if !existsInStore {
		return r.createCID(cidName, cidKey)
	}

	storeCIDKey := GetCIDKeyFromSecurityLabels(storeCID.SecurityLabels)
	if cidKey.Equals(storeCIDKey.LabelArray) {
		return nil
	}

	return r.updateCID(storeCID, cidKey)
}

func (r *reconciler) createCID(cidName string, cidKey *key.GlobalIdentity) error {
	cidLabels := cidKey.GetAsMap()
	selectedLabels, skippedLabels := SanitizeK8sLabels(cidLabels)
	r.logger.WithField(logfields.Labels, skippedLabels).Info("Skipped non-kubernetes labels when labelling ciliumidentity. All labels will still be used in identity determination")

	cid := &cilium_api_v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   cidName,
			Labels: selectedLabels,
		},
		SecurityLabels: cidLabels,
	}

	r.logger.WithField(logfields.CIDName, cidName).Info("Creating a Cilium Identity")

	_, err := r.clientset.CiliumV2().CiliumIdentities().Create(context.TODO(), cid, metav1.CreateOptions{})
	return err
}

func (r *reconciler) updateCID(cid *cilium_api_v2.CiliumIdentity, cidKey *key.GlobalIdentity) error {
	cidLabels := cidKey.GetAsMap()
	selectedLabels, skippedLabels := SanitizeK8sLabels(cidLabels)
	r.logger.WithField(logfields.Labels, skippedLabels).Info("Skipped non-kubernetes labels when labelling ciliumidentity. All labels will still be used in identity determination")

	cid.Labels = selectedLabels
	cid.SecurityLabels = cidLabels

	r.logger.WithField(logfields.CIDName, cid.Name).Info("Creating a Cilium Identity")

	_, err := r.clientset.CiliumV2().CiliumIdentities().Create(context.TODO(), cid, metav1.CreateOptions{})
	return err
}

func (r *reconciler) deleteCID(cidName string) error {
	r.logger.WithField(logfields.CIDName, cidName).Info("Deleting a Cilium Identity")

	err := r.clientset.CiliumV2().CiliumIdentities().Delete(context.TODO(), cidName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (r *reconciler) addCIDToCache(cidName string, cidKey *key.GlobalIdentity) error {
	if cidKey == nil || len(cidName) == 0 {
		return fmt.Errorf("invalid CID, name: %q, key: %v", cidName, cidKey)
	}

	cachedCIDKey, exists := r.desiredCIDState.LookupByID(cidName)
	if exists && cidKey.Equals(cachedCIDKey.LabelArray) {
		return nil
	}

	id, err := r.idAllocator.ValidateCIDName(cidName)
	if err != nil {
		return err
	}

	err = r.idAllocator.Allocate(idpool.ID(id))
	if err != nil {
		return err
	}
	r.desiredCIDState.Upsert(cidName, cidKey)

	return nil
}

// reconcilePod ensures that there is a CID that matches the pod. CIDs are
// created for new unique label sets, and potentailly deleted when pods are
// deleted, if no other pods match the CID labels.
func (r *reconciler) reconcilePod(podKey resource.Key) error {
	pod, exists, err := r.podStore.GetByKey(podKey)
	if err != nil {
		return err
	}
	// When a pod is not found in the pod store, it means it's deleted.
	if !exists {
		prevCIDName, count := r.cidUsageInPods.RemovePod(podKey.String())
		if count == 0 && !r.cidIsUsedInCES(prevCIDName) {
			r.cleanUpCID(prevCIDName)
		}
		return nil
	}

	cidName, err := r.allocateCIDForPod(pod)
	if err != nil {
		return err
	}

	prevCIDName, count := r.cidUsageInPods.AssignCIDForPod(podKey.String(), cidName)
	if count == 0 && !r.cidIsUsedInCES(prevCIDName) {
		r.cleanUpCID(prevCIDName)
	}

	return nil
}

func (r *reconciler) cleanUpCID(cidName string) {
	r.desiredCIDState.Remove(cidName)
	r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName))
}

func (r *reconciler) cidIsUsedInPods(cidName string) bool {
	return r.cidUsageInPods.CIDUsageCount(cidName) > 0
}

func (r *reconciler) cidIsUsedInCES(cidName string) bool {
	return r.cesEnabled && r.cidUsageInCES.CIDUsageCount(cidName) > 0
}

// allocateCIDForPod gets pod and namespace labels that are relevant to security
// identities, and ensures that a CID exists for that label set.
// 1. CID exists: No action.
// 2. CID doesn't exist: Create CID.
func (r *reconciler) allocateCIDForPod(pod *slim_corev1.Pod) (string, error) {
	k8sLabels, err := r.getRelevantLabelsForPod(pod)
	if err != nil {
		return "", err
	}

	return r.allocateCID(k8sLabels)
}

func (r *reconciler) allocateCID(k8sLabels map[string]string) (string, error) {
	cidKey := GetCIDKeyFromK8sLabels(k8sLabels)
	r.cidCreateLock.Lock()
	defer r.cidCreateLock.Unlock()

	cidName, exists := r.desiredCIDState.LookupByKey(cidKey)
	if exists {
		return cidName, nil
	}

	allocatedID, err := r.idAllocator.AllocateRandom()
	if err != nil {
		return "", err
	}

	cidName = allocatedID.String()
	r.desiredCIDState.Upsert(cidName, cidKey)
	r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName))

	return cidName, nil
}

func (r *reconciler) getRelevantLabelsForPod(pod *slim_corev1.Pod) (map[string]string, error) {
	ns, err := r.getNamespace(pod.Namespace)
	if err != nil {
		return nil, err
	}

	_, labelsMap, _, err := k8s.GetPodMetadata(ns, pod)
	if err != nil {
		return nil, err
	}

	return labelsMap, nil
}

func (r *reconciler) getNamespace(namespace string) (*slim_corev1.Namespace, error) {
	nsObj := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}

	ns, exists, err := r.nsStore.Get(nsObj)
	if err != nil {
		return nil, fmt.Errorf("unable to get namespace %q, error: %v", namespace, err)
	}
	if !exists {
		return nil, fmt.Errorf("namespace %q not found in store", namespace)
	}

	return ns, nil
}

// reconcileNS enqueues all pods in the namespace to be reconciled by the CID
// controller.
func (r *reconciler) reconcileNS(nsKey resource.Key) error {
	if err := r.updateAllPodsInANS(nsKey.Name); err != nil {
		return fmt.Errorf("failed to reconcile namespace %q change: %v", nsKey.Name, err)
	}
	return nil
}

func (r *reconciler) updateAllPodsInANS(namespace string) error {
	if r.podStore == nil {
		return fmt.Errorf("pod store is nil")
	}
	podList, err := r.podStore.ByIndex(cache.NamespaceIndex, namespace)
	if err != nil {
		return err
	}

	var lastErr error

	for _, pod := range podList {
		r.queueOps.enqueuePodReconciliation(podResourceKey(pod.Name, pod.Namespace))
	}

	return lastErr
}
