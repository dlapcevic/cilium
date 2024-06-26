// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2

import (
	"context"
	"time"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// CiliumNodeConfigsGetter has a method to return a CiliumNodeConfigInterface.
// A group's client should implement this interface.
type CiliumNodeConfigsGetter interface {
	CiliumNodeConfigs(namespace string) CiliumNodeConfigInterface
}

// CiliumNodeConfigInterface has methods to work with CiliumNodeConfig resources.
type CiliumNodeConfigInterface interface {
	Create(ctx context.Context, ciliumNodeConfig *v2.CiliumNodeConfig, opts v1.CreateOptions) (*v2.CiliumNodeConfig, error)
	Update(ctx context.Context, ciliumNodeConfig *v2.CiliumNodeConfig, opts v1.UpdateOptions) (*v2.CiliumNodeConfig, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2.CiliumNodeConfig, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2.CiliumNodeConfigList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.CiliumNodeConfig, err error)
	CiliumNodeConfigExpansion
}

// ciliumNodeConfigs implements CiliumNodeConfigInterface
type ciliumNodeConfigs struct {
	client rest.Interface
	ns     string
}

// newCiliumNodeConfigs returns a CiliumNodeConfigs
func newCiliumNodeConfigs(c *CiliumV2Client, namespace string) *ciliumNodeConfigs {
	return &ciliumNodeConfigs{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the ciliumNodeConfig, and returns the corresponding ciliumNodeConfig object, and an error if there is any.
func (c *ciliumNodeConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2.CiliumNodeConfig, err error) {
	result = &v2.CiliumNodeConfig{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of CiliumNodeConfigs that match those selectors.
func (c *ciliumNodeConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v2.CiliumNodeConfigList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v2.CiliumNodeConfigList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested ciliumNodeConfigs.
func (c *ciliumNodeConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a ciliumNodeConfig and creates it.  Returns the server's representation of the ciliumNodeConfig, and an error, if there is any.
func (c *ciliumNodeConfigs) Create(ctx context.Context, ciliumNodeConfig *v2.CiliumNodeConfig, opts v1.CreateOptions) (result *v2.CiliumNodeConfig, err error) {
	result = &v2.CiliumNodeConfig{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(ciliumNodeConfig).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a ciliumNodeConfig and updates it. Returns the server's representation of the ciliumNodeConfig, and an error, if there is any.
func (c *ciliumNodeConfigs) Update(ctx context.Context, ciliumNodeConfig *v2.CiliumNodeConfig, opts v1.UpdateOptions) (result *v2.CiliumNodeConfig, err error) {
	result = &v2.CiliumNodeConfig{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		Name(ciliumNodeConfig.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(ciliumNodeConfig).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the ciliumNodeConfig and deletes it. Returns an error if one occurs.
func (c *ciliumNodeConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *ciliumNodeConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched ciliumNodeConfig.
func (c *ciliumNodeConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.CiliumNodeConfig, err error) {
	result = &v2.CiliumNodeConfig{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("ciliumnodeconfigs").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
