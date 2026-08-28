package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structuralcel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	structuralpruning "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning"
	apiservervalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	utilversion "k8s.io/apimachinery/pkg/util/version"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ErrNoCluster is benign: crdsafe still reports the schema diff, just without correlation.
var ErrNoCluster = errors.New("no cluster available")

const (
	listPageSize   = 500
	listTimeout    = 15 * time.Second
	preflightLimit = 5 * time.Second
	// ponytail: hard cap so one enormous CRD cannot hang a CI job. Raise via --max-objects
	// if anyone actually has more than this of a single kind.
	maxObjectsPerCRD = 10000
	// Validation ratcheting is on by default from 1.30 and locked on from 1.33.
	ratchetingSince = "1.30.0"
)

type Cluster struct {
	dyn        dynamic.Interface
	Context    string
	Version    string
	Ratcheting bool
	MaxObjects int
}

// Connect resolves the standard kubeconfig chain. A missing or unreachable cluster is reported
// as ErrNoCluster, never as a failure: the schema diff still stands on its own.
func Connect(ctx context.Context, kubeconfigPath, contextName string) (*Cluster, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: contextName})
	cfg, err := cc.ClientConfig()
	if err != nil {
		if clientcmd.IsEmptyConfig(err) || errors.Is(err, rest.ErrNotInCluster) {
			return nil, ErrNoCluster
		}
		return nil, fmt.Errorf("resolving kubeconfig: %w", err)
	}
	cfg.UserAgent = "crdsafe"
	if cfg.Timeout == 0 {
		cfg.Timeout = listTimeout
	}

	// One GET /version, so an unreachable cluster is reported once instead of once per CRD.
	disco, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCluster, err)
	}
	pctx, cancel := context.WithTimeout(ctx, preflightLimit)
	defer cancel()
	info, err := disco.ServerVersionWithContext(pctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCluster, err)
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}
	name := cfg.Host
	if raw, err := cc.RawConfig(); err == nil && raw.CurrentContext != "" {
		name = raw.CurrentContext
	}
	return &Cluster{
		dyn:        dyn,
		Context:    name,
		Version:    info.GitVersion,
		Ratcheting: atLeast(info.GitVersion, ratchetingSince),
		MaxObjects: maxObjectsPerCRD,
	}, nil
}

func atLeast(gitVersion, min string) bool {
	v, err := utilversion.ParseGeneric(gitVersion)
	if err != nil {
		return false
	}
	return v.AtLeast(utilversion.MustParseGeneric(min))
}

// LiveCheck is the correlation index for one CRD: which live CRs fail at which path.
type LiveCheck struct {
	Total     int
	All       []Affected
	Pruned    []Affected // objects holding data the new schema drops, whatever the path
	ByPath    map[string][]Affected
	NotFound  bool
	Forbidden bool
	TimedOut  bool
	Truncated bool
	Err       error
	Note      string
}

// Inspect lists every live CR of this CRD and records, per schema path, which ones the NEW
// schema invalidates and which ones would silently lose data to pruning.
func (c *Cluster) Inspect(ctx context.Context, newCRD *apiextv1.CustomResourceDefinition) LiveCheck {
	out := LiveCheck{ByPath: map[string][]Affected{}}

	candidates := listableVersions(newCRD)
	if len(candidates) == 0 {
		out.Note = "CRD declares no served version"
		return out
	}
	gvr := schema.GroupVersionResource{
		Group:    newCRD.Spec.Group,
		Resource: newCRD.Spec.Names.Plural, // authoritative; never guess a plural from Kind
	}

	// The chart's storage version may not be the one this cluster serves yet - that is the normal
	// state when the upgrade is what introduces it. Fall through to the versions it does serve
	// rather than reporting a silent zero.
	var items []unstructured.Unstructured
	var res listResult
	version := candidates[0]
	for _, v := range candidates {
		gvr.Version = v
		items, res = c.list(ctx, gvr)
		if !res.notFound {
			version = v
			break
		}
	}
	out.NotFound, out.Forbidden, out.TimedOut, out.Truncated = res.notFound, res.forbidden, res.timedOut, res.truncated
	out.Err = res.err
	out.Total = len(items)
	if len(items) == 0 {
		return out
	}

	v, err := newCRValidator(newCRD, version)
	if err != nil {
		out.Note = err.Error()
		return out
	}
	namespaced := newCRD.Spec.Scope == apiextv1.NamespaceScoped
	for i := range items {
		ref := Affected{Name: items[i].GetName()}
		if namespaced {
			ref.Namespace = items[i].GetNamespace()
		}
		out.All = append(out.All, ref)
		violations, pruned := v.problems(ctx, &items[i])
		for path, reason := range violations {
			ref.Reason = reason
			v.index(out.ByPath, path, ref)
		}
		for path, reason := range pruned {
			ref.Reason = reason
			v.index(out.ByPath, path, ref)
		}
		if len(pruned) > 0 {
			ref.Reason = "drops " + strings.Join(sortedKeys(pruned), ", ")
			out.Pruned = append(out.Pruned, ref)
		}
	}
	return out
}

// listableVersions puts the storage version first, then every other served version, so a cluster
// that has not caught up with the chart is still checked at a version it actually serves.
func listableVersions(crd *apiextv1.CustomResourceDefinition) []string {
	var out []string
	if s := storageVersion(crd); s != "" && isServed(crd, s) {
		out = append(out, s)
	}
	for _, v := range crd.Spec.Versions {
		if v.Served && !slices.Contains(out, v.Name) {
			out = append(out, v.Name)
		}
	}
	return out
}

func isServed(crd *apiextv1.CustomResourceDefinition, name string) bool {
	for _, v := range crd.Spec.Versions {
		if v.Name == name {
			return v.Served
		}
	}
	return false
}

type listResult struct {
	notFound, forbidden, timedOut, truncated bool
	err                                      error
}

// An empty namespace hits the same collection endpoint for cluster-scoped resources and for
// all-namespaces on namespaced ones, so one code path covers both.
func (c *Cluster) list(ctx context.Context, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, listResult) {
	var items []unstructured.Unstructured
	var res listResult
	ri := c.dyn.Resource(gvr)
	secs := int64(listTimeout.Seconds())
	cont := ""
	restarted := false
	for {
		pageCtx, cancel := context.WithTimeout(ctx, listTimeout)
		page, err := ri.List(pageCtx, metav1.ListOptions{
			Limit: listPageSize, Continue: cont, TimeoutSeconds: &secs,
		})
		cancel()
		if err != nil {
			switch {
			case apierrors.IsNotFound(err):
				res.notFound = true
			case apierrors.IsForbidden(err):
				res.forbidden = true
			case errors.Is(err, context.DeadlineExceeded), apierrors.IsTimeout(err),
				apierrors.IsServerTimeout(err), apierrors.IsServiceUnavailable(err):
				res.timedOut = true
			case (apierrors.IsResourceExpired(err) || apierrors.IsGone(err)) && !restarted:
				// The continue token aged out of etcd. Restart once rather than under-report.
				restarted, cont, items = true, "", nil
				continue
			default:
				// Anything unrecognised is a real failure, not a benign skip. Keep the text:
				// silently degrading it to "timed out" would hide a broken correlation.
				res.err = err
			}
			return items, res
		}
		items = append(items, page.Items...)
		if len(items) >= c.MaxObjects {
			return items[:c.MaxObjects], listResult{truncated: true}
		}
		if cont = page.GetContinue(); cont == "" {
			return items, res
		}
	}
}

// crValidator validates live CRs against ONE version of the NEW CRD. CEL programs are compiled
// once here, so build it per version and reuse it across objects.
type crValidator struct {
	schemaValidator apiservervalidation.SchemaValidator
	structural      *structuralschema.Structural
	cel             *structuralcel.Validator
}

func newCRValidator(crd *apiextv1.CustomResourceDefinition, version string) (*crValidator, error) {
	var v1schema *apiextv1.CustomResourceValidation
	for i := range crd.Spec.Versions {
		if crd.Spec.Versions[i].Name == version {
			v1schema = crd.Spec.Versions[i].Schema
			break
		}
	}
	if v1schema == nil || v1schema.OpenAPIV3Schema == nil {
		return nil, fmt.Errorf("new CRD has no schema for version %s", version)
	}
	internal := &apiextensions.CustomResourceValidation{}
	if err := apiextv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(v1schema, internal, nil); err != nil {
		return nil, fmt.Errorf("converting schema: %w", err)
	}
	sv, _, err := apiservervalidation.NewSchemaValidator(internal.OpenAPIV3Schema)
	if err != nil {
		return nil, fmt.Errorf("building validator: %w", err)
	}
	ss, err := structuralschema.NewStructural(internal.OpenAPIV3Schema)
	if err != nil {
		return nil, fmt.Errorf("building structural schema: %w", err)
	}
	return &crValidator{
		schemaValidator: sv,
		structural:      ss,
		cel:             structuralcel.NewValidator(ss, true, celconfig.PerCallLimit),
	}, nil
}

// problems returns, keyed by instance path, everything the new schema does to this object:
// validation failures, and separately the fields pruning would silently delete.
func (v *crValidator) problems(ctx context.Context, cr *unstructured.Unstructured) (map[string]string, map[string]string) {
	out, pruned := map[string]string{}, map[string]string{}

	// Pruning happens before validation and is never an error, so check it separately.
	// This is the only class of breakage that no schema-only or dry-run tool can see.
	pruneObj := cr.DeepCopy().UnstructuredContent()
	opts := structuralschema.UnknownFieldPathOptions{TrackUnknownFieldPaths: true}
	for _, p := range structuralpruning.PruneWithOptions(pruneObj, v.structural, true, opts) {
		pruned[normalizeInstancePath(p)] = "value stored here is dropped on the next write (pruned, no error)"
	}

	obj := cr.DeepCopy().UnstructuredContent()
	structuraldefaulting.Default(obj, v.structural) // the apiserver defaults before validating
	errs := apiservervalidation.ValidateCustomResource(nil, obj, v.schemaValidator)
	if v.cel != nil && !hasBlockingErr(errs) {
		celErrs, _ := v.cel.Validate(ctx, nil, v.structural, obj, nil, celconfig.RuntimeCELCostBudget)
		errs = append(errs, celErrs...)
	}
	for _, e := range errs {
		p := normalizeInstancePath(e.Field)
		if _, taken := out[p]; !taken {
			out[p] = e.ErrorBody() // "Required value", "Unsupported value: ...", "Invalid value: ..."
		}
	}
	return out, pruned
}

// index files one object under the live path and, when they differ, under the same path with map
// keys removed. A finding's path comes from the schema, where a map level contributes no segment,
// while the apiserver reports the concrete key - so without this every custom resource inside a
// map of objects goes uncorrelated.
func (v *crValidator) index(byPath map[string][]Affected, path string, ref Affected) {
	byPath[path] = append(byPath[path], ref)
	if collapsed := collapseMapKeys(v.structural, path); collapsed != path {
		byPath[collapsed] = append(byPath[collapsed], ref)
	}
}

func collapseMapKeys(s *structuralschema.Structural, path string) string {
	if s == nil || path == "" {
		return path
	}
	node := s
	var out []string
	for _, seg := range strings.Split(path, ".") {
		// Array levels contribute no segment either; the index was already stripped.
		for node != nil && node.Items != nil && len(node.Properties) == 0 && node.AdditionalProperties == nil {
			node = node.Items
		}
		switch {
		case node == nil:
			out = append(out, seg)
		case hasProperty(node, seg):
			p := node.Properties[seg]
			out, node = append(out, seg), &p
		case node.AdditionalProperties != nil && node.AdditionalProperties.Structural != nil:
			node = node.AdditionalProperties.Structural // seg is a map key: drop it
		default:
			out, node = append(out, seg), nil
		}
	}
	return strings.Join(out, ".")
}

func hasProperty(s *structuralschema.Structural, name string) bool {
	_, ok := s.Properties[name]
	return ok
}

// copied from apiextensions-apiserver pkg/registry/customresource/strategy.go, where it is
// unexported: the apiserver skips CEL when a structural error already exists.
func hasBlockingErr(errs field.ErrorList) bool {
	for _, e := range errs {
		switch e.Type {
		case field.ErrorTypeNotSupported, field.ErrorTypeRequired, field.ErrorTypeTooLong,
			field.ErrorTypeTooMany, field.ErrorTypeTypeInvalid:
			return true
		}
	}
	return false
}

var indexSuffix = regexp.MustCompile(`\[[^\]]*\]`)

// normalizeInstancePath drops list indices and map keys so a concrete object path lines up with
// the schema path a finding carries: "status.applicationStatus[0].targetRevisions" ->
// "status.applicationStatus.targetRevisions".
func normalizeInstancePath(p string) string {
	return strings.Trim(indexSuffix.ReplaceAllString(p, ""), ".")
}
