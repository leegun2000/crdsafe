package main

import (
	"context"
	"testing"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func widget(namespace, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Widget",
		"metadata":   map[string]any{"namespace": namespace, "name": name},
		"spec":       spec,
	}}
}

func fakeCluster(crd *apiextv1.CustomResourceDefinition, objs ...runtime.Object) *Cluster {
	gvr := schema.GroupVersionResource{
		Group: crd.Spec.Group, Version: storageVersion(crd), Resource: crd.Spec.Names.Plural,
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: crd.Spec.Names.Kind + "List"}, objs...)
	return &Cluster{dyn: dyn, Context: "test", Version: "v1.33.0", Ratcheting: true, MaxObjects: maxObjectsPerCRD}
}

// The join is the product: a schema finding must name the live CRs it actually breaks.
func TestInspectCorrelatesLiveCRsToSchemaPaths(t *testing.T) {
	oldCRD := crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
		"tier": enum("gold", "silver", "bronze"), "legacy": str(""), "owner": str(""),
	})))
	newCRD := crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
		"tier": enum("gold", "silver"), "owner": str(""),
	}, "owner")))

	cluster := fakeCluster(newCRD,
		widget("prod", "narrowed", map[string]any{"tier": "bronze", "owner": "team-a"}),
		widget("prod", "pruned", map[string]any{"tier": "gold", "owner": "team-a", "legacy": "keepme"}),
		widget("stg", "missing-required", map[string]any{"tier": "gold"}),
		widget("stg", "fine", map[string]any{"tier": "gold", "owner": "team-b"}),
	)

	live := cluster.Inspect(context.Background(), newCRD)
	if live.Total != 4 {
		t.Fatalf("listed %d CRs, want 4", live.Total)
	}

	for _, tc := range []struct{ path, ns, name string }{
		{"spec.tier", "prod", "narrowed"},
		{"spec.legacy", "prod", "pruned"},
		{"spec.owner", "stg", "missing-required"},
	} {
		got := live.ByPath[tc.path]
		if len(got) != 1 || got[0].Namespace != tc.ns || got[0].Name != tc.name {
			t.Errorf("ByPath[%q] = %+v, want just %s/%s", tc.path, got, tc.ns, tc.name)
		}
	}

	// The valid CR must not appear anywhere.
	for path, refs := range live.ByPath {
		for _, r := range refs {
			if r.Name == "fine" {
				t.Errorf("valid CR reported at %s: %+v", path, r)
			}
		}
	}

	// Removed fields are invisible to validation - only pruning sees them.
	if reason := live.ByPath["spec.legacy"][0].Reason; reason == "" {
		t.Error("pruned field carries no reason")
	}

	// And the diff must produce findings whose paths match those keys, or the join is dead.
	findings, err := DiffCRDs([]*apiextv1.CustomResourceDefinition{oldCRD}, []*apiextv1.CustomResourceDefinition{newCRD})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"spec.tier", "spec.legacy", "spec.owner"} {
		found := false
		for _, f := range findings {
			if f.Path == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no finding at %q; correlation would silently report nothing", want)
		}
	}
}

// A finding's path comes from the schema, where a map level contributes no segment, but the
// apiserver reports the concrete key. Without collapsing those, every custom resource stored
// inside a map of objects goes uncorrelated and a data-destroying upgrade reports zero impact.
func TestInspectCorrelatesInsideMapsOfObjects(t *testing.T) {
	mapOfObjects := func(required ...string) *apiextv1.CustomResourceValidation {
		return props(map[string]apiextv1.JSONSchemaProps{
			"tags": {Type: "object", AdditionalProperties: &apiextv1.JSONSchemaPropsOrBool{
				Allows: true,
				Schema: &apiextv1.JSONSchemaProps{
					Type:       "object",
					Properties: map[string]apiextv1.JSONSchemaProps{"owner": str(""), "ttl": str("")},
					Required:   required,
				},
			}},
		})
	}
	oldCRD := crd(ver("v1", true, true, mapOfObjects()))
	newCRD := crd(ver("v1", true, true, mapOfObjects("owner")))

	cluster := fakeCluster(newCRD, widget("prod", "has-map", map[string]any{
		"tags": map[string]any{"blue": map[string]any{"ttl": "1h"}},
	}))

	findings, err := DiffCRDs([]*apiextv1.CustomResourceDefinition{oldCRD}, []*apiextv1.CustomResourceDefinition{newCRD})
	if err != nil {
		t.Fatal(err)
	}
	var target *Finding
	for i := range findings {
		if findings[i].Kind == KindRequiredAdded {
			target = &findings[i]
		}
	}
	if target == nil {
		t.Fatalf("no requiredAdded finding: %+v", findings)
	}
	if target.Path != "spec.tags.owner" {
		t.Fatalf("finding path %q, want spec.tags.owner", target.Path)
	}

	live := cluster.Inspect(context.Background(), newCRD)
	if got := live.ByPath[target.Path]; len(got) != 1 || got[0].Name != "has-map" {
		t.Fatalf("ByPath[%q] = %+v, want the one live CR; the apiserver reports spec.tags.blue.owner and the map key must be collapsed",
			target.Path, got)
	}
}

// crdsafe deliberately refuses to say whether a logic change tightens or loosens a schema. That
// only works if the cluster answers it: the apiserver reports an allOf/anyOf/oneOf/not failure
// against the object rather than a field, so those correlate on their own key.
func TestLogicChangeIsSettledByTheCluster(t *testing.T) {
	specWith := func(mutate func(*apiextv1.JSONSchemaProps)) *apiextv1.CustomResourceValidation {
		v := props(map[string]apiextv1.JSONSchemaProps{"a": str(""), "b": str("")})
		spec := v.OpenAPIV3Schema.Properties["spec"]
		mutate(&spec)
		v.OpenAPIV3Schema.Properties["spec"] = spec
		return v
	}
	oldCRD := crd(ver("v1", true, true, specWith(func(s *apiextv1.JSONSchemaProps) {
		s.OneOf = []apiextv1.JSONSchemaProps{{Required: []string{"a"}}, {Required: []string{"b"}}}
	})))
	// The first alternative is narrowed: an object carrying only "a" matched it before and now
	// matches nothing.
	newCRD := crd(ver("v1", true, true, specWith(func(s *apiextv1.JSONSchemaProps) {
		s.OneOf = []apiextv1.JSONSchemaProps{{Required: []string{"a", "c"}}, {Required: []string{"b"}}}
	})))

	findings, err := DiffCRDs([]*apiextv1.CustomResourceDefinition{oldCRD}, []*apiextv1.CustomResourceDefinition{newCRD})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Kind != KindLogicChanged {
		t.Fatalf("want one schemaLogicChanged, got %+v", findings)
	}

	cluster := fakeCluster(newCRD,
		widget("prod", "breaks", map[string]any{"a": "hello"}),
		widget("prod", "fine", map[string]any{"b": "hello"}),
	)
	live := cluster.Inspect(context.Background(), newCRD)
	got := live.ByPath[logicRootKey]
	if len(got) != 1 || got[0].Name != "breaks" {
		t.Fatalf("ByPath[logicRootKey] = %+v, want just prod/breaks", got)
	}
}

func TestInspectHandlesUninstalledCRDAndEmptyCluster(t *testing.T) {
	c := crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{"tier": str("")})))
	live := fakeCluster(c).Inspect(context.Background(), c)
	if live.Total != 0 || len(live.ByPath) != 0 {
		t.Fatalf("empty cluster produced %+v", live)
	}
}

func TestInspectSkipsCRDWithNoServedVersion(t *testing.T) {
	c := crd(ver("v1", false, false, props(map[string]apiextv1.JSONSchemaProps{"tier": str("")})))
	live := (&Cluster{MaxObjects: maxObjectsPerCRD}).Inspect(context.Background(), c)
	if live.Note == "" {
		t.Fatal("want a note explaining why nothing was checked")
	}
}
