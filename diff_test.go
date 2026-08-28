package main

import (
	"testing"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func props(m map[string]apiextv1.JSONSchemaProps, required ...string) *apiextv1.CustomResourceValidation {
	return &apiextv1.CustomResourceValidation{OpenAPIV3Schema: &apiextv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {Type: "object", Properties: m, Required: required},
		},
	}}
}

func ver(name string, served, storage bool, schema *apiextv1.CustomResourceValidation) apiextv1.CustomResourceDefinitionVersion {
	return apiextv1.CustomResourceDefinitionVersion{Name: name, Served: served, Storage: storage, Schema: schema}
}

func crd(vs ...apiextv1.CustomResourceDefinitionVersion) *apiextv1.CustomResourceDefinition {
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: "example.com",
			Names: apiextv1.CustomResourceDefinitionNames{Plural: "widgets", Kind: "Widget"},
			Scope: apiextv1.NamespaceScoped, Versions: vs,
		},
	}
}

func str(desc string) apiextv1.JSONSchemaProps {
	return apiextv1.JSONSchemaProps{Type: "string", Description: desc}
}
func num(min *float64) apiextv1.JSONSchemaProps {
	return apiextv1.JSONSchemaProps{Type: "integer", Minimum: min}
}
func enum(vals ...string) apiextv1.JSONSchemaProps {
	p := apiextv1.JSONSchemaProps{Type: "string"}
	for _, v := range vals {
		p.Enum = append(p.Enum, apiextv1.JSON{Raw: []byte(`"` + v + `"`)})
	}
	return p
}

func f64(v float64) *float64 { return &v }

// has reports whether findings contain one with this kind, path and severity.
func has(fs []Finding, kind, path string, sev Severity) bool {
	for _, f := range fs {
		if f.Kind == kind && f.Path == path && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestDiffCRDs(t *testing.T) {
	base := props(map[string]apiextv1.JSONSchemaProps{
		"name":     str("the name"),
		"tier":     enum("gold", "silver", "bronze"),
		"replicas": num(f64(1)),
		"legacy":   str(""),
	})

	tests := []struct {
		name  string
		from  []*apiextv1.CustomResourceDefinition
		to    []*apiextv1.CustomResourceDefinition
		check func(*testing.T, []Finding)
	}{
		{
			name: "identical charts produce no findings",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to:   []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			check: func(t *testing.T, fs []Finding) {
				if len(fs) != 0 {
					t.Fatalf("want no findings, got %+v", fs)
				}
			},
		},
		{
			name: "CRD removed is CRITICAL",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to:   nil,
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindCRDRemoved, "", SevCritical) {
					t.Fatalf("want crdRemoved CRITICAL, got %+v", fs)
				}
			},
		},
		{
			name: "CRD added is LOW",
			from: nil,
			to:   []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindCRDAdded, "", SevLow) {
					t.Fatalf("want crdAdded LOW, got %+v", fs)
				}
			},
		},
		{
			// Graduating alpha to v1 with an identical schema rewrites objects unchanged. Gating
			// CI on that made every one of the 17 CRITICALs measured across real adjacent chart
			// pairs a false positive.
			name: "storage version flip between identical served schemas is LOW",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base), ver("v2", true, false, base))},
			to:   []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, false, base), ver("v2", true, true, base))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindStorageVersion, "", SevLow) {
					t.Fatalf("want storageVersionChanged LOW, got %+v", fs)
				}
			},
		},
		{
			name: "storage version flip to a differently shaped version is CRITICAL",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base), ver("v2", true, false, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, false, base), ver("v2", true, true,
				props(map[string]apiextv1.JSONSchemaProps{"name": str("")})))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindStorageVersion, "", SevCritical) {
					t.Fatalf("want storageVersionChanged CRITICAL, got %+v", fs)
				}
			},
		},
		{
			name: "storage version flip away from a version that stops being served is CRITICAL",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base), ver("v2", true, false, base))},
			to:   []*apiextv1.CustomResourceDefinition{crd(ver("v1", false, false, base), ver("v2", true, true, base))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindStorageVersion, "", SevCritical) {
					t.Fatalf("want storageVersionChanged CRITICAL, got %+v", fs)
				}
			},
		},
		{
			name: "served version removed is CRITICAL",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1alpha1", true, false, base), ver("v1", true, true, base))},
			to:   []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindServedVersionGone, "", SevCritical) {
					t.Fatalf("want servedVersionRemoved CRITICAL, got %+v", fs)
				}
			},
		},
		{
			name: "field removal is HIGH and carries an instance path",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
				"name": str("the name"), "tier": enum("gold", "silver", "bronze"), "replicas": num(f64(1)),
			})))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindFieldRemoved, "spec.legacy", SevHigh) {
					t.Fatalf("want fieldRemoved at spec.legacy, got %+v", fs)
				}
			},
		},
		{
			name: "new required field is HIGH and names the field in the path",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
				"name": str("the name"), "tier": enum("gold", "silver", "bronze"),
				"replicas": num(f64(1)), "legacy": str(""),
			}, "name")))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindRequiredAdded, "spec.name", SevHigh) {
					t.Fatalf("want requiredAdded at spec.name, got %+v", fs)
				}
			},
		},
		{
			name: "type change is HIGH",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
				"name": str("the name"), "tier": enum("gold", "silver", "bronze"),
				"replicas": str(""), "legacy": str(""),
			})))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindTypeChanged, "spec.replicas", SevHigh) {
					t.Fatalf("want typeChanged at spec.replicas, got %+v", fs)
				}
			},
		},
		{
			name: "narrowing an enum is HIGH",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
				"name": str("the name"), "tier": enum("gold", "silver"),
				"replicas": num(f64(1)), "legacy": str(""),
			})))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindEnumNarrowed, "spec.tier", SevHigh) {
					t.Fatalf("want enumNarrowed at spec.tier, got %+v", fs)
				}
			},
		},
		{
			name: "widening an enum is not a finding",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
				"name": str("the name"), "tier": enum("gold", "silver", "bronze", "platinum"),
				"replicas": num(f64(1)), "legacy": str(""),
			})))},
			check: func(t *testing.T, fs []Finding) {
				if len(fs) != 0 {
					t.Fatalf("want no findings for a widened enum, got %+v", fs)
				}
			},
		},
		{
			name: "tightening a constraint is MEDIUM",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
				"name": str("the name"), "tier": enum("gold", "silver", "bronze"),
				"replicas": num(f64(5)), "legacy": str(""),
			})))},
			check: func(t *testing.T, fs []Finding) {
				if !has(fs, KindConstraint, "spec.replicas", SevMedium) {
					t.Fatalf("want constraintTightened at spec.replicas, got %+v", fs)
				}
			},
		},
		{
			name: "a description-only change is not a finding",
			from: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, base))},
			to: []*apiextv1.CustomResourceDefinition{crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
				"name": str("the name, but the typo is fixed"), "tier": enum("gold", "silver", "bronze"),
				"replicas": num(f64(1)), "legacy": str(""),
			})))},
			check: func(t *testing.T, fs []Finding) {
				if len(fs) != 0 {
					t.Fatalf("want no findings for a description change, got %+v", fs)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DiffCRDs(tc.from, tc.to)
			if err != nil {
				t.Fatalf("DiffCRDs: %v", err)
			}
			tc.check(t, got)
		})
	}
}

// The join key must come from the schema, not from stripping keywords out of the path string:
// a CRD is allowed to have a property literally named "items".
func TestFlattenInstancePaths(t *testing.T) {
	arrayOf := func(p apiextv1.JSONSchemaProps) apiextv1.JSONSchemaProps {
		return apiextv1.JSONSchemaProps{Type: "array", Items: &apiextv1.JSONSchemaPropsOrArray{Schema: &p}}
	}
	mapOf := func(p apiextv1.JSONSchemaProps) apiextv1.JSONSchemaProps {
		return apiextv1.JSONSchemaProps{Type: "object", AdditionalProperties: &apiextv1.JSONSchemaPropsOrBool{Schema: &p}}
	}
	object := func(m map[string]apiextv1.JSONSchemaProps) apiextv1.JSONSchemaProps {
		return apiextv1.JSONSchemaProps{Type: "object", Properties: m}
	}

	v := ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{
		"tags":   arrayOf(object(map[string]apiextv1.JSONSchemaProps{"key": str("")})),
		"labels": mapOf(str("")),
		"items":  object(map[string]apiextv1.JSONSchemaProps{"count": num(nil)}),
	}))
	got := flatten(v)

	for schemaPath, wantInstance := range map[string]string{
		"^":                                  "",
		"^.spec":                             "spec",
		"^.spec.tags":                        "spec.tags",
		"^.spec.tags.items":                  "spec.tags",
		"^.spec.tags.items.key":              "spec.tags.key",
		"^.spec.labels":                      "spec.labels",
		"^.spec.labels.additionalProperties": "spec.labels",
		"^.spec.items":                       "spec.items",       // a real property, not a keyword
		"^.spec.items.count":                 "spec.items.count", // and its children survive
	} {
		node, ok := got[schemaPath]
		if !ok {
			t.Errorf("flatten produced no node at %q", schemaPath)
			continue
		}
		if node.instance != wantInstance {
			t.Errorf("%q -> instance %q, want %q", schemaPath, node.instance, wantInstance)
		}
	}
}

func TestNormalizeInstancePath(t *testing.T) {
	for in, want := range map[string]string{
		"spec.tier":                            "spec.tier",
		"spec.ports[1]":                        "spec.ports",
		"status.applicationStatus[0].revision": "status.applicationStatus.revision",
	} {
		if got := normalizeInstancePath(in); got != want {
			t.Errorf("normalizeInstancePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExitCodeFollowsWorstSeverity(t *testing.T) {
	for _, tc := range []struct {
		sev  Severity
		want int
	}{{SevLow, 0}, {SevMedium, 0}, {SevHigh, 1}, {SevCritical, 2}} {
		r := &Report{Findings: []Finding{{Severity: tc.sev}}}
		if got := r.ExitCode(); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.sev, got, tc.want)
		}
	}
	if got := (&Report{}).ExitCode(); got != 0 {
		t.Errorf("no findings: exit %d, want 0", got)
	}
}
