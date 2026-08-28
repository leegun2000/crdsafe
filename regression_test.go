package main

import (
	"strings"
	"testing"

	"helm.sh/helm/v4/pkg/cli/values"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func one(c *apiextv1.CustomResourceDefinition) []*apiextv1.CustomResourceDefinition {
	return []*apiextv1.CustomResourceDefinition{c}
}

func scoped(scope apiextv1.ResourceScope, c *apiextv1.CustomResourceDefinition) *apiextv1.CustomResourceDefinition {
	out := c.DeepCopy()
	out.Spec.Scope = scope
	return out
}

// Each of these was a real false negative: crdsafe printed "No CRD changes" for an upgrade the
// apiserver would reject or that would destroy data.
func TestRegressions(t *testing.T) {
	base := props(map[string]apiextv1.JSONSchemaProps{"size": str(""), "replicas": num(f64(1))})

	t.Run("scope flip is reported", func(t *testing.T) {
		from := one(scoped(apiextv1.NamespaceScoped, crd(ver("v1", true, true, base))))
		to := one(scoped(apiextv1.ClusterScoped, crd(ver("v1", true, true, base))))
		got, err := DiffCRDs(from, to)
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindScopeChanged, "", SevCritical) {
			t.Fatalf("want CRITICAL scopeChanged (spec.scope is immutable, the apiserver rejects the update), got %+v", got)
		}
	})

	t.Run("un-serving a retained version is reported", func(t *testing.T) {
		from := one(crd(ver("v1beta1", true, false, base), ver("v1", true, true, base)))
		to := one(crd(ver("v1beta1", false, false, base), ver("v1", true, true, base)))
		got, err := DiffCRDs(from, to)
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindVersionUnserved, "", SevCritical) {
			t.Fatalf("want CRITICAL versionUnserved, got %+v", got)
		}
	})

	// Shipping a new alpha alongside a stable version is the normal way to add an API. crdify
	// compares them to each other and calls every field it does not find "changed"; gating CI on
	// that trains people to ignore the exit code.
	t.Run("adding a served version does not fail the upgrade", func(t *testing.T) {
		v2 := props(map[string]apiextv1.JSONSchemaProps{"size": num(nil)})
		from := one(crd(ver("v1", true, true, base)))
		to := one(crd(ver("v1", true, true, base), ver("v2alpha1", true, false, v2)))
		got, err := DiffCRDs(from, to)
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindVersionAdded, "", SevLow) {
			t.Errorf("want the new version reported at LOW, got %+v", got)
		}
		if worst := maxSeverity(got); worst > SevLow {
			t.Fatalf("adding an alpha version scored %s and would fail CI: %+v", worst, got)
		}
	})

	// Everything crdify cannot classify has to surface. Enumerating the dangerous fields is a
	// losing game, so anything not provably harmless is a finding.
	t.Run("changes crdify does not model are reported, not assumed safe", func(t *testing.T) {
		for name, mutate := range map[string]func(*apiextv1.JSONSchemaProps){
			"multipleOf":       func(p *apiextv1.JSONSchemaProps) { p.MultipleOf = f64(5) },
			"exclusiveMinimum": func(p *apiextv1.JSONSchemaProps) { p.ExclusiveMinimum = true },
			"format":           func(p *apiextv1.JSONSchemaProps) { p.Format = "int32" },
			"uniqueItems":      func(p *apiextv1.JSONSchemaProps) { p.UniqueItems = true },
		} {
			t.Run(name, func(t *testing.T) {
				changed := props(map[string]apiextv1.JSONSchemaProps{"size": str(""), "replicas": num(f64(1))})
				p := changed.OpenAPIV3Schema.Properties["spec"].Properties["replicas"]
				mutate(&p)
				changed.OpenAPIV3Schema.Properties["spec"].Properties["replicas"] = p
				got, err := DiffCRDs(one(crd(ver("v1", true, true, base))), one(crd(ver("v1", true, true, changed))))
				if err != nil {
					t.Fatal(err)
				}
				if maxSeverity(got) < SevHigh {
					t.Fatalf("%s change scored %s, want HIGH - crdsafe must not assume an unmodelled change is safe: %+v",
						name, maxSeverity(got), got)
				}
			})
		}
	})

	// A brand-new allOf/anyOf/oneOf/not constrains data that already exists, unlike a brand-new
	// optional property, which has nothing stored under it.
	t.Run("a newly added quantor subschema is reported", func(t *testing.T) {
		constrained := props(map[string]apiextv1.JSONSchemaProps{"size": str(""), "replicas": num(f64(1))})
		spec := constrained.OpenAPIV3Schema.Properties["spec"]
		spec.AllOf = []apiextv1.JSONSchemaProps{{Required: []string{"size"}}}
		constrained.OpenAPIV3Schema.Properties["spec"] = spec
		got, err := DiffCRDs(one(crd(ver("v1", true, true, base))), one(crd(ver("v1", true, true, constrained))))
		if err != nil {
			t.Fatal(err)
		}
		if maxSeverity(got) < SevHigh {
			t.Fatalf("a new allOf requiring a field scored %s, want HIGH: %+v", maxSeverity(got), got)
		}
	})

	t.Run("switching on pruning is reported", func(t *testing.T) {
		old := crd(ver("v1", true, true, base))
		old.Spec.PreserveUnknownFields = true
		got, err := DiffCRDs(one(old), one(crd(ver("v1", true, true, base))))
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindPruningEnabled, "", SevCritical) {
			t.Fatalf("want CRITICAL pruningEnabled, got %+v", got)
		}
	})

	// A removed property named "items" used to normalize to its parent's path, which both
	// mislabelled the report and suppressed every real change beneath that parent.
	t.Run("a property named items does not swallow its siblings", func(t *testing.T) {
		withItems := props(map[string]apiextv1.JSONSchemaProps{
			"items":    {Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{"a": str("")}},
			"replicas": num(f64(1)),
		})
		withoutItems := props(map[string]apiextv1.JSONSchemaProps{"replicas": str("")})
		got, err := DiffCRDs(one(crd(ver("v1", true, true, withItems))), one(crd(ver("v1", true, true, withoutItems))))
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindFieldRemoved, "spec.items", SevHigh) {
			t.Errorf("want fieldRemoved at spec.items, got %+v", got)
		}
		if !has(got, KindTypeChanged, "spec.replicas", SevHigh) {
			t.Errorf("the unrelated type change at spec.replicas was swallowed, got %+v", got)
		}
	})

	// crdify lumps every x-kubernetes-* change into an unclassified go-cmp dump. The ones that can
	// invalidate a stored object have to be checked against the schema directly.
	t.Run("list uniqueness being switched on is reported", func(t *testing.T) {
		listOf := func(t string) apiextv1.JSONSchemaProps {
			return apiextv1.JSONSchemaProps{Type: "array", XListType: &t,
				Items: &apiextv1.JSONSchemaPropsOrArray{Schema: &apiextv1.JSONSchemaProps{Type: "string"}}}
		}
		from := one(crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{"ports": listOf("atomic")}))))
		to := one(crd(ver("v1", true, true, props(map[string]apiextv1.JSONSchemaProps{"ports": listOf("set")}))))
		got, err := DiffCRDs(from, to)
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindListType, "spec.ports", SevHigh) {
			t.Fatalf("want HIGH listUniquenessAdded at spec.ports, got %+v", got)
		}
	})

	t.Run("a new CEL rule is reported", func(t *testing.T) {
		withRule := props(map[string]apiextv1.JSONSchemaProps{"size": str("")})
		withRule.OpenAPIV3Schema.Properties["spec"] = apiextv1.JSONSchemaProps{
			Type:         "object",
			Properties:   map[string]apiextv1.JSONSchemaProps{"size": str("")},
			XValidations: []apiextv1.ValidationRule{{Rule: "self.size != ''", Message: "size required"}},
		}
		got, err := DiffCRDs(one(crd(ver("v1", true, true, base))), one(crd(ver("v1", true, true, withRule))))
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindCELAdded, "spec", SevHigh) {
			t.Fatalf("want HIGH validationRuleAdded at spec, got %+v", got)
		}
	})

	// x-kubernetes-map-type cannot make a stored object invalid, but atomic makes the map a single
	// leaf to server-side apply, so the next apply drops keys owned by other field managers. Worth
	// saying; not worth failing CI over.
	t.Run("a map going atomic is reported without gating CI", func(t *testing.T) {
		atomic := "atomic"
		tweaked := props(map[string]apiextv1.JSONSchemaProps{
			"size": str(""), "replicas": {Type: "integer", Minimum: f64(1), XMapType: &atomic},
		})
		got, err := DiffCRDs(one(crd(ver("v1", true, true, base))), one(crd(ver("v1", true, true, tweaked))))
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindMapAtomic, "spec.replicas", SevMedium) {
			t.Fatalf("want MEDIUM mapNowAtomic, got %+v", got)
		}
		if (&Report{Findings: got}).ExitCode() != 0 {
			t.Error("a map-type change must not fail CI")
		}
	})

	// Whether a node is an allOf/anyOf/oneOf/not entry is something the schema walk knows. Deriving
	// it from the path string breaks on a CRD that declares a property with one of those names,
	// and gets the direction wrong for disjunctions.
	t.Run("quantors", func(t *testing.T) {
		specOf := func(mutate func(*apiextv1.JSONSchemaProps)) *apiextv1.CustomResourceValidation {
			v := props(map[string]apiextv1.JSONSchemaProps{"size": str(""), "replicas": num(f64(1))})
			spec := v.OpenAPIV3Schema.Properties["spec"]
			mutate(&spec)
			v.OpenAPIV3Schema.Properties["spec"] = spec
			return v
		}
		plain := specOf(func(*apiextv1.JSONSchemaProps) {})

		t.Run("a new allOf branch is reported even when the constraint is one level deeper", func(t *testing.T) {
			deep := specOf(func(s *apiextv1.JSONSchemaProps) {
				s.AllOf = []apiextv1.JSONSchemaProps{{Properties: map[string]apiextv1.JSONSchemaProps{
					"size": {Type: "string", MaxLength: func(i int64) *int64 { return &i }(3)},
				}}}
			})
			got, err := DiffCRDs(one(crd(ver("v1", true, true, plain))), one(crd(ver("v1", true, true, deep))))
			if err != nil {
				t.Fatal(err)
			}
			if maxSeverity(got) < SevHigh {
				t.Fatalf("a maxLength inside a new allOf branch scored %s, want HIGH: %+v", maxSeverity(got), got)
			}
		})

		t.Run("removing a oneOf alternative is a tightening, not a loosening", func(t *testing.T) {
			two := specOf(func(s *apiextv1.JSONSchemaProps) {
				s.OneOf = []apiextv1.JSONSchemaProps{{Required: []string{"size"}}, {Required: []string{"replicas"}}}
			})
			oneLeft := specOf(func(s *apiextv1.JSONSchemaProps) {
				s.OneOf = []apiextv1.JSONSchemaProps{{Required: []string{"size"}}}
			})
			got, err := DiffCRDs(one(crd(ver("v1", true, true, two))), one(crd(ver("v1", true, true, oneLeft))))
			if err != nil {
				t.Fatal(err)
			}
			if maxSeverity(got) < SevHigh {
				t.Fatalf("dropping a oneOf branch scored %s, want HIGH: %+v", maxSeverity(got), got)
			}
		})

		t.Run("required inside a oneOf branch is an alternative, not a requirement", func(t *testing.T) {
			withOneOf := specOf(func(s *apiextv1.JSONSchemaProps) {
				s.OneOf = []apiextv1.JSONSchemaProps{{Required: []string{"size"}}, {Required: []string{"replicas"}}}
			})
			got, err := DiffCRDs(one(crd(ver("v1", true, true, plain))), one(crd(ver("v1", true, true, withOneOf))))
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range got {
				if f.Kind == KindRequiredAdded {
					t.Fatalf("reported %q as newly required, but it only names one oneOf alternative: %+v", f.Path, f)
				}
			}
		})

		t.Run("a property genuinely named not is treated as a property", func(t *testing.T) {
			withProp := specOf(func(s *apiextv1.JSONSchemaProps) {
				s.Properties["not"] = apiextv1.JSONSchemaProps{Type: "string"}
			})
			got, err := DiffCRDs(one(crd(ver("v1", true, true, withProp))), one(crd(ver("v1", true, true, plain))))
			if err != nil {
				t.Fatal(err)
			}
			if !has(got, KindFieldRemoved, "spec.not", SevHigh) {
				t.Fatalf("want fieldRemoved at spec.not, got %+v", got)
			}
		})
	})
}

// A chart can keep CRDs in templates/. Falling back to the crds/ directory when the render fails
// would drop those silently and turn a breaking upgrade into a clean report.
func TestRenderFailureIsNotSwallowed(t *testing.T) {
	crds, suppressed, err := LoadCRDs(ChartRef{Chart: "testdata/render-fail"}, values.Options{})
	if err != nil {
		t.Fatalf("lint-mode render should survive a failing template: %v", err)
	}
	// Both CRDs must survive: one from crds/, one from templates/ alongside the failing template.
	if len(crds) != 2 {
		t.Errorf("extracted %d CRDs, want 2 (crds/ and templates/)", len(crds))
	}
	if len(suppressed) == 0 {
		t.Fatal("the swallowed template failure must be reported, not discarded")
	}
	if !strings.Contains(strings.Join(suppressed, " "), "always fails") {
		t.Errorf("suppressed message lost: %v", suppressed)
	}
}
