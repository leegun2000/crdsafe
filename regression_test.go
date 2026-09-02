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

	// A change to a schema's logical structure is reported once, at the node that owns it, without
	// a claim about direction. Which way it goes depends on the whole boolean expression, so
	// crdsafe answers it from the cluster rather than from the schema.
	t.Run("a newly added quantor subschema is reported", func(t *testing.T) {
		constrained := props(map[string]apiextv1.JSONSchemaProps{"size": str(""), "replicas": num(f64(1))})
		spec := constrained.OpenAPIV3Schema.Properties["spec"]
		spec.AllOf = []apiextv1.JSONSchemaProps{{Required: []string{"size"}}}
		constrained.OpenAPIV3Schema.Properties["spec"] = spec
		got, err := DiffCRDs(one(crd(ver("v1", true, true, base))), one(crd(ver("v1", true, true, constrained))))
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindLogicChanged, "spec", SevHigh) {
			t.Fatalf("want schemaLogicChanged at spec, got %+v", got)
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

	// Direction inside a logical combinator is not decidable node by node: dropping a branch of an
	// anyOf tightens, dropping the whole anyOf loosens, and `required` under a `not` means the
	// opposite of `required` anywhere else. Four review rounds produced wrong answers in both
	// directions before this collapsed into one honest finding per changed structure.
	t.Run("logic changes are reported once, without a direction claim", func(t *testing.T) {
		specOf := func(mutate func(*apiextv1.JSONSchemaProps)) *apiextv1.CustomResourceValidation {
			v := props(map[string]apiextv1.JSONSchemaProps{"size": str(""), "replicas": num(f64(1))})
			spec := v.OpenAPIV3Schema.Properties["spec"]
			mutate(&spec)
			v.OpenAPIV3Schema.Properties["spec"] = spec
			return v
		}
		req := func(names ...string) apiextv1.JSONSchemaProps {
			return apiextv1.JSONSchemaProps{Required: names}
		}
		plain := specOf(func(*apiextv1.JSONSchemaProps) {})

		for name, pair := range map[string][2]*apiextv1.CustomResourceValidation{
			"required narrowed inside an existing oneOf branch": {
				specOf(func(s *apiextv1.JSONSchemaProps) { s.OneOf = []apiextv1.JSONSchemaProps{req("size"), req("replicas")} }),
				specOf(func(s *apiextv1.JSONSchemaProps) {
					s.OneOf = []apiextv1.JSONSchemaProps{req("size", "extra"), req("replicas")}
				}),
			},
			"a not.required list shrinking": {
				specOf(func(s *apiextv1.JSONSchemaProps) {
					s.Not = &apiextv1.JSONSchemaProps{Required: []string{"size", "replicas"}}
				}),
				specOf(func(s *apiextv1.JSONSchemaProps) { s.Not = &apiextv1.JSONSchemaProps{Required: []string{"size"}} }),
			},
			"a whole anyOf disappearing": {
				specOf(func(s *apiextv1.JSONSchemaProps) { s.AnyOf = []apiextv1.JSONSchemaProps{req("size"), req("replicas")} }),
				plain,
			},
			"an alternative added to an existing anyOf": {
				specOf(func(s *apiextv1.JSONSchemaProps) { s.AnyOf = []apiextv1.JSONSchemaProps{req("size")} }),
				specOf(func(s *apiextv1.JSONSchemaProps) { s.AnyOf = []apiextv1.JSONSchemaProps{req("size"), req("replicas")} }),
			},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := DiffCRDs(one(crd(ver("v1", true, true, pair[0]))), one(crd(ver("v1", true, true, pair[1]))))
				if err != nil {
					t.Fatal(err)
				}
				// HIGH on the schema alone: crdsafe has not been told which way this went, and
				// unknown is not safe. correlate() drops it to MEDIUM once a cluster reports no
				// stored object failing, and raises it to CRITICAL once one does.
				if len(got) != 1 || !has(got, KindLogicChanged, "spec", SevHigh) {
					t.Fatalf("want exactly one schemaLogicChanged at spec, got %+v", got)
				}
			})
		}

		t.Run("required outside a quantor is still a plain requirement", func(t *testing.T) {
			required := specOf(func(s *apiextv1.JSONSchemaProps) { s.Required = []string{"size"} })
			got, err := DiffCRDs(one(crd(ver("v1", true, true, plain))), one(crd(ver("v1", true, true, required))))
			if err != nil {
				t.Fatal(err)
			}
			if !has(got, KindRequiredAdded, "spec.size", SevHigh) {
				t.Fatalf("want HIGH requiredAdded at spec.size, got %+v", got)
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

// Argo CD 2.12 -> 3.4 adds spec.sourceHydrator, whose schema carries the ordinary IntOrString
// `anyOf: [integer, string]`. crdsafe reported that as a changed logical structure at HIGH, 27
// times, on a field that did not exist before - burying the one real finding in the same run.
// A subtree that is new has nothing stored under it.
func TestLogicOnANewFieldIsNotAChange(t *testing.T) {
	intOrString := func() apiextv1.JSONSchemaProps {
		return apiextv1.JSONSchemaProps{
			XIntOrString: true,
			AnyOf:        []apiextv1.JSONSchemaProps{{Type: "integer"}, {Type: "string"}},
		}
	}
	specOf := func(m map[string]apiextv1.JSONSchemaProps) *apiextv1.CustomResourceValidation {
		return props(m)
	}
	old := specOf(map[string]apiextv1.JSONSchemaProps{"size": str("")})

	t.Run("a brand-new field carrying anyOf is not reported", func(t *testing.T) {
		to := specOf(map[string]apiextv1.JSONSchemaProps{"size": str(""), "count": intOrString()})
		got, err := DiffCRDs(one(crd(ver("v1", true, true, old))), one(crd(ver("v1", true, true, to))))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range got {
			if f.Kind == KindLogicChanged {
				t.Fatalf("a new field cannot invalidate stored data: %+v", f)
			}
		}
	})

	t.Run("a new subtree several levels deep is not reported either", func(t *testing.T) {
		deep := specOf(map[string]apiextv1.JSONSchemaProps{"size": str(""), "hydrator": {
			Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{
				"source": {Type: "object", Properties: map[string]apiextv1.JSONSchemaProps{"count": intOrString()}},
			},
		}})
		got, err := DiffCRDs(one(crd(ver("v1", true, true, old))), one(crd(ver("v1", true, true, deep))))
		if err != nil {
			t.Fatal(err)
		}
		if maxSeverity(got) > SevLow {
			t.Fatalf("adding an optional subtree scored %s: %+v", maxSeverity(got), got)
		}
	})

	t.Run("logic changing on a field that already existed is still reported", func(t *testing.T) {
		before := specOf(map[string]apiextv1.JSONSchemaProps{"count": {
			AnyOf: []apiextv1.JSONSchemaProps{{Type: "integer"}}}})
		after := specOf(map[string]apiextv1.JSONSchemaProps{"count": {
			AnyOf: []apiextv1.JSONSchemaProps{{Type: "integer"}, {Type: "string"}}}})
		got, err := DiffCRDs(one(crd(ver("v1", true, true, before))), one(crd(ver("v1", true, true, after))))
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindLogicChanged, "spec.count", SevHigh) {
			t.Fatalf("want schemaLogicChanged at spec.count, got %+v", got)
		}
	})

	t.Run("removing a field that carried logic is a removal, not two findings", func(t *testing.T) {
		before := specOf(map[string]apiextv1.JSONSchemaProps{"size": str(""), "count": intOrString()})
		got, err := DiffCRDs(one(crd(ver("v1", true, true, before))), one(crd(ver("v1", true, true, old))))
		if err != nil {
			t.Fatal(err)
		}
		if !has(got, KindFieldRemoved, "spec.count", SevHigh) {
			t.Fatalf("want fieldRemoved at spec.count, got %+v", got)
		}
		for _, f := range got {
			if f.Kind == KindLogicChanged {
				t.Fatalf("the removal is already reported; %+v duplicates it", f)
			}
		}
	})
}

// "The old chart does not declare this field" is not the same as "nothing is stored there". A CRD
// that preserved unknown fields stored whatever clients sent, so a field the new schema declares
// for the first time can already hold data - and now it gets validated and pruned.
func TestNewFieldUnderACRDThatPreservedUnknownFields(t *testing.T) {
	bare := props(map[string]apiextv1.JSONSchemaProps{"size": str("")})
	declared := props(map[string]apiextv1.JSONSchemaProps{
		"size": str(""),
		"tier": {Type: "string", Enum: []apiextv1.JSON{{Raw: []byte(`"gold"`)}}},
	})

	t.Run("CRD-level preserveUnknownFields is honoured", func(t *testing.T) {
		old := crd(ver("v1", true, true, bare))
		old.Spec.PreserveUnknownFields = true // what convertV1beta1 sets for a v1beta1 chart
		got, err := DiffCRDs(one(old), one(crd(ver("v1", true, true, declared))))
		if err != nil {
			t.Fatal(err)
		}
		var sawTier bool
		for _, f := range got {
			if f.Path == "spec.tier" {
				sawTier = true
			}
		}
		if !sawTier {
			t.Fatalf("spec.tier was stored unvalidated and is now constrained, but nothing was reported: %+v", got)
		}
	})

	t.Run("an ordinary new field is still quiet", func(t *testing.T) {
		got, err := DiffCRDs(one(crd(ver("v1", true, true, bare))), one(crd(ver("v1", true, true, declared))))
		if err != nil {
			t.Fatal(err)
		}
		if maxSeverity(got) > SevLow {
			t.Fatalf("a plain new optional field should stay quiet, got %+v", got)
		}
	})
}
