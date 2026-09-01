package main

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/crdify/pkg/config"
	"sigs.k8s.io/crdify/pkg/runner"
	"sigs.k8s.io/crdify/pkg/validations"
)

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string { return sevNames[s] }

func (s Severity) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

// Finding kinds. Everything above the divider is crdsafe's own; crdify models none of them.
const (
	KindCRDRemoved        = "crdRemoved"
	KindCRDAdded          = "crdAdded"
	KindStorageVersion    = "storageVersionChanged"
	KindServedVersionGone = "servedVersionRemoved"
	KindVersionUnserved   = "versionUnserved"
	KindFieldRemoved      = "fieldRemoved"
	KindRequiredAdded     = "requiredAdded"
	KindPruningEnabled    = "pruningEnabled"
	KindVersionAdded      = "servedVersionAdded"

	KindTypeChanged  = "typeChanged"
	KindEnumNarrowed = "enumNarrowed"
	KindConstraint   = "constraintTightened"
	KindScopeChanged = "scopeChanged"
	KindUnmodeled    = "unclassifiedChange"
	KindCELAdded     = "validationRuleAdded"
	KindListType     = "listUniquenessAdded"
	KindListMapKeys  = "listMapKeysChanged"
	KindMapAtomic    = "mapNowAtomic"
	KindLogicChanged = "schemaLogicChanged"
	KindCrossVersion = "servedVersionIncompatible"
)

// Ratchet states. Validation ratcheting (KEP-4008, GA in k8s 1.33) makes the apiserver accept
// updates that leave a resource invalid, as long as the offending value was not touched.
const (
	RatchetTolerated = "tolerated" // survives an update that does not touch the field; still fails on create
	RatchetEnforced  = "enforced"  // rejected on both update and create
	RatchetNA        = "n/a"       // not a per-object validation path at all
)

// A live CR that this specific finding invalidates. This join is the thing no other tool does.
type Affected struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

type Finding struct {
	CRD     string `json:"crd"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"` // instance-style path, e.g. spec.template.spec.project
	Kind    string `json:"kind"`
	// Keyword names the schema keyword behind a class that covers several, so the report can say
	// maxLength where the class only says constraintTightened. Empty when Kind is already specific.
	Keyword  string     `json:"keyword,omitempty"`
	Severity Severity   `json:"severity"`
	Detail   string     `json:"detail"`
	Ratchet  string     `json:"ratchet"`
	Affected []Affected `json:"affected,omitempty"`
}

// wholeCRDKinds are findings about the CRD or one of its versions rather than a schema location,
// so they carry no field path and correlate against every live CR instead of one path.
var wholeCRDKinds = map[string]bool{
	KindCRDAdded: true, KindCRDRemoved: true, KindStorageVersion: true,
	KindServedVersionGone: true, KindVersionUnserved: true, KindVersionAdded: true,
	KindPruningEnabled: true, KindScopeChanged: true,
}

func (f Finding) wholeCRD() bool { return wholeCRDKinds[f.Kind] }

// directionUnknown marks the findings crdsafe scores as risky only because it cannot prove which
// way they go. A cluster that reports nothing failing has answered the question they were asking.
var directionUnknown = map[string]bool{
	KindLogicChanged: true, KindCELAdded: true, KindUnmodeled: true,
}

// ratchetOf reports what the apiserver does with a violation of this kind.
func ratchetOf(kind string) string {
	switch kind {
	case KindRequiredAdded, KindTypeChanged, KindEnumNarrowed, KindConstraint:
		return RatchetTolerated
	case KindListType, KindListMapKeys:
		// Both ratchet on update through the enclosing object; they bite on create.
		return RatchetTolerated
	case KindCELAdded:
		// A rule reading oldSelf is never ratcheted; ratchetOfRule refines this per rule.
		return RatchetTolerated
	case KindFieldRemoved, KindPruningEnabled:
		return RatchetNA // never validated: the value is pruned before it reaches a validator
	default:
		return RatchetNA
	}
}

// crdifyKinds maps crdify validation names onto crdsafe's severity model.
// crdify has no severity of its own - error vs warning is purely the enforcement policy we hand it.
var crdifyKinds = map[string]struct {
	kind string
	sev  Severity
}{
	"type":          {KindTypeChanged, SevHigh},
	"enum":          {KindEnumNarrowed, SevHigh},
	"minimum":       {KindConstraint, SevMedium},
	"maximum":       {KindConstraint, SevMedium},
	"minItems":      {KindConstraint, SevMedium},
	"maxItems":      {KindConstraint, SevMedium},
	"minLength":     {KindConstraint, SevMedium},
	"maxLength":     {KindConstraint, SevMedium},
	"minProperties": {KindConstraint, SevMedium},
	"maxProperties": {KindConstraint, SevMedium},
	"pattern":       {KindConstraint, SevMedium},
	"nullable":      {KindTypeChanged, SevHigh},
	"default":       {KindConstraint, SevMedium},
	"scope":         {KindScopeChanged, SevCritical},
}

// crdify validations crdsafe re-derives itself, because crdify returns them as prose with the
// path buried in the string and correlation needs a real path.
var crdifyHandledLocally = map[string]bool{
	"required":             true,
	"existingFieldRemoval": true,
	"description":          true, // disabled by config anyway
	"storedVersionRemoval": true, // reads status.storedVersions, always empty on a chart-sourced CRD
}

// olmConfig mirrors what operator-controller hardcodes. crdify's stock defaults produce dozens of
// ERROR findings on a real chart upgrade (typo fixes in description, x-kubernetes-* churn).
func olmConfig() (*config.Config, error) {
	cfg := &config.Config{
		UnhandledEnforcement: config.EnforcementPolicyWarn,
		Conversion:           config.ConversionPolicyNone,
		Validations: []config.ValidationConfig{
			{Name: "description", Enforcement: config.EnforcementPolicyNone},
			{
				Name:          "enum",
				Enforcement:   config.EnforcementPolicyError,
				Configuration: map[string]interface{}{"additionPolicy": "Allow"},
			},
		},
	}
	// runner.New does not validate or default the config; unset policies silently behave as None.
	if err := config.ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("crdify config: %w", err)
	}
	return cfg, nil
}

// DiffCRDs compares the CRD sets of two chart versions.
func DiffCRDs(from, to []*apiextv1.CustomResourceDefinition) ([]Finding, error) {
	cfg, err := olmConfig()
	if err != nil {
		return nil, err
	}
	r, err := runner.New(cfg, runner.DefaultRegistry())
	if err != nil {
		return nil, fmt.Errorf("crdify runner: %w", err)
	}

	oldByName, newByName := byName(from), byName(to)
	var findings []Finding

	for _, name := range sortedKeys(oldByName) {
		if _, ok := newByName[name]; !ok {
			findings = append(findings, Finding{
				CRD: name, Kind: KindCRDRemoved, Severity: SevCritical, Ratchet: RatchetNA,
				Detail: "CRD is gone from the new chart; the apiextensions finalizer deletes every one of its custom resources",
			})
		}
	}
	for _, name := range sortedKeys(newByName) {
		if _, ok := oldByName[name]; !ok {
			findings = append(findings, Finding{
				CRD: name, Kind: KindCRDAdded, Severity: SevLow, Ratchet: RatchetNA,
				Detail: "new CRD",
			})
		}
	}

	for _, name := range sortedKeys(newByName) {
		oldCRD, ok := oldByName[name]
		if !ok {
			continue
		}
		newCRD := newByName[name]
		schema, removed := schemaFindings(oldCRD, newCRD)
		findings = append(findings, versionFindings(oldCRD, newCRD)...)
		findings = append(findings, schema...)
		findings = append(findings, crdifyFindings(r, oldCRD, newCRD, removed)...)
	}

	sortFindings(findings)
	return dedupe(findings), nil
}

// One schema change can reach the same conclusion by two routes - the same required field named in
// two branches of a oneOf, for instance. The reader should see it once.
func dedupe(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		key := strings.Join([]string{f.CRD, f.Version, f.Path, f.Kind, f.Detail}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// versionFindings tracks the spec.versions[] served and storage flags, plus the two whole-CRD
// settings that decide whether stored data survives at all.
func versionFindings(oldCRD, newCRD *apiextv1.CustomResourceDefinition) []Finding {
	var out []Finding
	add := func(f Finding) { f.CRD, f.Ratchet = newCRD.Name, RatchetNA; out = append(out, f) }

	if o, n := storageVersion(oldCRD), storageVersion(newCRD); o != n && o != "" && n != "" {
		// Moving the storage version only endangers data if reaching the new one converts it: a
		// webhook runs, the old version stops being served, or the two schemas actually differ.
		// A plain alpha-to-v1 graduation with identical schemas rewrites objects and changes
		// nothing about them.
		risky, why := storageRisk(oldCRD, newCRD, o, n)
		sev := SevLow
		if risky {
			sev = SevCritical
		}
		add(Finding{
			Version: n, Kind: KindStorageVersion, Severity: sev,
			Detail: fmt.Sprintf("storage version %s -> %s; %s", o, n, why),
		})
	}

	newVersions := versionsByName(newCRD)
	for _, ov := range oldCRD.Spec.Versions {
		nv, kept := newVersions[ov.Name]
		switch {
		case !kept && ov.Served:
			add(Finding{
				Version: ov.Name, Kind: KindServedVersionGone, Severity: SevCritical,
				Detail: fmt.Sprintf("served version %s is gone; reads and writes at that version stop working, and the apiserver rejects the CRD itself while %s is still in status.storedVersions", ov.Name, ov.Name),
			})
		case kept && ov.Served && !nv.Served:
			// Not a deletion, so nothing above catches it, but every client pinned to this
			// version starts getting 404s the moment the CRD lands.
			add(Finding{
				Version: ov.Name, Kind: KindVersionUnserved, Severity: SevCritical,
				Detail: fmt.Sprintf("version %s is no longer served; clients and controllers using it start failing immediately", ov.Name),
			})
		}
	}
	oldVersions := versionsByName(oldCRD)
	for _, nv := range newCRD.Spec.Versions {
		if _, existed := oldVersions[nv.Name]; !existed && nv.Served {
			add(Finding{
				Version: nv.Name, Kind: KindVersionAdded, Severity: SevLow,
				Detail: fmt.Sprintf("new served version %s", nv.Name),
			})
		}
	}

	// A v1beta1 CRD with preserveUnknownFields:true stored everything a client sent. The v1 API
	// always prunes, so this migration deletes every field the schema does not declare.
	if oldCRD.Spec.PreserveUnknownFields && !newCRD.Spec.PreserveUnknownFields {
		add(Finding{
			Kind: KindPruningEnabled, Severity: SevCritical,
			Detail: "the old CRD set preserveUnknownFields:true, so it stored fields absent from the schema; the new one prunes them, deleting that data on each object's next write",
		})
	}
	return out
}

// storageRisk says whether moving the storage version can change or lose stored data.
func storageRisk(oldCRD, newCRD *apiextv1.CustomResourceDefinition, from, to string) (bool, string) {
	if c := newCRD.Spec.Conversion; c != nil && c.Strategy == apiextv1.WebhookConverter {
		return true, "a conversion webhook rewrites every object on the way, so what it stores depends on that webhook"
	}
	if !isServed(newCRD, from) {
		return true, fmt.Sprintf("%s is no longer served, so objects still stored at it can only be reached through conversion", from)
	}
	oldSchema := validations.GetCRDVersionByName(newCRD, from)
	newSchema := validations.GetCRDVersionByName(newCRD, to)
	if oldSchema == nil || newSchema == nil || !reflect.DeepEqual(oldSchema.Schema, newSchema.Schema) {
		return true, fmt.Sprintf("the two versions do not share a schema, so objects change shape when they are rewritten to %s", to)
	}
	return false, fmt.Sprintf("both versions stay served with the same schema, so objects are rewritten to %s unchanged", to)
}

func versionsByName(crd *apiextv1.CustomResourceDefinition) map[string]apiextv1.CustomResourceDefinitionVersion {
	m := make(map[string]apiextv1.CustomResourceDefinitionVersion, len(crd.Spec.Versions))
	for _, v := range crd.Spec.Versions {
		m[v.Name] = v
	}
	return m
}

func storageVersion(crd *apiextv1.CustomResourceDefinition) string {
	for _, v := range crd.Spec.Versions {
		if v.Storage {
			return v.Name
		}
	}
	return ""
}

// schemaFindings derives the two classes crdify reports as prose: removed fields and added
// required fields. Both need a machine-readable path so a live CR can be correlated to them.
func schemaFindings(oldCRD, newCRD *apiextv1.CustomResourceDefinition) ([]Finding, removedPaths) {
	var out []Finding
	removed := removedPaths{}

	newVersions := versionsByName(newCRD)
	for _, ov := range oldCRD.Spec.Versions {
		nv, kept := newVersions[ov.Name]
		if !kept {
			continue // already reported whole, by versionFindings
		}
		oldFlat, newFlat := flatten(ov), flatten(nv)

		for _, path := range sortedKeys(oldFlat) {
			if _, stillThere := newFlat[path]; stillThere {
				continue
			}
			if parent := oldFlat[path].parent; parent != "" {
				if _, parentStillThere := newFlat[parent]; !parentStillThere {
					continue // report the shallowest removal only
				}
			}
			if oldFlat[path].inLogic {
				continue // the whole logic subtree is reported once, by logicFindings
			}
			if removed[ov.Name] == nil {
				removed[ov.Name] = map[string]bool{}
			}
			removed[ov.Name][path] = true
			out = append(out, Finding{
				CRD: newCRD.Name, Version: ov.Name, Path: oldFlat[path].instance,
				Kind: KindFieldRemoved, Severity: SevHigh, Ratchet: RatchetNA,
				Detail: "field removed from the schema; any value still stored under it is pruned on the next write, with no error",
			})
		}

		out = append(out, logicFindings(newCRD.Name, ov.Name, oldFlat, newFlat)...)

		for _, path := range sortedKeys(newFlat) {
			newNode := newFlat[path]
			if newNode.inLogic {
				continue // ditto
			}
			oldNode, existed := oldFlat[path]
			if !existed {
				// A brand-new optional property has no stored data to invalidate. A new
				// allOf/anyOf/oneOf/not branch is the opposite - it constrains data that is
				// already there - and so is anything declared under a parent that used to
				// preserve unknown fields. Both apply at any depth, not just to the top node.
				// A brand-new optional property has no stored data to invalidate. A field newly
				// declared under a parent that used to preserve unknown fields is different: that
				// data was being stored unchecked and is now validated and pruned.
				if !underPreserved(oldFlat, newNode.parent) {
					continue
				}
				oldNode = schemaNode{props: &apiextv1.JSONSchemaProps{}}
			}
			for _, name := range added(oldNode.props.Required, newNode.props.Required) {
				out = append(out, Finding{
					CRD: newCRD.Name, Version: ov.Name, Path: joinPath(newNode.instance, name),
					Kind: KindRequiredAdded, Severity: SevHigh, Ratchet: ratchetOf(KindRequiredAdded),
					Detail: fmt.Sprintf("%q is now required", name),
				})
			}
			out = append(out, extensionFindings(newCRD.Name, ov.Name, newNode.instance, oldNode.props, newNode.props, existed)...)
		}
	}
	return out, removed
}

// crdifyFindings reads all three of crdify's result buckets. Reading only the same-version one
// silently drops whole-CRD changes such as a Namespaced -> Cluster scope flip.
// extensionFindings reports what crdify leaves unclassified. crdify buries every one of those in
// an "unhandled" go-cmp dump, and enumerating the dangerous ones is a losing game: the list of
// schema fields that can invalidate a stored object is open-ended, and anything crdsafe forgot
// would read as "safe". So the polarity is inverted here - crdsafe ignores only what it can prove
// harmless, and reports every remaining difference by name.
func extensionFindings(crdName, version, instance string, oldProps, newProps *apiextv1.JSONSchemaProps, crdifySaw bool) []Finding {
	var out []Finding
	add := func(kind string, sev Severity, ratchet, detail string) {
		out = append(out, Finding{
			CRD: crdName, Version: version, Path: instance, Kind: kind,
			Severity: sev, Ratchet: ratchet, Detail: detail,
		})
	}

	for _, rule := range addedRules(oldProps.XValidations, newProps.XValidations) {
		ratchet := RatchetTolerated
		if strings.Contains(rule, "oldSelf") {
			ratchet = RatchetEnforced // transition rules are never ratcheted
		}
		if len(oldProps.XValidations) > 0 {
			// The field already carried rules and their text changed. Editing a rule to accept an
			// extra case is at least as common as adding a real restriction, and the text alone
			// does not say which; the live check settles it.
			add(KindCELAdded, SevMedium, ratchet,
				fmt.Sprintf("validation rule changed to %q; crdsafe cannot tell from the expression whether that accepts more or less", rule))
			continue
		}
		add(KindCELAdded, SevHigh, ratchet,
			fmt.Sprintf("new validation rule %q; stored objects that fail it are rejected on their next write", rule))
	}

	// List uniqueness. Adding it constrains what is already stored; changing established map keys
	// re-keys entries. Dropping either is a loosening and is not reported.
	oldType, newType := deref(oldProps.XListType), deref(newProps.XListType)
	oldKeys, newKeys := oldProps.XListMapKeys, newProps.XListMapKeys
	switch {
	case len(oldKeys) > 0 && len(newKeys) > 0 && !slices.Equal(oldKeys, newKeys):
		add(KindListMapKeys, SevCritical, ratchetOf(KindListMapKeys),
			fmt.Sprintf("list map keys %v -> %v; stored entries are re-keyed and every client's merge behaviour changes", oldKeys, newKeys))
	case len(oldKeys) == 0 && len(newKeys) > 0:
		add(KindListType, SevHigh, ratchetOf(KindListType),
			fmt.Sprintf("entries must now be unique by %v; a stored list with duplicates becomes invalid", newKeys))
	case oldType != newType && (newType == "set" || newType == "map"):
		add(KindListType, SevHigh, ratchetOf(KindListType),
			fmt.Sprintf("list type %s -> %q; entries must now be unique, and a stored list with duplicates becomes invalid",
				orNone(oldType), newType))
	}

	// An atomic map is a single leaf to server-side apply, so the next apply replaces the whole
	// map and drops keys owned by other field managers. Nothing becomes invalid; data still goes.
	if deref(oldProps.XMapType) != "atomic" && deref(newProps.XMapType) == "atomic" {
		add(KindMapAtomic, SevMedium, RatchetNA,
			"the map is now atomic; the next server-side apply replaces it wholesale and drops keys owned by other field managers")
	}

	if isTruePtr(oldProps.XPreserveUnknownFields) && !isTruePtr(newProps.XPreserveUnknownFields) {
		add(KindPruningEnabled, SevCritical, RatchetNA,
			"x-kubernetes-preserve-unknown-fields was switched off here; anything stored below this point is pruned on the next write")
	}

	if fields, relaxed := residualDiff(oldProps, newProps, crdifySaw); len(fields) > 0 {
		if relaxed {
			// Every differing field went from set to unset. A constraint that is gone cannot
			// reject anything that was already accepted.
			add(KindUnmodeled, SevLow, RatchetNA,
				fmt.Sprintf("%s no longer constrains this field", strings.Join(fields, ", ")))
		} else {
			add(KindUnmodeled, SevHigh, RatchetNA,
				fmt.Sprintf("%s changed here, and crdsafe cannot prove that keeps stored objects valid - review it by hand",
					strings.Join(fields, ", ")))
		}
	}
	return out
}

// classifiedElsewhere lists the schema fields crdify validates itself (its registered validation
// names) plus the ones extensionFindings handles above, so the residual comparison does not
// double-report them.
var classifiedElsewhere = map[string]bool{
	"Type": true, "Enum": true, "Pattern": true, "Required": true, "Default": true, "Nullable": true,
	"Minimum": true, "Maximum": true, "MinLength": true, "MaxLength": true,
	"MinItems": true, "MaxItems": true, "MinProperties": true, "MaxProperties": true,
	"XValidations": true, "XListType": true, "XListMapKeys": true, "XPreserveUnknownFields": true,
}

// provablyHarmless lists the fields whose change cannot make a stored object invalid: documentation,
// and x-kubernetes-map-type, which only affects server-side-apply merge semantics.
var provablyHarmless = map[string]bool{
	"Description": true, "Title": true, "Example": true, "ExternalDocs": true,
	"ID": true, "Schema": true, "Ref": true,
	"XMapType": true, // reported explicitly in extensionFindings; it cannot invalidate, but it does alter stored objects
}

// childFields are reached by their own nodes in the schema walk, so a change inside one is
// reported there rather than at the parent.
// childFields are reached by their own nodes in the schema walk, so a change inside one is
// reported there. Nothing else belongs here: a field the walk does not visit must fall through to
// the residual comparison rather than be silently exempted.
var childFields = map[string]bool{
	"Properties": true, "Items": true, "AllOf": true, "AnyOf": true, "OneOf": true, "Not": true,
}

// residualDiff names every field that differs and that nothing else in crdsafe or crdify covers.
// crdifySaw says whether crdify compared this pair. It only compares paths that exist on the OLD
// side, so for a node crdsafe synthesised an empty old counterpart for, the exemption below would
// drop every constraint on the new node instead of deferring to a report that never comes.
// The second return value reports that every difference is a constraint being dropped.
func residualDiff(oldProps, newProps *apiextv1.JSONSchemaProps, crdifySaw bool) ([]string, bool) {
	a, b := reflect.ValueOf(*oldProps), reflect.ValueOf(*newProps)
	t := a.Type()
	var names []string
	relaxed := true
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		if (crdifySaw && classifiedElsewhere[name]) || provablyHarmless[name] || childFields[name] {
			continue
		}
		x, y := a.Field(i).Interface(), b.Field(i).Interface()
		if name == "AdditionalProperties" {
			// The schema half is a child node; only the shape and the bool matter here.
			x, y = additionalShape(oldProps.AdditionalProperties), additionalShape(newProps.AdditionalProperties)
		}
		if reflect.DeepEqual(x, y) {
			continue
		}
		names = append(names, schemaFieldName(name))
		if name == "AdditionalProperties" {
			relaxed = relaxed && permissiveness(newProps.AdditionalProperties) > permissiveness(oldProps.AdditionalProperties)
			continue
		}
		// An absent keyword is an absent constraint, so new-is-zero means the constraint went away.
		relaxed = relaxed && b.Field(i).IsZero() && !a.Field(i).IsZero()
	}
	sort.Strings(names)
	return names, relaxed
}

func permissiveness(ap *apiextv1.JSONSchemaPropsOrBool) int {
	switch additionalShape(ap) {
	case "denied":
		return 0
	case "schema":
		return 1
	default: // absent or allowed: anything goes
		return 2
	}
}

// additionalShape distinguishes absent, a value schema, allow-anything and deny-anything, which
// a single bool would collapse.
// schemaFieldName turns a Go field name into what a CRD author actually writes.
func schemaFieldName(goName string) string {
	if goName == "ID" {
		return "id"
	}
	if s, ok := map[string]string{
		"XEmbeddedResource":      "x-kubernetes-embedded-resource",
		"XIntOrString":           "x-kubernetes-int-or-string",
		"XMapType":               "x-kubernetes-map-type",
		"XListType":              "x-kubernetes-list-type",
		"XListMapKeys":           "x-kubernetes-list-map-keys",
		"XValidations":           "x-kubernetes-validations",
		"XPreserveUnknownFields": "x-kubernetes-preserve-unknown-fields",
	}[goName]; ok {
		return s
	}
	return strings.ToLower(goName[:1]) + goName[1:]
}

func additionalShape(ap *apiextv1.JSONSchemaPropsOrBool) string {
	switch {
	case ap == nil:
		return "absent"
	case ap.Schema != nil:
		return "schema"
	case ap.Allows:
		return "allowed"
	default:
		return "denied"
	}
}

func addedRules(oldRules, newRules []apiextv1.ValidationRule) []string {
	have := make(map[string]bool, len(oldRules))
	for _, r := range oldRules {
		have[r.Rule] = true
	}
	var out []string
	for _, r := range newRules {
		if !have[r.Rule] {
			out = append(out, r.Rule)
		}
	}
	sort.Strings(out)
	return out
}

func isTruePtr(b *bool) bool { return b != nil && *b }

func deref[T ~string | ~bool](p *T) string {
	if p == nil {
		return ""
	}
	return fmt.Sprint(*p)
}

func orNone(s string) string {
	if s == "" {
		return "unset"
	}
	return strconv.Quote(s)
}

func underPreserved(oldFlat map[string]schemaNode, parent string) bool {
	for p := parent; p != ""; {
		node, ok := oldFlat[p]
		if !ok {
			return false
		}
		if isTruePtr(node.props.XPreserveUnknownFields) {
			return true
		}
		p = node.parent
	}
	return false
}

// logicFindings reports a change anywhere in a node's allOf/anyOf/oneOf/not structure as one
// finding, and deliberately does not try to say which direction it went.
//
// Whether an edit inside a logical combinator tightens or loosens a schema depends on the whole
// boolean expression, not on the node that changed: dropping a branch of an anyOf is a tightening,
// dropping the entire anyOf is a loosening, and `required` inside a `not` means the opposite of
// `required` anywhere else. A node-local diff cannot answer that, and four rounds of trying
// produced wrong answers in both directions. crdsafe does not have to answer it - it has the
// cluster. The apiserver reports a logic failure exactly, so the correlation below is the answer
// and the schema diff only has to say where to look.
func logicFindings(crdName, version string, oldFlat, newFlat map[string]schemaNode) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, path := range sortedKeys(newFlat) {
		node := newFlat[path]
		if node.inLogic {
			continue
		}
		old, existed := oldFlat[path]
		if !existed {
			// The whole subtree is new, so nothing is stored under it - unless the parent used to
			// keep whatever clients sent, in which case the data is there and now gets checked.
			// Argo CD 2.12 -> 3.4 adds one such subtree and it produced 27 findings about data
			// that does not exist.
			if !underPreserved(oldFlat, node.parent) {
				continue
			}
			old = schemaNode{props: &apiextv1.JSONSchemaProps{}}
		}
		if !hasLogic(node.props) && !hasLogic(old.props) {
			continue
		}
		if logicEqual(old.props, node.props) || seen[node.instance] {
			continue
		}
		seen[node.instance] = true
		out = append(out, Finding{
			CRD: crdName, Version: version, Path: node.instance, Kind: KindLogicChanged,
			Severity: SevHigh, Ratchet: RatchetTolerated,
			Detail: "the allOf/anyOf/oneOf/not structure changed here; whether that accepts more or less depends on the whole expression, so crdsafe checks the cluster instead of guessing",
		})
	}
	// A node that is gone entirely is reported as a removal; there is nothing to add by saying its
	// logic also went with it.
	return out
}

func logicOf(flat map[string]schemaNode, path string) *apiextv1.JSONSchemaProps {
	if n, ok := flat[path]; ok {
		return n.props
	}
	return &apiextv1.JSONSchemaProps{}
}

func hasLogic(p *apiextv1.JSONSchemaProps) bool {
	return p != nil && (len(p.AllOf) > 0 || len(p.AnyOf) > 0 || len(p.OneOf) > 0 || p.Not != nil)
}

func logicEqual(a, b *apiextv1.JSONSchemaProps) bool {
	return reflect.DeepEqual(a.AllOf, b.AllOf) && reflect.DeepEqual(a.AnyOf, b.AnyOf) &&
		reflect.DeepEqual(a.OneOf, b.OneOf) && reflect.DeepEqual(a.Not, b.Not)
}

func crdifyFindings(r *runner.Runner, oldCRD, newCRD *apiextv1.CustomResourceDefinition, removed removedPaths) []Finding {
	// Results.RenderJSON mutates the receiver, so read everything before rendering anything.
	res := r.Run(oldCRD, newCRD)
	var out []Finding

	for _, cr := range res.CRDValidation {
		if cr.IsZero() || crdifyHandledLocally[cr.Name] || len(cr.Errors) == 0 {
			continue
		}
		meta, known := crdifyKinds[cr.Name]
		if !known {
			meta.kind, meta.sev = cr.Name, SevHigh
		}
		out = append(out, Finding{
			CRD: newCRD.Name, Kind: meta.kind, Severity: meta.sev, Ratchet: ratchetOf(meta.kind),
			Detail: strings.Join(cr.Errors, "; "),
		})
	}

	// Both buckets share a shape. The served-version one compares two versions of the NEW CRD to
	// each other, which the "vA -> vB" version string makes recognisable downstream.
	index := newPathIndex(newCRD)
	logic := logicPaths(newCRD, oldCRD)
	oldVersions := versionsByName(oldCRD)
	for _, vr := range slices.Concat(res.SameVersionValidation, res.ServedVersionValidation) {
		// A served-bucket entry compares two versions of the NEW CRD to each other. That is a
		// property of the new chart's API surface, not of the upgrade - and when one side is a
		// version the old chart never had, crdify has no baseline to cancel against and reports
		// the whole new version field by field. Adding an alpha version is not a breaking change.
		if from, to, paired := strings.Cut(vr.Version, " -> "); paired {
			if _, hadFrom := oldVersions[from]; !hadFrom {
				continue
			}
			if _, hadTo := oldVersions[to]; !hadTo {
				continue
			}
		}
		for _, pr := range vr.PropertyComparisons {
			for _, cr := range pr.ComparisonResults {
				if cr.IsZero() || cr.Name == "unhandled" {
					continue // residualDiff covers everything crdify cannot classify
				}
				if logic.covers(vr.Version, pr.Property) {
					continue // reported once as a logic change; crdify cannot tell the direction either
				}
				if f, ok := propertyFinding(newCRD, vr.Version, pr.Property, cr, removed, index); ok {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

func propertyFinding(newCRD *apiextv1.CustomResourceDefinition, version, property string,
	cr validations.ComparisonResult, removed removedPaths, index pathIndex) (Finding, bool) {
	if crdifyHandledLocally[cr.Name] {
		return Finding{}, false
	}
	if removed.covers(version, property) {
		return Finding{}, false // already reported as a removal; this is the same change seen twice
	}
	if len(cr.Errors) == 0 && len(cr.Warnings) == 0 {
		return Finding{}, false
	}

	if loosened(cr.Name, newCRD, version, property) {
		return Finding{}, false
	}
	if cr.Name == "type" && strings.Contains(strings.Join(cr.Errors, " "), `-> ""`) {
		// crdify diffs a removed node against a synthesised empty schema. The removal is already
		// reported; this is the same change wearing a type change's clothes.
		return Finding{}, false
	}
	meta, known := crdifyKinds[cr.Name]
	if !known {
		meta.kind, meta.sev = cr.Name, SevMedium
	}
	// A same-version bucket entry compares one version to itself across the upgrade; a served
	// bucket entry compares two versions of the new CRD to each other, which is a conversion
	// problem rather than an upgrade break.
	if strings.Contains(version, " -> ") {
		meta.kind, meta.sev = KindCrossVersion, SevMedium
	}
	// crdify maps ten keywords onto one constraint class and shares one message across them, so
	// carry the keyword through for the reader. "nullable" gets the same treatment because its
	// class, typeChanged, does not say which of the two it was.
	keyword := ""
	if meta.kind == KindConstraint || cr.Name == "nullable" {
		keyword = cr.Name
	}
	return Finding{
		CRD: newCRD.Name, Version: version, Path: index.instance(version, property),
		Kind: meta.kind, Keyword: keyword, Severity: meta.sev, Ratchet: ratchetOf(meta.kind),
		Detail: strings.Join(slices.Concat(cr.Errors, cr.Warnings), "; "),
	}, true
}

// loosened checks the new schema directly for the two crdify validations whose direction its
// classification does not carry: an enum that is gone entirely constrains nothing, and a field
// that became nullable accepts strictly more.
func loosened(validation string, newCRD *apiextv1.CustomResourceDefinition, version, property string) bool {
	v := validations.GetCRDVersionByName(newCRD, version)
	if v == nil {
		return false
	}
	node, ok := flatten(*v)[property]
	if !ok {
		return false
	}
	switch validation {
	case "enum":
		return len(node.props.Enum) == 0
	case "nullable":
		return node.props.Nullable
	}
	return false
}

// removedPaths records, per CRD version, the SCHEMA paths whose entry is gone. Every crdify
// property finding under one of these is an artefact of the removal, not a separate change:
// crdify diffs against a synthesised empty schema for the missing side. Keyed on the schema path
// rather than the instance path, because two different schema paths can share an instance path.
type removedPaths map[string]map[string]bool

func (r removedPaths) covers(version, schemaPath string) bool {
	if from, to, paired := strings.Cut(version, " -> "); paired {
		return r.covers(from, schemaPath) || r.covers(to, schemaPath)
	}
	for removed := range r[version] {
		if schemaPath == removed || strings.HasPrefix(schemaPath, removed+".") {
			return true
		}
	}
	return false
}

func joinPath(base, leaf string) string {
	if base == "" {
		return leaf
	}
	return base + "." + leaf
}

func added(oldList, newList []string) []string {
	have := make(map[string]bool, len(oldList))
	for _, s := range oldList {
		have[s] = true
	}
	var out []string
	for _, s := range newList {
		if !have[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		if f[i].CRD != f[j].CRD {
			return f[i].CRD < f[j].CRD
		}
		if f[i].Path != f[j].Path {
			return f[i].Path < f[j].Path
		}
		return f[i].Kind < f[j].Kind
	})
}

func maxSeverity(f []Finding) Severity {
	worst := SevInfo
	for _, x := range f {
		if x.Severity > worst {
			worst = x.Severity
		}
	}
	return worst
}
