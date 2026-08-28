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
	CRD      string     `json:"crd"`
	Version  string     `json:"version,omitempty"`
	Path     string     `json:"path,omitempty"` // instance-style path, e.g. spec.template.spec.project
	Kind     string     `json:"kind"`
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
	KindPruningEnabled: true, KindScopeChanged: true, KindUnmodeled: true,
}

func (f Finding) wholeCRD() bool { return wholeCRDKinds[f.Kind] }

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
	return findings, nil
}

// versionFindings tracks the spec.versions[] served and storage flags, plus the two whole-CRD
// settings that decide whether stored data survives at all.
func versionFindings(oldCRD, newCRD *apiextv1.CustomResourceDefinition) []Finding {
	var out []Finding
	add := func(f Finding) { f.CRD, f.Ratchet = newCRD.Name, RatchetNA; out = append(out, f) }

	if o, n := storageVersion(oldCRD), storageVersion(newCRD); o != n && o != "" && n != "" {
		add(Finding{
			Version: n, Kind: KindStorageVersion, Severity: SevCritical,
			Detail: fmt.Sprintf("storage version %s -> %s; existing objects stay at %s until each is rewritten", o, n, o),
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
			if isConstraintNode(path) {
				continue // dropping an allOf/anyOf/oneOf/not loosens the schema; nothing breaks
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

		for _, path := range sortedKeys(newFlat) {
			newNode := newFlat[path]
			oldNode, existed := oldFlat[path]
			if !existed {
				// A brand-new optional property has no stored data to invalidate, so it is not
				// interesting. A brand-new allOf/anyOf/oneOf/not is the opposite: it constrains
				// data that is already there. So is a field newly declared under a parent that
				// used to preserve unknown fields, because that data was being stored unchecked.
				if !isConstraintNode(path) && !underPreservedParent(oldFlat, newNode.parent) {
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
			out = append(out, extensionFindings(newCRD.Name, ov.Name, newNode.instance, oldNode.props, newNode.props)...)
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
func extensionFindings(crdName, version, instance string, oldProps, newProps *apiextv1.JSONSchemaProps) []Finding {
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

	if isTruePtr(oldProps.XPreserveUnknownFields) && !isTruePtr(newProps.XPreserveUnknownFields) {
		add(KindPruningEnabled, SevCritical, RatchetNA,
			"x-kubernetes-preserve-unknown-fields was switched off here; anything stored below this point is pruned on the next write")
	}

	if fields := residualDiff(oldProps, newProps); len(fields) > 0 {
		add(KindUnmodeled, SevHigh, RatchetNA,
			fmt.Sprintf("%s changed here, and crdsafe cannot prove that keeps stored objects valid - review it by hand",
				strings.Join(fields, ", ")))
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
	"Description": true, "Title": true, "Example": true, "ExternalDocs": true, "XMapType": true,
	"ID": true, "Schema": true, "Ref": true,
}

// childFields are reached by their own nodes in the schema walk, so a change inside one is
// reported there rather than at the parent.
var childFields = map[string]bool{
	"Properties": true, "Items": true, "AllOf": true, "AnyOf": true, "OneOf": true, "Not": true,
	"PatternProperties": true, "Definitions": true, "Dependencies": true, "AdditionalItems": true,
}

// residualDiff names every field that differs and that nothing else in crdsafe or crdify covers.
func residualDiff(oldProps, newProps *apiextv1.JSONSchemaProps) []string {
	a, b := reflect.ValueOf(*oldProps), reflect.ValueOf(*newProps)
	t := a.Type()
	var names []string
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		if classifiedElsewhere[name] || provablyHarmless[name] || childFields[name] {
			continue
		}
		x, y := a.Field(i).Interface(), b.Field(i).Interface()
		if name == "AdditionalProperties" {
			// Only the bool half matters here; the schema half is a child node.
			x, y = allowsUnknown(oldProps.AdditionalProperties), allowsUnknown(newProps.AdditionalProperties)
		}
		if !reflect.DeepEqual(x, y) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func allowsUnknown(ap *apiextv1.JSONSchemaPropsOrBool) bool {
	return ap != nil && ap.Allows && ap.Schema == nil
}

// isConstraintNode reports whether a schema path's last step is an allOf/anyOf/oneOf/not entry.
// Those add no object level - they only add constraints to data that already exists.
func isConstraintNode(schemaPath string) bool {
	last := schemaPath[strings.LastIndex(schemaPath, ".")+1:]
	if last == "not" {
		return true
	}
	if i := strings.IndexByte(last, '['); i > 0 {
		switch last[:i] {
		case "allOf", "anyOf", "oneOf":
			return true
		}
	}
	return false
}

func underPreservedParent(oldFlat map[string]schemaNode, parent string) bool {
	node, ok := oldFlat[parent]
	return ok && isTruePtr(node.props.XPreserveUnknownFields)
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
	return Finding{
		CRD: newCRD.Name, Version: version, Path: index.instance(version, property),
		Kind: meta.kind, Severity: meta.sev, Ratchet: ratchetOf(meta.kind),
		Detail: strings.Join(slices.Concat(cr.Errors, cr.Warnings), "; "),
	}, true
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
