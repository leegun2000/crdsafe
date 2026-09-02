package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"helm.sh/helm/v4/pkg/action"
	chartcommon "helm.sh/helm/v4/pkg/chart/common"
	commonutil "helm.sh/helm/v4/pkg/chart/common/util"
	chartv2 "helm.sh/helm/v4/pkg/chart/v2"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"
	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/engine"
	"helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/registry"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"
)

// renderKubeVersion is what templates/ sees as .Capabilities.KubeVersion.
// ponytail: pinned so a chart version pair always diffs against the same capability set.
// Make it a flag if someone needs to diff a chart that gates CRDs on the k8s version.
const renderKubeVersion = "v1.31.0"

// ChartRef locates one side of the comparison.
type ChartRef struct {
	Chart   string // "cert-manager", "./mychart", "/tmp/x.tgz", or "oci://ghcr.io/org/chart"
	RepoURL string // empty for local paths and OCI
	Version string // exact version; empty means latest
}

func (r ChartRef) String() string {
	if r.Version == "" {
		return r.Chart
	}
	return r.Chart + " " + r.Version
}

// LoadCRDs pulls the chart and returns every CRD it declares: the chart's own crds/,
// every subchart's crds/, and any CustomResourceDefinition rendered from templates/.
// The second return value lists values the chart demanded and we did not supply. crdsafe renders
// in lint mode so an unrelated template cannot sink CRD extraction, which means those demands are
// suppressed rather than fatal - and a CRD gated behind one of them would render wrong.
func LoadCRDs(ref ChartRef, vals values.Options) ([]*apiextv1.CustomResourceDefinition, []string, error) {
	// Projects whose whole deliverable is CRDs often ship a plain manifest bundle and no chart at
	// all - Gateway API publishes standard-install.yaml and nothing else. Read those directly.
	if manifests, ok := manifestPaths(ref); ok {
		var out []*apiextv1.CustomResourceDefinition
		seen := map[string]bool{}
		for _, p := range manifests {
			body, err := os.ReadFile(p)
			if err != nil {
				return nil, nil, err
			}
			crds, err := decodeCRDs(body)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", p, err)
			}
			for _, crd := range crds {
				if !seen[crd.Name] {
					seen[crd.Name] = true
					out = append(out, crd)
				}
			}
		}
		return out, nil, nil
	}
	settings := cli.New()
	ch, err := loadChart(ref, settings)
	if err != nil {
		return nil, nil, err
	}
	userVals, err := vals.MergeValues(getter.All(settings))
	if err != nil {
		return nil, nil, fmt.Errorf("merge values: %w", err)
	}
	return crdsFromChart(ch, userVals)
}

// loadChart is `helm pull` + load. LocateChart never touches the cluster, so the zero
// action.Configuration is enough — crdsafe stays read-only and kubeconfig-free here.
func loadChart(ref ChartRef, settings *cli.EnvSettings) (*chartv2.Chart, error) {
	inst := action.NewInstall(&action.Configuration{})
	inst.RepoURL = ref.RepoURL
	inst.Version = ref.Version
	if registry.IsOCI(ref.Chart) {
		rc, err := registry.NewClient()
		if err != nil {
			return nil, fmt.Errorf("registry client: %w", err)
		}
		inst.SetRegistryClient(rc)
	}
	// Helm reads an unresolvable a/b as repo/chart, so a mistyped local path comes back as a
	// missing repository. Anything that can only be a filesystem path is checked as one.
	if ref.RepoURL == "" && !registry.IsOCI(ref.Chart) && looksLikePath(ref.Chart) {
		if _, err := os.Stat(ref.Chart); err != nil {
			return nil, fmt.Errorf("locate chart %s: %w", ref.Chart, err)
		}
	}
	path, err := inst.LocateChart(ref.Chart, settings)
	if err != nil {
		return nil, fmt.Errorf("locate chart %s: %w", ref, err)
	}
	return loader.Load(path)
}

// manifestPaths returns the YAML files to read when the reference is a manifest bundle or a
// directory of them rather than a chart.
func manifestPaths(ref ChartRef) ([]string, bool) {
	if ref.RepoURL != "" || registry.IsOCI(ref.Chart) {
		return nil, false
	}
	info, err := os.Stat(ref.Chart)
	if err != nil {
		return nil, false
	}
	if !info.IsDir() {
		if strings.HasSuffix(ref.Chart, ".yaml") || strings.HasSuffix(ref.Chart, ".yml") {
			return []string{ref.Chart}, true
		}
		return nil, false
	}
	if _, err := os.Stat(filepath.Join(ref.Chart, "Chart.yaml")); err == nil {
		return nil, false // a real chart; Helm handles it
	}
	entries, err := os.ReadDir(ref.Chart)
	if err != nil {
		return nil, false
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); !e.IsDir() && (strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			out = append(out, filepath.Join(ref.Chart, n))
		}
	}
	sort.Strings(out)
	return out, len(out) > 0
}

func looksLikePath(ref string) bool {
	return strings.HasSuffix(ref, ".tgz") || strings.HasSuffix(ref, ".tar.gz") ||
		strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../")
}

func crdsFromChart(ch *chartv2.Chart, userVals map[string]any) ([]*apiextv1.CustomResourceDefinition, []string, error) {
	// Capture everything Helm logs instead of erroring, across dependency processing as well as
	// the render itself.
	rec := &lintRecorder{}
	restore := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(restore)

	// Helm processes dependencies before it collects anything. Doing it later would leave a
	// subchart that a condition switches off contributing its crds/ directory to the comparison,
	// so crdsafe would report findings for CRDs the upgrade never touches.
	if err := chartutil.ProcessDependencies(ch, chartcommon.Values(userVals)); err != nil {
		return nil, nil, fmt.Errorf("processing chart dependencies: %w", err)
	}

	var out []*apiextv1.CustomResourceDefinition
	seen := map[string]bool{}
	add := func(src string, data []byte) error {
		crds, err := decodeCRDs(data)
		if err != nil {
			return fmt.Errorf("%s: %w", src, err)
		}
		for _, c := range crds {
			if !seen[c.Name] {
				seen[c.Name] = true
				out = append(out, c)
			}
		}
		return nil
	}

	// CRDObjects walks the chart's crds/ and recurses into every dependency.
	for _, obj := range ch.CRDObjects() {
		if err := add(obj.Filename, obj.File.Data); err != nil {
			return nil, nil, err
		}
	}

	rendered, err := renderTemplates(ch, userVals)
	if err != nil {
		// Never fall back to the crds/ directory alone: a chart can keep CRDs in templates/, and
		// silently dropping those would turn a breaking upgrade into a clean report.
		return nil, nil, err
	}
	for name, body := range rendered {
		if strings.HasSuffix(name, "NOTES.txt") || !strings.Contains(body, "CustomResourceDefinition") {
			continue
		}
		if err := add(name, []byte(body)); err != nil {
			return nil, nil, err
		}
	}
	return out, rec.messages(), nil
}

// renderTemplates is `helm template` with no cluster and no release storage.
func renderTemplates(ch *chartv2.Chart, userVals map[string]any) (map[string]string, error) {
	kv, err := chartcommon.ParseKubeVersion(renderKubeVersion)
	if err != nil {
		return nil, err
	}
	// A chart may branch on .Capabilities.HelmVersion; leaving it zero makes those templates
	// panic on a nil field rather than render.
	caps := &chartcommon.Capabilities{
		KubeVersion: *kv,
		APIVersions: chartcommon.DefaultVersionSet,
		HelmVersion: chartcommon.DefaultCapabilities.HelmVersion,
	}
	relOpts := chartcommon.ReleaseOptions{Name: "crdsafe", Namespace: "default", Revision: 1, IsInstall: true}
	rv, err := commonutil.ToRenderValues(ch, userVals, relOpts, caps)
	if err != nil {
		return nil, fmt.Errorf("render values: %w", err)
	}
	// LintMode keeps a missing `required` value, or an explicit `fail`, from aborting the render.
	// crdsafe wants CRDs, not a deployable release, so a half-rendered chart is still useful. The
	// caller captures what lint mode swallows.
	files, err := (&engine.Engine{LintMode: true}).Render(ch, rv)
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", ch.Name(), err)
	}
	return files, nil
}

// lintRecorder captures the "missing required value" and "funcMap fail" lines Helm emits instead
// of erroring when LintMode is on.
type lintRecorder struct{ seen []string }

func (r *lintRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *lintRecorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *lintRecorder) WithGroup(string) slog.Handler            { return r }

func (r *lintRecorder) Handle(_ context.Context, rec slog.Record) error {
	// Helm's lint-mode paths carry the suppressed text in a "message" attr. Everything else that
	// reaches this handler is Helm's own chatter - dependency counts and the like - which is only
	// worth surfacing when Helm itself considered it a warning.
	found := false
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "message" {
			r.seen, found = append(r.seen, a.Value.String()), true
		}
		return true
	})
	if !found && rec.Level >= slog.LevelWarn && rec.Message != "" {
		r.seen = append(r.seen, rec.Message)
	}
	return nil
}

func (r *lintRecorder) messages() []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range r.seen {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

func decodeCRDs(data []byte) ([]*apiextv1.CustomResourceDefinition, error) {
	var out []*apiextv1.CustomResourceDefinition
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		doc, err := r.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var tm metav1.TypeMeta
		if err := sigsyaml.Unmarshal(doc, &tm); err != nil {
			return nil, fmt.Errorf("reading a document as YAML: %w", err)
		}
		if tm.Kind != "CustomResourceDefinition" {
			continue
		}
		switch tm.APIVersion {
		case apiextv1.SchemeGroupVersion.String():
			var crd apiextv1.CustomResourceDefinition
			if err := sigsyaml.Unmarshal(doc, &crd); err != nil {
				return nil, fmt.Errorf("decode CRD: %w", err)
			}
			out = append(out, &crd)
		case apiextv1beta1.SchemeGroupVersion.String():
			// Old charts on the "from" side still ship the CRD API that k8s removed in 1.22.
			// Skipping them would break pairing and report the new CRD as freshly added, so
			// convert instead - the cluster serves these as v1 anyway.
			crd, err := convertV1beta1(doc)
			if err != nil {
				return nil, err
			}
			out = append(out, crd)
		default:
			return nil, fmt.Errorf("unsupported CRD apiVersion %q", tm.APIVersion)
		}
	}
}

func byName(crds []*apiextv1.CustomResourceDefinition) map[string]*apiextv1.CustomResourceDefinition {
	m := make(map[string]*apiextv1.CustomResourceDefinition, len(crds))
	for _, c := range crds {
		m[c.Name] = c
	}
	return m
}

// convertV1beta1 upgrades an apiextensions.k8s.io/v1beta1 CRD to v1. The generated converters do
// everything except move the single top-level spec.validation into each version, which is the one
// structural difference between the two APIs.
func convertV1beta1(doc []byte) (*apiextv1.CustomResourceDefinition, error) {
	var beta apiextv1beta1.CustomResourceDefinition
	if err := sigsyaml.Unmarshal(doc, &beta); err != nil {
		return nil, fmt.Errorf("decode v1beta1 CRD: %w", err)
	}
	// The real defaulter, not a hand-copied subset of it. v1beta1 defaults scope to Namespaced and
	// preserveUnknownFields to true, among others; missing either invents a change that is not
	// there or hides one that is.
	apiextv1beta1.SetObjectDefaults_CustomResourceDefinition(&beta)
	internal := &apiextensions.CustomResourceDefinition{}
	if err := apiextv1beta1.Convert_v1beta1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&beta, internal, nil); err != nil {
		return nil, fmt.Errorf("convert v1beta1 CRD %s: %w", beta.Name, err)
	}

	spec := &internal.Spec
	if len(spec.Versions) == 0 && spec.Version != "" {
		spec.Versions = []apiextensions.CustomResourceDefinitionVersion{
			{Name: spec.Version, Served: true, Storage: true},
		}
	}
	for i := range spec.Versions {
		if spec.Versions[i].Schema == nil {
			spec.Versions[i].Schema = spec.Validation
		}
		if spec.Versions[i].Subresources == nil {
			spec.Versions[i].Subresources = spec.Subresources
		}
	}
	spec.Validation, spec.Subresources, spec.Version = nil, nil, ""
	spec.AdditionalPrinterColumns = nil // v1 requires these per version; they never affect a schema diff
	if spec.PreserveUnknownFields == nil {
		// The v1beta1 API defaults this to true, and we are not running its defaulters. Left unset
		// it would read as false and hide the fact that moving to v1 starts pruning stored data.
		yes := true
		spec.PreserveUnknownFields = &yes
	}
	if spec.Conversion == nil {
		spec.Conversion = &apiextensions.CustomResourceConversion{Strategy: apiextensions.NoneConverter}
	}

	out := &apiextv1.CustomResourceDefinition{}
	if err := apiextv1.Convert_apiextensions_CustomResourceDefinition_To_v1_CustomResourceDefinition(internal, out, nil); err != nil {
		return nil, fmt.Errorf("convert CRD %s to v1: %w", beta.Name, err)
	}
	return out, nil
}
