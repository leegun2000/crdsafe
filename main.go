package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"helm.sh/helm/v4/pkg/action"
	chartv2 "helm.sh/helm/v4/pkg/chart/v2"
	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/cli/values"
	releasev1 "helm.sh/helm/v4/pkg/release/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const usage = `crdsafe - report what a Helm chart upgrade does to your CRDs and to the custom
resources already in your cluster. Read-only: it never applies, patches, or deletes anything.

  crdsafe check --chart NAME --repo URL --from VERSION --to VERSION [flags]
  crdsafe check --from ./chart-1.0.0.tgz --to ./chart-2.0.0.tgz [flags]
  crdsafe check --release NAME -n NAMESPACE --repo URL --to VERSION [flags]

Without --chart, --from and --to are chart paths, .tgz files, or oci:// references.
The --release form reads the chart embedded in the deployed release, so --from is not needed.

Flags:
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	var (
		chartName  = fs.String("chart", "", "chart name, local path, .tgz, or oci:// reference")
		repoURL    = fs.String("repo", "", "chart repository URL")
		from       = fs.String("from", "", "current chart version")
		to         = fs.String("to", "", "target chart version")
		release    = fs.String("release", "", "read the current CRDs from this installed release instead of --from")
		namespace  = fs.String("n", "", "namespace of --release")
		kubeconfig = fs.String("kubeconfig", "", "path to kubeconfig (default: standard resolution)")
		kctx       = fs.String("context", "", "kubeconfig context")
		output     = fs.String("output", "text", "text or json")
		noCluster  = fs.Bool("no-cluster", false, "skip the live cluster check; diff schemas only")
		maxObjects = fs.Int("max-objects", maxObjectsPerCRD, "stop listing after this many custom resources per CRD")
		setVals    stringList
		valFiles   stringList
	)
	fs.Var(&setVals, "set", "set chart values (repeatable), e.g. --set crds.enabled=true")
	fs.Var(&valFiles, "f", "values file (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *to == "" {
		fmt.Fprintln(os.Stderr, "crdsafe: --to is required")
		return 2
	}
	if *maxObjects < 1 {
		fmt.Fprintln(os.Stderr, "crdsafe: --max-objects must be at least 1; a zero bound would report every CRD as having no live resources")
		return 2
	}
	if *chartName == "" && *release == "" && *from == "" {
		fmt.Fprintln(os.Stderr, "crdsafe: give --chart with --from/--to, or --from/--to as chart paths, or --release")
		return 2
	}
	// Helm logs a WARN for every `required` value a chart wants and we never supply; crdsafe
	// renders in lint mode on purpose, so keep only real errors.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	vals := values.Options{Values: setVals, ValueFiles: valFiles}
	ctx := context.Background()

	rep, err := check(ctx, checkOpts{
		chart: *chartName, repo: *repoURL, from: *from, to: *to,
		release: *release, namespace: *namespace,
		kubeconfig: *kubeconfig, kubeContext: *kctx,
		noCluster: *noCluster, maxObjects: *maxObjects, vals: vals,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "crdsafe: %v\n", err)
		return 2
	}

	if *output == "json" {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "crdsafe: %v\n", err)
			return 2
		}
	} else {
		rep.WriteText(os.Stdout)
	}
	return rep.ExitCode()
}

// ref reads --from/--to as versions of --chart, or as chart references in their own right.
func (o checkOpts) ref(version string) ChartRef {
	if o.chart == "" {
		return ChartRef{Chart: version}
	}
	return ChartRef{Chart: o.chart, RepoURL: o.repo, Version: version}
}

type checkOpts struct {
	chart, repo, from, to string
	release, namespace    string
	kubeconfig            string
	kubeContext           string
	noCluster             bool
	maxObjects            int
	vals                  values.Options
}

func check(ctx context.Context, o checkOpts) (*Report, error) {
	rep := &Report{Chart: o.chart, From: o.from, To: o.to}

	var oldCRDs []*apiextv1.CustomResourceDefinition
	var err error
	if o.release != "" {
		var name, version string
		oldCRDs, name, version, err = crdsFromRelease(o.release, o.namespace, o.kubeContext, o.kubeconfig)
		if err != nil {
			return nil, err
		}
		rep.Chart, rep.From = name, version+" (deployed)"
		if o.chart == "" {
			o.chart = name
		}
	} else {
		if o.from == "" {
			return nil, errors.New("--from is required unless --release is used")
		}
		var suppressed []string
		oldCRDs, suppressed, err = LoadCRDs(o.ref(o.from), o.vals)
		if err != nil {
			return nil, err
		}
		rep.Warnings = append(rep.Warnings, renderWarnings(o.from, suppressed)...)
	}

	newCRDs, suppressed, err := LoadCRDs(o.ref(o.to), o.vals)
	if err != nil {
		return nil, err
	}
	rep.Warnings = append(rep.Warnings, renderWarnings(o.to, suppressed)...)
	switch {
	case len(oldCRDs) == 0 && len(newCRDs) == 0:
		rep.Warnings = append(rep.Warnings,
			"neither chart version rendered any CRD - if the chart gates them behind a value, pass it with --set (cert-manager needs --set crds.enabled=true)")
	case len(oldCRDs) == 0:
		rep.Warnings = append(rep.Warnings,
			"the old chart rendered no CRD at all, so every CRD below looks new - check whether it gates CRDs behind a value this version spells differently (cert-manager renamed installCRDs to crds.enabled in v1.15)")
	case len(newCRDs) == 0:
		rep.Warnings = append(rep.Warnings,
			"the new chart rendered no CRD at all, so every CRD below looks removed - check whether it gates CRDs behind a value this version spells differently")
	}

	rep.Findings, err = DiffCRDs(oldCRDs, newCRDs)
	if err != nil {
		return nil, err
	}
	if o.noCluster {
		return rep, nil
	}

	cluster, err := Connect(ctx, o.kubeconfig, o.kubeContext)
	if err != nil {
		if errors.Is(err, ErrNoCluster) {
			rep.Warnings = append(rep.Warnings, "no reachable cluster; reporting the schema diff only")
			return rep, nil
		}
		return nil, err
	}
	cluster.MaxObjects = o.maxObjects
	rep.Cluster, rep.K8s = cluster.Context, cluster.Version
	rep.Ratcheting = &cluster.Ratcheting
	if !cluster.Ratcheting {
		rep.Warnings = append(rep.Warnings,
			"cluster predates validation ratcheting (k8s "+cluster.Version+"); every finding below is enforced on update too")
	}
	correlate(ctx, cluster, rep, byName(oldCRDs), byName(newCRDs))
	return rep, nil
}

// correlate is the join that makes crdsafe more than two separate reports: every finding gets
// the exact list of live custom resources it invalidates.
func correlate(ctx context.Context, cluster *Cluster, rep *Report, oldByName, newByName map[string]*apiextv1.CustomResourceDefinition) {
	checks := map[string]LiveCheck{}
	inspect := func(name string, crd *apiextv1.CustomResourceDefinition) LiveCheck {
		if c, done := checks[name]; done {
			return c
		}
		c := cluster.Inspect(ctx, crd)
		checks[name] = c
		return c
	}

	affectedCRs := map[string]bool{}
	for i := range rep.Findings {
		f := &rep.Findings[i]
		switch {
		case f.Kind == KindCRDRemoved:
			crd, ok := oldByName[f.CRD]
			if !ok {
				continue
			}
			for _, a := range inspect("old/"+f.CRD, crd).All {
				a.Reason = "deleted along with the CRD"
				f.Affected = append(f.Affected, a)
			}
		case f.Kind == KindPruningEnabled:
			crd, ok := newByName[f.CRD]
			if !ok {
				continue
			}
			f.Affected = inspect(f.CRD, crd).Pruned
		case f.wholeCRD():
			// Nothing object-level to point at, but still list the CRD so the count is honest.
			if crd, ok := newByName[f.CRD]; ok {
				inspect(f.CRD, crd)
			}
			continue
		default:
			crd, ok := newByName[f.CRD]
			if !ok {
				continue
			}
			f.Affected = inspect(f.CRD, crd).ByPath[f.Path]
		}
		// A change that provably breaks live data is worse than the same change on paper.
		if len(f.Affected) > 0 && f.Severity < SevCritical && f.Kind == KindFieldRemoved {
			f.Severity = SevCritical
		}
		for _, a := range f.Affected {
			affectedCRs[f.CRD+"|"+a.Namespace+"/"+a.Name] = true
		}
	}

	counted := map[string]bool{}
	for _, name := range sortedKeys(checks) { // map order would make the report unstable
		c := checks[name]
		if crdName := strings.TrimPrefix(name, "old/"); !counted[crdName] {
			counted[crdName] = true
			rep.Checked += c.Total
		}
		rep.Warnings = append(rep.Warnings, liveWarnings(strings.TrimPrefix(name, "old/"), c)...)
	}
	rep.Invalid = len(affectedCRs)
	sortFindings(rep.Findings)
}

// renderWarnings surfaces what lint-mode rendering swallowed, so a CRD gated behind a value the
// user did not supply cannot quietly go missing from the comparison.
func renderWarnings(version string, suppressed []string) []string {
	if len(suppressed) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%s: rendered past %d unmet chart requirement(s) - any CRD that depends on them may be missing or wrong: %s",
		version, len(suppressed), strings.Join(suppressed, " | "))}
}

func liveWarnings(name string, c LiveCheck) []string {
	var out []string
	switch {
	case c.Err != nil:
		out = append(out, name+": listing custom resources failed ("+c.Err.Error()+"); correlation skipped")
	case c.NotFound:
		out = append(out, name+": not installed in this cluster at any served version; correlation skipped")
	case c.Forbidden:
		out = append(out, name+": not authorized to list its custom resources; correlation skipped")
	case c.TimedOut:
		out = append(out, name+": listing custom resources timed out (conversion webhook?); correlation skipped")
	case c.Truncated:
		out = append(out, name+": too many custom resources to check them all; correlation is partial")
	}
	if c.Note != "" {
		out = append(out, name+": "+c.Note)
	}
	return out
}

// crdsFromRelease reads the chart that is actually deployed, which is more accurate than
// re-pulling a version number and needs no repository.
func crdsFromRelease(name, namespace, kubeContext, kubeconfig string) ([]*apiextv1.CustomResourceDefinition, string, string, error) {
	settings := cli.New()
	if namespace != "" {
		settings.SetNamespace(namespace)
	}
	if kubeContext != "" {
		settings.KubeContext = kubeContext
	}
	if kubeconfig != "" {
		// Without this the release is read through the default kubeconfig while the live CR check
		// uses --kubeconfig, and one report ends up straddling two clusters.
		settings.KubeConfig = kubeconfig
	}
	cfg := new(action.Configuration)
	// Driver stays empty on purpose: HELM_DRIVER=sql would have crdsafe open a database and run
	// DDL at startup, which a read-only tool has no business doing.
	if err := cfg.Init(settings.RESTClientGetter(), settings.Namespace(), ""); err != nil {
		return nil, "", "", fmt.Errorf("connecting to cluster for --release: %w", err)
	}
	got, err := action.NewGet(cfg).Run(name)
	if err != nil {
		return nil, "", "", fmt.Errorf("reading release %s: %w", name, err)
	}
	rel, ok := got.(*releasev1.Release)
	if !ok || rel.Chart == nil {
		return nil, "", "", fmt.Errorf("release %s carries no chart", name)
	}
	ch, ok := any(rel.Chart).(*chartv2.Chart)
	if !ok {
		return nil, "", "", fmt.Errorf("release %s uses an unsupported chart format", name)
	}
	crds, _, err := crdsFromChart(ch, rel.Config)
	return crds, ch.Name(), ch.Metadata.Version, err
}
