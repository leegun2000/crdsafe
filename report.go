package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
)

type Report struct {
	Chart   string `json:"chart"`
	From    string `json:"from"`
	To      string `json:"to"`
	Cluster string `json:"cluster,omitempty"`
	K8s     string `json:"kubernetesVersion,omitempty"`
	// nil when no cluster was reached, so the report does not claim to know.
	Ratcheting *bool `json:"validationRatcheting,omitempty"`
	// CRDsCompared separates "the CRDs did not change" from "there were no CRDs to compare".
	CRDsCompared int       `json:"crdsCompared"`
	Findings     []Finding `json:"findings"`
	Checked      int       `json:"liveCRsChecked"`
	Invalid      int       `json:"liveCRsAffected"`
	Warnings     []string  `json:"warnings,omitempty"`
}

func (r *Report) Risk() Severity { return maxSeverity(r.Findings) }

// redacted returns a copy safe to paste somewhere public. The apiserver embeds the offending value
// in a validation error, so a report can quote a repository URL with a token in it, an internal
// host, or a bucket name; a kubeconfig context is commonly an EKS ARN or a GKE project path. What
// stays is what makes the report readable: the CRD, the field, the severity, the kind of failure,
// and which of your resources it names.
func (r *Report) redacted() *Report {
	out := *r
	if out.Cluster != "" {
		out.Cluster = "(redacted)"
		out.K8s = minorVersion(out.K8s)
	}
	out.Findings = make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.Affected = make([]Affected, len(r.Findings[i].Affected))
		for j, a := range r.Findings[i].Affected {
			a.Reason = reasonKind(a.Reason)
			f.Affected[j] = a
		}
		out.Findings[i] = f
	}
	out.Warnings = make([]string, len(r.Warnings))
	for i, w := range r.Warnings {
		out.Warnings[i] = redactWarning(w)
	}
	return &out
}

// reasonKind keeps the apiserver's verdict and drops the value it quotes:
// `Invalid value: "https://user:token@host": must be https` -> `Invalid value`.
func reasonKind(reason string) string {
	if kind, _, found := strings.Cut(reason, ": "); found {
		return kind
	}
	return reason
}

// redactWarning strips the one warning that embeds a raw client-go error, which is where an
// apiserver address can appear. Every other warning is crdsafe's own fixed text plus a CRD name,
// and blanking those would throw away the fix the reader needs.
const listFailurePrefix = "listing custom resources failed ("

func redactWarning(w string) string {
	if i := strings.Index(w, listFailurePrefix); i >= 0 {
		return w[:i+len(listFailurePrefix)-1] + "(details omitted); correlation skipped"
	}
	return w
}

// minorVersion keeps v1.33 and drops the patch level and distribution suffix, which together name
// a precise build to match a CVE against.
func minorVersion(v string) string {
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) < 2 {
		return "(redacted)"
	}
	return "v" + parts[0] + "." + parts[1] + ".x"
}

// ExitCode follows the spec: 0 safe, 1 HIGH or above, 2 CRITICAL.
func (r *Report) ExitCode() int {
	switch {
	case r.Risk() >= SevCritical:
		return 2
	case r.Risk() >= SevHigh:
		return 1
	default:
		return 0
	}
}

func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (r *Report) WriteText(w io.Writer) {
	if r.Chart == "" {
		fmt.Fprintf(w, "CRD Compatibility Report: %s -> %s\n", r.From, r.To)
	} else {
		fmt.Fprintf(w, "CRD Compatibility Report: %s %s -> %s\n", r.Chart, r.From, r.To)
	}
	if r.Cluster != "" {
		fmt.Fprintf(w, "Cluster: %s (%s)\n", r.Cluster, r.K8s)
	} else {
		fmt.Fprintln(w, "Cluster: not connected - schema diff only, no live CR correlation")
	}
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		if r.CRDsCompared == 0 {
			fmt.Fprintln(w, "No CRDs in either chart version - nothing was compared.")
		} else {
			fmt.Fprintf(w, "No CRD changes across %s.\n", plural(r.CRDsCompared, "CRD"))
		}
	} else {
		writeSummary(w, r.Findings)
		for _, crd := range crdOrder(r.Findings) {
			fmt.Fprintf(w, "\n%s\n", crd)
			for _, g := range group(r.Findings, crd) {
				f := g.Finding
				f.Version = strings.Join(g.versions, ", ")
				writeFinding(w, f, g.alsoAt, r.Ratcheting)
			}
		}
	}

	fmt.Fprintln(w)
	if r.Cluster != "" {
		fmt.Fprintf(w, "Live CRs checked: %d. Affected by a change: %d.\n", r.Checked, r.Invalid)
	}
	for _, note := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", note)
	}
	fmt.Fprintf(w, "Exit %d (%s)\n", r.ExitCode(), r.Risk())
}

func writeSummary(w io.Writer, findings []Finding) {
	type row struct {
		count int
		risk  Severity
	}
	perCRD := map[string]*row{}
	var order []string
	for _, f := range findings {
		if _, ok := perCRD[f.CRD]; !ok {
			perCRD[f.CRD] = &row{}
			order = append(order, f.CRD)
		}
		perCRD[f.CRD].count++
		if f.Severity > perCRD[f.CRD].risk {
			perCRD[f.CRD].risk = f.Severity
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := perCRD[order[i]], perCRD[order[j]]
		if a.risk != b.risk {
			return a.risk > b.risk
		}
		return order[i] < order[j]
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CRD\tCHANGES\tRISK")
	for _, name := range order {
		fmt.Fprintf(tw, "%s\t%d\t%s\n", name, perCRD[name].count, perCRD[name].risk)
	}
	tw.Flush()
}

const (
	findingIndent = "    "
	maxAlsoAt     = 3
)

func writeFinding(w io.Writer, f Finding, alsoAt []string, ratcheting *bool) {
	loc := f.Path
	if loc == "" {
		loc = "(whole CRD)"
	}
	if len(alsoAt) > 0 {
		loc += fmt.Sprintf(" (+%d more)", len(alsoAt))
	}
	label := f.Kind
	if f.Keyword != "" {
		label = f.Keyword
	}
	fmt.Fprintf(w, "  %-8s %-21s %s %s\n", f.Severity, label, versionTag(f.Version), loc)
	fmt.Fprintf(w, "%s%s\n", findingIndent, f.Detail)
	// The full list is in --output json; three is enough to recognise the pattern.
	for i, p := range alsoAt {
		if i == maxAlsoAt {
			fmt.Fprintf(w, "%sand %s (see --output json)\n", findingIndent, plural(len(alsoAt)-i, "more path"))
			break
		}
		fmt.Fprintf(w, "%salso at %s\n", findingIndent, p)
	}
	if note := ratchetNote(f, ratcheting); note != "" {
		fmt.Fprintf(w, "%s%s\n", findingIndent, note)
	}
	if len(f.Affected) == 0 {
		return
	}
	fmt.Fprintf(w, "%s%s affected:\n", findingIndent, plural(len(f.Affected), "live custom resource"))
	for _, a := range f.Affected {
		fmt.Fprintf(w, "%s  %s  %s\n", findingIndent, crName(a), a.Reason)
	}
}

// grouped is one printed entry: a finding, plus the other paths where the identical change
// happened. A codegen bump can add the same annotation to a dozen fields, and a dozen identical
// paragraphs bury the one finding that matters. The JSON output keeps every finding separate.
type grouped struct {
	Finding
	alsoAt   []string
	versions []string
}

func group(findings []Finding, crd string) []grouped {
	var out []grouped
	at := map[string]int{}
	for _, f := range findings {
		if f.CRD != crd {
			continue
		}
		// A finding with correlated resources always stands alone: its live CRs are the point.
		// Version is not part of the key: a CRD serving three versions of the same schema reports
		// the same change three times, and that is one change to read, not three.
		key := strings.Join([]string{f.Kind, f.Keyword, f.Severity.String(), f.Detail}, "\x00")
		if i, seen := at[key]; seen && len(f.Affected) == 0 && len(out[i].Affected) == 0 {
			if f.Path != out[i].Path && !slices.Contains(out[i].alsoAt, f.Path) {
				out[i].alsoAt = append(out[i].alsoAt, f.Path)
			}
			if !slices.Contains(out[i].versions, f.Version) {
				out[i].versions = append(out[i].versions, f.Version)
			}
			continue
		}
		at[key] = len(out)
		out = append(out, grouped{Finding: f, versions: []string{f.Version}})
	}
	return out
}

// crdOrder lists each CRD once, worst first, matching the summary table above it.
func crdOrder(findings []Finding) []string {
	worst := map[string]Severity{}
	var order []string
	for _, f := range findings {
		if _, seen := worst[f.CRD]; !seen {
			order = append(order, f.CRD)
		}
		if f.Severity > worst[f.CRD] {
			worst[f.CRD] = f.Severity
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		if worst[order[i]] != worst[order[j]] {
			return worst[order[i]] > worst[order[j]]
		}
		return order[i] < order[j]
	})
	return order
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func versionTag(v string) string {
	if v == "" {
		return ""
	}
	return "[" + v + "]"
}

func crName(a Affected) string {
	if a.Namespace == "" {
		return a.Name
	}
	return a.Namespace + "/" + a.Name
}

// ratchetNote must not promise tolerance the cluster does not offer: validation ratcheting is
// only on by default from Kubernetes 1.30.
func ratchetNote(f Finding, ratcheting *bool) string {
	if f.Ratchet != RatchetTolerated {
		return ""
	}
	switch {
	case ratcheting != nil && !*ratcheting:
		return "ratchet: this cluster predates validation ratcheting, so every write to the object is rejected"
	case ratcheting == nil:
		return "ratchet: on Kubernetes 1.30+ an update that leaves this untouched is accepted, and creates still fail; connect to a cluster to confirm its version"
	default:
		return "ratchet: the apiserver accepts updates that leave this untouched; fails on create (restore, delete-and-recreate, argocd sync --force)"
	}
}
