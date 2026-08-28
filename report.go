package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
)

type Report struct {
	Chart   string `json:"chart"`
	From    string `json:"from"`
	To      string `json:"to"`
	Cluster string `json:"cluster,omitempty"`
	K8s     string `json:"kubernetesVersion,omitempty"`
	// nil when no cluster was reached, so the report does not claim to know.
	Ratcheting *bool     `json:"validationRatcheting,omitempty"`
	Findings   []Finding `json:"findings"`
	Checked    int       `json:"liveCRsChecked"`
	Invalid    int       `json:"liveCRsAffected"`
	Warnings   []string  `json:"warnings,omitempty"`
}

func (r *Report) Risk() Severity { return maxSeverity(r.Findings) }

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
		fmt.Fprintln(w, "No CRD changes.")
	} else {
		writeSummary(w, r.Findings)
		for _, crd := range crdOrder(r.Findings) {
			fmt.Fprintf(w, "\n%s\n", crd)
			for _, f := range r.Findings {
				if f.CRD == crd {
					writeFinding(w, f, r.Ratcheting)
				}
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

const findingIndent = "    "

func writeFinding(w io.Writer, f Finding, ratcheting *bool) {
	loc := f.Path
	if loc == "" {
		loc = "(whole CRD)"
	}
	fmt.Fprintf(w, "  %-8s %-21s %s %s\n", f.Severity, f.Kind, versionTag(f.Version), loc)
	fmt.Fprintf(w, "%s%s\n", findingIndent, f.Detail)
	if note := ratchetNote(f, ratcheting); note != "" {
		fmt.Fprintf(w, "%s%s\n", findingIndent, note)
	}
	if len(f.Affected) == 0 {
		return
	}
	fmt.Fprintf(w, "%s%d live CR(s) affected:\n", findingIndent, len(f.Affected))
	for _, a := range f.Affected {
		fmt.Fprintf(w, "%s  %s  %s\n", findingIndent, crName(a), a.Reason)
	}
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
