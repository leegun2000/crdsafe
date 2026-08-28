# crdsafe Phase 0 Kill-Check: RESCOPE

Date: 2026-08-28. All claims verified against primary sources on the date of writing.

## Verdict

No single tool does "detect CRD schema changes between chart version A and B, and check whether CRs existing in the cluster violate the new schema." The kill criterion is not met. But the project as specified is mostly re-implementation: pillar 1 is free from Helm, pillar 2 is 90 percent crdify, and pillar 3's validation engine is kubectl-validate. What is genuinely missing is the wiring and one novel output.

The honest short version: crdify already does the diff half, and crdsafe should be a thin wrapper. Build the wrapper, not the engines.

## Prior art

| Tool | Latest activity | Pillar 1: chart A/B CRD extraction | Pillar 2: schema diff + severity | Pillar 3: validate live CRs | Verdict |
|---|---|---|---|---|---|
| [kubernetes-sigs/crdify](https://github.com/kubernetes-sigs/crdify) | v0.6.0 2026-05-19, last commit 2026-06-02 | No. Zero "helm" hits in repo; file loader is one CRD per file | Yes, 6 of 7 classes. Misses storage-version flip | No. kube:// fetches the CRD object only; no client-go/dynamic dep | Strongest prior art. Import as library |
| [manohar-nunna/kubeproof-agent](https://github.com/manohar-nunna/kubeproof-agent) | Created and last pushed 2026-08-02, 2 commits, 0 stars, 0 releases | No. Loader rejects anything but one object per file | Yes, hand-rolled Python | Yes, `kubectl get {plural}.{group} -A` | Closest shape, dead prototype, not credible prior art |
| [openshift/crd-schema-checker](https://github.com/openshift/crd-schema-checker) | Push 2026-08-17, rebased to k8s 1.36 | No | Yes: no_field_removal, no_data_type_change, no_enum_removal, no_new_required_fields | No. README lists it as an unimplemented "Probable goal" | Maintained, pillar 2 only |
| [jerphil/helmdiff](https://github.com/jerphil/helmdiff) | All 15 commits on 2026-05-17, 2 stars | Yes, Helm SDK, .tgz and dirs, OCI | No. [crds.go](https://github.com/jerphil/helmdiff/blob/main/internal/diff/crds.go) compares CRD names and version NAMES only; never opens openAPIV3Schema | No cluster connection at all | Pillar 1 only, abandoned |
| [databus23/helm-diff](https://github.com/databus23/helm-diff) | v3.15.11 2026-08-01, active | Yes. `local CHART1 CHART2 --include-crds` | Partial. Line-based LCS or generic JSON-pointer field changes; no severity vocabulary | No | Pillar 1 solved, nothing else |
| [kubernetes-sigs/kubectl-validate](https://github.com/kubernetes-sigs/kubectl-validate) | No release since v0.0.4 2024-05-29; last commit 2026-01-05 | No | No | Engine only. `--local-crds` gives apiserver-grade + CEL errors; cluster client is OpenAPIV3 schema download only | Embed the validator, accept the maintenance risk |
| [yannh/kubeconform](https://github.com/yannh/kubeconform) | v0.8.0 2026-06-04 | No | No | Partial. Validates piped manifests, but silently passes CEL rules (open issue #236) | Do not use for pillar 3 |
| Pluto / kubent | Pluto v5.24.3 active; kubent stable 0.7.3 from 2024-08-30, dormant | No | No. Both reduce manifests to kind+apiVersion before matching | No | Different problem entirely |
| `kubectl apply --dry-run=server` | Core k8s | No | No | Broken for this use case. Validates against the INSTALLED CRD, and validation ratcheting (KEP-4008, stable in v1.33) suppresses unchanged-field violations | The obvious alternative, and it is wrong |
| [xrstf/crdiff](https://github.com/xrstf/crdiff) | 2023, 2 stars | Directory-level | Yes via oasdiff | No | Dead |
| [Ambiguous-ellipsis10/helmdiff](https://github.com/Ambiguous-ellipsis10/helmdiff) | 2026-08-26 | Not real | Not real | Not real | Download-bait spam: README only plus a .zip with an .exe. Do not fetch |

Governance check: [KEP-5000](https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/5000-api-linting-crd-schema-tooling/README.md) formally scopes crdify to CRD-to-CRD schema diffing plus an optional admission plugin. Live-CR validation and Helm integration are out of scope upstream. [HIP-0011](https://github.com/helm/community/blob/main/hips/hip-0011.md) is informational/final and deliberately proposes no CRD-upgrade solution; [helm/helm#31027](https://github.com/helm/helm/issues/31027) has been open since 2025-07-03. Nobody upstream is coming to close this.

## The strongest argument against building anything

An adversarial pass constructed and ran a 12-line shell pipeline over `helm template --include-crds`, `yq`, `crdify`, and `kubectl-validate` and covered all three pillars, including a real cert-manager v1.16.5 to v1.21.1 run that correctly reported zero breaking changes. If a 12-line script does it, a Go binary needs a better excuse than convenience.

The excuses that survive:

1. Correlation. The pipeline emits two disconnected reports. Nothing joins "enum narrowed at .spec.tier" to "these 4 CRs in staging now fail." A human does that join by eye. This is the only output no existing tool produces, and it is the actual product.
2. Defaults. crdify's stock config on a real cert-manager upgrade produced dozens of ERROR findings that are pure noise — description typo fixes, and raw Go struct dumps from the `unhandled` catch-all for an `XListType: nil -> "atomic"` change that cannot break any CR. Getting the right answer requires knowing to set `unhandledEnforcement: Warn`, `description: None`, `enum additionPolicy: Allow` — exactly what OLM's wrapper hardcodes. Worth four lines of YAML, not a project.
3. Distribution. crdify v0.6.0 ships zero release assets (verified: assets length 0; issue #6 closed without a binary), and kubectl-validate's only release predates its k8s 1.35 support. CI needs a Go toolchain to `go install` two semi-maintained sigs projects. One static binary is a real but unglamorous argument.

Points 2 and 3 alone would be a "write a Makefile" verdict. Point 1 is what makes it a binary.

## Honest weakness in pillar 3 that nobody in the survey turned on crdsafe

Validation ratcheting went stable in Kubernetes v1.33 ([KEP-4008](https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/4008-crd-ratcheting/kep.yaml)). The apiserver accepts updates to resources that are invalid after the update, provided the failing parts were not changed by the update. Stored CRs are never re-validated on read. So a live CR that violates a newly tightened minimum keeps working indefinitely, and even a full controller re-apply with unchanged values ratchets through.

This means crdsafe's pillar-3 output is a latent future-write hazard list, not an outage predictor. That is still worth having — required-field additions, list-type and list-map-key changes, quantors, properties-structure changes, additionalProperties removal, oldSelf CEL rules, and metadata validation all still fire, and conversion or storage-version migration forces a real rewrite. But the report must say which findings ratcheting protects and which it does not, or it will cry wolf. Making that distinction visible is itself a differentiator over `kubectl apply --dry-run=server`, which silently ratchets away four of the seven severity classes and reports success.

## Rescoped build

One binary. `crdsafe diff <chartA> <chartB> [--kubeconfig]`.

Vendored, not written:
- `helm.sh/helm` SDK for rendering both charts with IncludeCRDs. `Chart.CRDObjects()` already recurses into subchart `crds/`, verified empirically on Helm v4.2.4 with a fixture carrying CRDs in parent `crds/`, parent `templates/`, and a subchart `crds/`. Zero new code.
- `sigs.k8s.io/crdify` as a Go library for the schema diff and severity classification.
- `sigs.k8s.io/kubectl-validate` (or apiextensions-apiserver directly) for CR validation, which brings CEL for free.

Written from scratch, roughly 600-900 lines:
1. Pair CRDs by `metadata.name` across the two rendered sets; emit CRD-ADDED and CRD-REMOVED. crdify cannot express this — its loader is one CRD per file, and issue #63 asks for exactly this.
2. Storage-version-change detection: compare `spec.versions[?storage].name`. Verified as the one severity class crdify misses; its only storage check is `storedVersionRemoval`, which reads `.status.storedVersions` and is empty for file-loaded CRDs.
3. Live-CR enumeration: derive `spec.names.plural` + `spec.group` from each new CRD, list all instances across namespaces with `client-go/dynamic`. No maintained tool does this.
4. Correlation: join each breaking finding to the namespace/name of every live CR it invalidates. The product.
5. Ratcheting-aware severity annotation per the caveat above.
6. OLM-grade defaults baked in, `--crdify-config` to override.

Ergonomic landmines already mapped, all one-time: kubectl-validate cannot read stdin and cannot parse `kind: List`, and `--local-crds` silently ignores CRD files lacking a `.yaml`/`.yml` extension. Using it as a library sidesteps all three. Also warn when zero CRDs render — cert-manager v1.15+ gates its CRDs behind `crds.enabled`, so default values produce an empty result that looks like a clean bill of health.

## Risks to accept knowingly

- Both vendored engines are thinly maintained. crdify is 45 stars with no release binaries; kubectl-validate has an unanswered "State of the Project" issue open since 2026-04-27 and no release in over two years. Pin versions, expect to carry patches.
- crdify's known detection gaps are tracked and open: CEL/XValidations (#50), allOf/anyOf/not/multipleOf/uniqueItems/exclusiveMin/Max (#19-#27). crdsafe inherits them on the diff side, though the live-CR validation side covers CEL via kubectl-validate.
- If crdify ever grows a dynamic client, or crd-schema-checker delivers its stated "runtime check against all existing instances" goal, crdsafe's remaining value collapses to the Helm pairing and the correlation view. Ship small so that outcome is cheap.

## Appendix: the baseline crdsafe must beat

An adversarial agent constructed and RAN this. It covers all three pillars on a fixture chart
(CRDs in parent `crds/`, parent `templates/`, and a subchart) and on a real cert-manager
v1.16.5 -> v1.21.1 upgrade. It belongs in the README as "why not just do this", and any feature
crdsafe adds must be something this cannot do.

`crdify.yaml`:

```yaml
unhandledEnforcement: Warn
validations:
- {name: description, enforcement: None}
- {name: enum, enforcement: Error, configuration: {additionPolicy: Allow}}
```

`crdsafe.sh`:

```sh
mkdir -p old new objs; rc=0
helm template r "$1" --include-crds | yq ea -s '"old/" + .metadata.name + ".yaml"' 'select(.kind=="CustomResourceDefinition")' >/dev/null
helm template r "$2" --include-crds | yq ea -s '"new/" + .metadata.name + ".yaml"' 'select(.kind=="CustomResourceDefinition")' >/dev/null
for f in new/*; do n=${f#new/}
  [ -f "old/$n" ] || { echo "ADDED: $n"; continue; }
  [ "$(yq '.spec.versions[]|select(.storage).name' "old/$n")" = "$(yq '.spec.versions[]|select(.storage).name' "$f")" ] || { echo "BREAKING storage-version change: $n"; rc=1; }
  crdify --config crdify.yaml "file://$PWD/old/$n" "file://$PWD/$f" || rc=1
  kubectl get "$(yq '.spec.names.plural + "." + .spec.group' "$f")" -A -o yaml | yq ea -s '"objs/" + .metadata.namespace + "_" + .metadata.name' '.items[]' >/dev/null
done
for f in old/*; do [ -f "new/${f#old/}" ] || { echo "BREAKING CRD removed: ${f#old/}"; rc=1; }; done
kubectl-validate objs --local-crds new -o json || rc=1
exit $rc
```

What it cannot do, in order of how much it matters:

1. Join a breaking finding to the specific live CRs it invalidates. It prints two unrelated reports.
2. Say which findings validation ratcheting will absorb and which will actually bite.
3. Flag field removal as silent data loss (unknown fields are pruned on next write, never an error).
4. Ship as one binary. It needs helm, yq, kubectl, plus `go install` of two sigs projects with no release assets.
