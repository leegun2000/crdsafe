# crdsafe

Reports what a Helm chart upgrade would do to your CRDs, and to the custom resources already
running in your cluster.

**crdsafe never applies, patches, or deletes anything.** It reads two chart versions and lists
your cluster. That read-only guarantee is the point: it makes a judgement Helm declined to make,
and leaves the decision to you.

## The problem

Helm applies the CRDs in a chart's `crds/` directory **on install only**. On `helm upgrade` it
skips CRDs that already exist, with a warning. Helm 4 kept this behaviour deliberately.

The maintainers' reason is sound: an incompatible schema change can damage the custom resources
already stored in etcd, and Helm has no safe way to judge whether a given change is one of those.

The consequence is that your CRDs go stale while your controllers move on. The failure is quiet:
the controller reads a field the old CRD never had, or writes one the new schema no longer
declares, and nothing in `kubectl get` looks wrong. The
[Helm issue tracker](https://github.com/helm/helm/issues/31027) calls it a production time bomb.

There is a second half to this that the framing above misses. Many charts moved their CRDs out of
`crds/` and into `templates/` — argo-cd, cert-manager and istio's `base` chart all ship them that
way. Helm applies `templates/` on every upgrade like any other manifest, so those CRDs are not
stale at all: they are updated with no append-only rule and no check of any kind. Both halves want
the same answer. Either your CRD is stale and you want to know whether updating it is safe, or it
was updated already and you want to know what that did.

crdsafe makes the judgement Helm declined to make. It does not act on it.

## What it does

```
crdsafe check --chart argo-cd --repo https://argoproj.github.io/argo-helm --from 7.3.11 --to 7.4.0
```

```
CRD Compatibility Report: argo-cd 7.3.11 -> 7.4.0
Cluster: orbstack (v1.35.6+orb1)

CRD                          CHANGES  RISK
applicationsets.argoproj.io  10       CRITICAL

applicationsets.argoproj.io
  CRITICAL requiredAdded         [v1alpha1] status.applicationStatus.targetRevisions
    "targetRevisions" is now required
    ratchet: the apiserver accepts updates that leave this untouched; fails on create (restore, delete-and-recreate, argocd sync --force)
    2 live custom resources affected:
      crdsafe-demo/prod-apps  Required value
      crdsafe-demo/stg-apps  Required value
  MEDIUM   mapNowAtomic          [v1alpha1] spec.generators.clusterDecisionResource.labelSelector (+8 more)
    the map is now atomic; the next server-side apply replaces it wholesale and drops keys owned by other field managers
    also at spec.generators.clusters.selector
    also at spec.generators.matrix.generators.clusterDecisionResource.labelSelector
    also at spec.generators.matrix.generators.clusters.selector
    and 5 more paths (see --output json)

Live CRs checked: 3. Affected by a change: 2.
Exit 2 (CRITICAL)
```

Argo CD 2.12 added a required `targetRevisions` to `ApplicationSet.status.applicationStatus`.
Every ApplicationSet whose progressive-sync controller had already written a status predates the
field, so the object as stored is invalid under the new schema — which is what
[argoproj/argo-cd#20576](https://github.com/argoproj/argo-cd/issues/20576) turned out to be.
A schema-only diff can tell you a required field was added. The `2 live custom resources affected`
block is the part no other tool produces: which of your resources it is actually about. It is also
what makes this CRITICAL rather than HIGH — the same change with nothing stored behind it does not
block a build.

The same run on a version pair that removes a field:

```
CRD Compatibility Report: argo-cd 3.33.2 -> 4.9.10
Cluster: orbstack (v1.35.6+orb1)

CRD                          CHANGES  RISK
applications.argoproj.io     6        CRITICAL
applicationsets.argoproj.io  1        LOW

applications.argoproj.io
  CRITICAL fieldRemoved          [v1alpha1] spec.source.ksonnet
    field removed from the schema; any value still stored under it is pruned on the next write, with no error
    1 live custom resource affected:
      crdsafe-demo/legacy-ksonnet-app  value stored here is dropped on the next write (pruned, no error)
  HIGH     fieldRemoved          [v1alpha1] operation.sync.source.ksonnet (+4 more)
    field removed from the schema; any value still stored under it is pruned on the next write, with no error
    also at status.history.source.ksonnet
    also at status.operationState.operation.sync.source.ksonnet
    also at status.operationState.syncResult.source.ksonnet
    and 1 more path (see --output json)
```

Argo CD dropped ksonnet, and `source` appears at six paths in the Application schema. Only one of
the six is CRITICAL: it is the one where a resource in this cluster is still holding data that the
upgrade would silently delete. The other five are real removals with nothing behind them, so they
collapse into one entry. `--output json` always keeps every finding separate.

Other forms:

```
crdsafe check --from ./chart-1.0.0.tgz --to ./chart-2.0.0.tgz
crdsafe check --release argocd -n argocd --repo https://argoproj.github.io/argo-helm --to 7.4.0
```

`--release` reads the chart embedded in the deployed release, so it compares against what is
actually installed rather than a version number you remember.

Charts that gate their CRDs behind a value need that value; crdsafe tells you when nothing rendered.

```
crdsafe check --chart cert-manager --repo https://charts.jetstack.io \
  --from v1.16.5 --to v1.21.1 --set crds.enabled=true
```

Flags: `--set`, `-f`, `--kubeconfig`, `--context`, `--no-cluster`, `--max-objects`, `--redact`,
`--output json`.

**Before pasting a report anywhere public, read it or pass `--redact`.** The header names your
cluster — on EKS and GKE that context is an account ARN or a project path — and the apiserver
quotes the offending value back in a validation error, so a report can contain a repository URL
with a token in it, an internal hostname, or a bucket name. `--redact` drops those and the exact
server version, and keeps the CRD, the field, the severity and which of your resources is
affected.
Exit codes: `0` safe, `1` HIGH or above, `2` CRITICAL.

## What it looks for

| Change | Severity |
|---|---|
| CRD removed | CRITICAL |
| served version removed | CRITICAL |
| storage version changed | CRITICAL |
| version un-served, or scope flipped | CRITICAL |
| x-kubernetes-preserve-unknown-fields switched off, or list map keys changed | CRITICAL |
| **anything the cluster proves invalidates a resource you have** | **CRITICAL** |
| field removed | HIGH, and CRITICAL when a live CR still stores data there |
| required field added | HIGH |
| type or nullability changed | HIGH |
| enum narrowed | HIGH |
| CEL validation rule added, or list uniqueness switched on | HIGH |
| anything else crdsafe cannot prove harmless | HIGH |
| min/max/pattern/default tightened | MEDIUM |
| a map became atomic, so server-side apply now replaces it wholesale | MEDIUM |
| the allOf/anyOf/oneOf/not structure changed | HIGH until a cluster clears it |
| a validation rule added, where crdsafe cannot tell if it accepts more or less | HIGH until a cluster clears it |
| storage version moved between two served versions with the same schema | LOW |
| a constraint dropped rather than added | LOW |
| two of the new chart's versions no longer round-trip | MEDIUM |
| CRD added, or a served version added | LOW |
| description, title, example, x-kubernetes-map-type changed | not reported |

The "anything else" row is the important one. The list of schema fields that can invalidate a
stored object is open-ended, so crdsafe does not enumerate it. It ignores only the changes it can
prove harmless and reports everything else by field name — an unknown risk is not a safe one.

Severity is not decided by the schema alone. A finding that names resources the new schema
invalidates is CRITICAL whatever kind of change it is, and a finding that only scored high because
crdsafe could not tell which direction it went drops to MEDIUM once the cluster reports nothing
failing. Measured against the apiserver over a thousand generated upgrades, deciding this at the
schema and never revisiting it meant a third of provably broken clusters got a passing exit code.

The logic row is where crdsafe stops reasoning on purpose. Whether an edit inside `allOf`, `anyOf`,
`oneOf` or `not` makes a schema stricter or looser depends on the whole boolean expression, not on
the part that changed: dropping one branch of an `anyOf` is a tightening, dropping the entire
`anyOf` is a loosening, and `required` under a `not` means the opposite of `required` anywhere
else. A schema-only tool has to guess at that. crdsafe does not have to, because it has the
cluster — the apiserver reports a logic failure exactly — so it says where the structure changed
and lets the live check settle it.

Every finding says whether [validation ratcheting](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-ratcheting)
absorbs it. Since Kubernetes 1.33 the apiserver accepts an update that leaves a resource invalid,
as long as the update did not touch the offending value. So most findings are latent hazards that
bite on the next *create* — a restore, a delete-and-recreate sync — rather than immediate outages.
A tool that does not draw that line cries wolf. Ratcheting never applies below Kubernetes 1.30, and
crdsafe checks your server version to say so.

**Field removal is the one it is worth running for.** A removed property is not a validation error;
the value is silently pruned from the object on its next write, by any controller, for any reason.
No dry-run, no admission webhook, and no schema-only diff can see that data leave. crdsafe lists
the exact resources holding data in a field the new schema drops.

## In a GitOps pipeline

crdsafe needs no special support to comment on a pull request: the report goes to stdout and the
exit code is 0 safe / 1 needs review / 2 can destroy data.
[examples/gitops-pr-comment.yml](examples/gitops-pr-comment.yml) is a working GitHub Actions job
that reads the chart version out of the PR's diff, runs the check, and keeps a single updated
comment on the PR.

Two things there are worth reading rather than copying:

- **Pass `--redact` on a public repository.** Without it a comment can contain a value quoted back
  by the apiserver from one of your own resources.
- **Give the runner a read-only kubeconfig if you can.** With `--no-cluster` you get a schema diff,
  which every other tool can also give you. The part that is worth having in a pull request is the
  line naming the resources in your cluster that the new schema would reject.

## What it does not do

- Apply, upgrade, or migrate anything. Read-only, no exceptions.
- Deprecated apiVersion detection — that is [Pluto](https://github.com/FairwindsOps/pluto)
  and [kubent](https://github.com/doitintl/kube-no-trouble).
- Diff non-CRD resources — that is [helm-diff](https://github.com/databus23/helm-diff).
- Generate migrations, run a web UI, or talk to more than one cluster.

## How it differs from the neighbours

| | chart A vs B | CRD schema diff | validates live CRs |
|---|---|---|---|
| Pluto, kubent | no | no — they match apiVersion against a deprecation list | no |
| helm-diff | yes | textual only, no severity | no |
| kubeconform, kubectl-validate | no | no | engine only; you supply the resources |
| [crdify](https://github.com/kubernetes-sigs/crdify) | no | yes | no |
| crdsafe | yes | yes, via crdify | yes |

## How it works

crdsafe is mostly wiring. The hard parts belong to other people:

- [Helm SDK](https://helm.sh) renders both chart versions and collects CRDs from `crds/`,
  from `templates/`, and from every subchart.
- [sigs.k8s.io/crdify](https://github.com/kubernetes-sigs/crdify) classifies the schema changes,
  configured the way OLM's operator-controller configures it. Its stock defaults report English
  typo fixes as errors.
- [k8s.io/apiextensions-apiserver](https://github.com/kubernetes/apiextensions-apiserver) validates
  each live custom resource, so the verdict is the apiserver's own, CEL rules included.

crdsafe adds CRD pairing across two charts, storage and served version tracking, cluster-wide
resource enumeration, pruning detection, the ratcheting annotation, and the join between them.

## Install

Prebuilt binaries are on the [releases page](https://github.com/leegun2000/crdsafe/releases) for
`linux/amd64`, `linux/arm64` and `darwin/arm64`. One static binary, no runtime dependencies:

```
VERSION=v0.1.2
OS=linux ARCH=amd64        # or linux/arm64, or darwin/arm64
curl -sSL "https://github.com/leegun2000/crdsafe/releases/download/${VERSION}/crdsafe_${VERSION}_${OS}_${ARCH}.tar.gz" \
  | tar -xz crdsafe && sudo mv crdsafe /usr/local/bin/
crdsafe version
```

Checksums for every archive are published alongside them as
`crdsafe_${VERSION}_checksums.txt`.

From source, with Go 1.27 or newer:

```
go install github.com/leegun2000/crdsafe@latest
```

## License

Apache 2.0
