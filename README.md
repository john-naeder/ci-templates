# ci-templates

Shared GitLab CI templates for a **self-hosted GitLab CE** instance.

Everything here is built from open-source scanners rather than GitLab's
`Security/*.gitlab-ci.yml` templates, because Dependency Scanning, Container
Scanning, License Scanning and the Security Dashboard are Ultimate features.
On CE those templates either refuse to run or produce reports that nothing
renders.

## `security.gitlab-ci.yml`

| Job | Tool | Covers |
| --- | --- | --- |
| `secrets:trivy` | Trivy | credentials in the working tree — **always blocking** |
| `secrets:gitleaks` | Gitleaks | credentials anywhere in git history — **always blocking** |
| `deps:trivy` | Trivy | vulnerable packages from lockfiles and OS packages |
| `deps:dotnet` | .NET SDK | NuGet advisories, which Trivy misses without `packages.lock.json` |
| `iac:trivy` | Trivy | Dockerfile, Compose, Kubernetes, Helm, Terraform, Ansible |
| `sast:semgrep` | Semgrep OSS | code-level findings across C#, Go, Python, Java, JS/TS |
| `container:trivy` | Trivy | a built image, when `SCAN_IMAGE` is set |
| `report:codequality` | — | merges all of the above into one Code Quality report |

### Why Code Quality

Code Quality is the one security-shaped MR widget CE renders. The report job
converts every scanner's output into that format, so findings appear inline on
the diff instead of only in a job log nobody opens. Raw JSON and SARIF stay
available as artifacts for anything that wants to ingest them later.

### Use it

```yaml
include:
  - project: 'john-naeder/ci-templates'
    ref: main
    file: '/security.gitlab-ci.yml'

stages: [scan, report]
```

Until this project exists on your GitLab, vendor the file instead:

```yaml
include:
  - local: '.gitlab/ci/security.yml'
```

### Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `SECURITY_FAIL_ON` | *(empty)* | `blocker` \| `critical` \| `major` \| `minor` \| `info`. Empty means report-only. Secret detection ignores this and always blocks. |
| `SECURITY_SCAN_DISABLED` | *(unset)* | Set to anything to skip every job. |
| `SCAN_IMAGE` | *(unset)* | Image reference for `container:trivy`. |
| `TRIVY_DB_REPOSITORY` | upstream | Point at a Harbor mirror for an air-gapped runner. |
| `TRIVY_IMAGE`, `GITLEAKS_IMAGE`, `SEMGREP_IMAGE`, `PYTHON_IMAGE` | pinned | Bump deliberately. |

Start with `SECURITY_FAIL_ON` empty on an existing codebase. A gate nobody can
turn green is a gate everyone learns to ignore — triage the backlog first, then
tighten to `critical`.

### Runner notes

- The runner needs to pull the scanner images, or have them mirrored in Harbor.
- `GIT_DEPTH: 0` is set because Gitleaks reads history; a shallow clone hides
  almost all of it.
- The Trivy DB cache key is branch-agnostic, so the first job of a pipeline
  pays the download once.
- On the Kubernetes executor, give the scan jobs a memory limit — Semgrep on a
  large repository will use more than the 256Mi a default `[runners.kubernetes]`
  block tends to set.

### A nightly full scan

Advisory databases change; the code does not have to. Add a pipeline schedule
on the default branch (**CI/CD → Schedules**) so new CVEs against unchanged
dependencies still surface. Every job already has a
`$CI_PIPELINE_SOURCE == "schedule"` rule.

## Editing the converter

`scripts/to-codequality.py` is the source of truth. It is embedded into the
`.codequality_converter` block of `security.gitlab-ci.yml` because `include:`
brings YAML, not files. After changing it:

```bash
python3 scripts/sync-template.py
```

You can run it locally against any scanner output in the current directory:

```bash
trivy fs --scanners vuln,secret,misconfig --format json --output trivy-fs.json .
semgrep scan --config auto --json --output semgrep.json
gitleaks detect --source . --report-format json --report-path gitleaks.json --exit-code 0
SECURITY_FAIL_ON=critical python3 scripts/to-codequality.py
```
