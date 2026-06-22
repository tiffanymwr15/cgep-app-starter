Machine-readable control traceability for the Acme Health capstone. Primary framework: **HIPAA Security Rule**.

NIST does not publish an official OSCAL catalog for HIPAA or for [NIST SP 800-66 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final). Per [FRAMEWORKS.md](../FRAMEWORKS.md), this repo provides a **capstone-authored HIPAA catalog** (`catalogs/hipaa-security-rule-catalog.json`) whose metadata cites SP 800-66 as implementation guidance. Component `control-id` values are 164.x safeguards; each `implemented-requirement` carries the full CFR citation in `hipaa-section` / `hipaa-control` props (matching Rego policy metadata).

## Artifacts

| File | Purpose |
|---|---|
| [catalogs/hipaa-security-rule-catalog.json](catalogs/hipaa-security-rule-catalog.json) | HIPAA 164.x catalog (800-66 aligned) |
| [components/acme-health-intake.json](components/acme-health-intake.json) | Governed system implementations |
| [profiles/hipaa-minimum.json](profiles/hipaa-minimum.json) | Control selection profile |

## Evidence

Pipeline bundle from main merge (run [27923873028](https://github.com/tiffanymwr15/cgep-app-starter/actions/runs/27923873028)):

```
s3://acme-health-intake-grc-evidence-vault-f88cc5df/runs/27923873028/evidence-27923873028-bf5834ae793038b3f1379ac9dec8bef02ea878ae.tar.gz
```

Verify chain of custody:

```bash
bash scripts/verify-evidence.sh 27923873028 \
  --vault acme-health-intake-grc-evidence-vault-f88cc5df \
  --profile capstone-deploy-user
```

## Validate

Validate with trestle from the repo root (requires `.trestle/config.ini` and mirrored paths under `component-definitions/` and `profiles/`):

```bash
trestle validate -t catalog -n hipaa-security-rule
trestle validate -t component-definition -n acme-health-intake
trestle validate -t profile -n hipaa-minimum
```

Capture output for submission (sanitized paths, safe to commit):

```bash
trestle validate -t catalog -n hipaa-security-rule 2>&1 | sed 's|.*cgep-app-starter/||' | tee docs/trestle-validate.txt
trestle validate -t component-definition -n acme-health-intake 2>&1 | sed 's|.*cgep-app-starter/||' | tee -a docs/trestle-validate.txt
trestle validate -t profile -n hipaa-minimum 2>&1 | sed 's|.*cgep-app-starter/||' | tee -a docs/trestle-validate.txt
```

The `evidence/` directory is gitignored (may contain local `plan.json` with resource ARNs). Use `docs/trestle-validate.txt` for the grader.
