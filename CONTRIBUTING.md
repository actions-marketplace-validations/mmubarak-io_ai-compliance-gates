# Contributing

Contributions are welcome, especially new jurisdiction policy packs and
PII recognizers.

## Getting started

Requires **Python 3.11+**.

```bash
pip install -r requirements.txt pytest
pytest tests/ -v
```

The Rego tests need [conftest](https://www.conftest.dev/) on your `PATH`;
they skip automatically if it isn't installed. To run them:

```bash
conftest test --parser hcl2 --combine -p policy infrastructure/modules/ml-platform/*.tf
```

## What we're looking for

- **Policy packs**: Rego rules for other jurisdictions (KSA PDPL, Qatar
  PDPPL, DIFC DP Law). Follow the pattern in `policy/terraform_compliance.rego`:
  every rule tagged with a policy ID and the regulation article it enforces.
- **PII recognizers**: region-specific patterns (national IDs, phone formats,
  IBANs). Add the pattern to `scripts/pii_scanner.py` or contribute it as a
  documented `custom_patterns` example in `templates/compliance.config.yml`,
  with a test either way.
- **Model card schemas**: alternative profiles (e.g. NIST AI RMF, ISO 42001)
  as config files.

## Ground rules

- Every gate change needs a test in `tests/`.
- Every policy rule must cite the regulation it enforces. No rules that
  exist "because it seems secure."
- Sample data must be synthetic. Never commit real personal data, even as a
  test fixture.
- Keep the core dependency-light; heavyweight dependencies (NLP models etc.)
  go behind optional extras.

## The one rule that matters most

**A gate must never report success for a check it did not perform.**

This is the failure mode that makes a compliance toolkit actively harmful:
a green check and an evidence pack asserting compliance for something nobody
looked at. Concretely, when you touch gate logic:

| Situation | Required behaviour |
|-----------|--------------------|
| Nothing matched the target path | exit `2`, unless `--allow-empty` |
| Input unreadable or malformed | treat as a finding, exit `1` |
| Config invalid | exit `2` with a message naming the key |
| Violation found | exit `1` in **every** `--output-format` |

If you add an output format, a discovery path, or an early return, add the
matching regression test. The existing ones are grouped under
`TestPIIScannerExitCodes` and `TestModelCardExitCodes`. Follow the pattern.

New rules also need a negative fixture proving they actually fire. See
`examples/terraform/non_compliant/`, which is deliberately split across two
files so the cross-file rules are exercised.

## Editing the architecture diagram

`docs/architecture.drawio` is the source; `docs/architecture.svg` is what the
README embeds. When you re-export from draw.io:

**File -> Export as -> SVG, and set Text Settings to `SVG`, not `HTML`.**

The HTML setting wraps every label in `<foreignObject>`. It looks correct in a
browser, but GitHub sanitises SVG in markdown and drops those elements, so the
README falls back to the truncated single-line text draw.io emits alongside
them. The diagram then renders as `UAE PDPL...` and loses the regulation
citations that are the point of it.

If your export does contain `<foreignObject>`, you do not need to hunt for the
setting. Run the fixer, which pulls the full text out of each foreignObject and
rewrites it as ordinary `<text>` and `<tspan>` elements:

```bash
python tools/fix_drawio_svg.py docs/architecture.svg
```

It keeps draw.io's `light-dark()` fills, so the diagram still follows GitHub's
dark mode.

`TestArchitectureDiagram` enforces the result: it fails on any
`<foreignObject>`, on clipped labels, and on policy ids the register does not
define. If a label is genuinely too long for its shape, widen the shape in
draw.io rather than letting the exporter clip it.

Exporting as PNG instead also avoids the problem entirely, at the cost of
scalable text and dark-mode adaptation.

## Pull requests

Fork, branch, commit (short and simple messages), open a PR against `main`.
CI must be green. The pipeline dogfoods the toolkit against `examples/`,
in both directions: clean fixtures must pass and dirty ones must be blocked,
so a broken gate blocks your PR by design.

Note whether your change makes a gate **stricter** or **looser**; the PR
template asks, and stricter changes need a `CHANGELOG.md` entry so adopters
know a previously-green build may start failing.

If you touch a gate under `.github/actions/`, change the root
[`action.yml`](action.yml) in the same commit. It is the Marketplace listing
and runs the same engines by re-invoking them, so the two drift apart
otherwise; `TestRootActionParity` fails the build when they do. Releasing and
publishing are maintainer tasks, documented in
[docs/RELEASING.md](docs/RELEASING.md).

## Security

A gate that passes when it should block is a security issue, not a bug.
Report it privately via [SECURITY.md](SECURITY.md).
