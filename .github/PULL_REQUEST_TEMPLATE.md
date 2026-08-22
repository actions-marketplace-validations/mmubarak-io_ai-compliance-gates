## What this changes

<!-- One or two sentences. If it changes gate behaviour, say which gate and in which direction. -->

## Why

<!-- For policy or recognizer changes, cite the regulation provision. -->

## Checklist

- [ ] Tests added or updated in `tests/` (every gate change needs one)
- [ ] Any new policy rule cites the regulation article it enforces
- [ ] Any example data is **synthetic**
- [ ] Core dependencies unchanged, or heavyweight deps kept behind `requirements-nlp.txt`
- [ ] CI is green — the pipeline dogfoods the toolkit against `examples/`

## Gate behaviour

<!-- Delete if not applicable. -->

- [ ] This makes a gate **stricter** (previously-passing input now blocks) — adopters need a changelog note
- [ ] This makes a gate **looser** (previously-blocking input now passes) — explain why the old behaviour was a false positive
