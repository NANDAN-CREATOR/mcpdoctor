# Contributing

```bash
git clone https://github.com/NANDAN-CREATOR/mcpdoctor && cd mcpdoctor
pip install -e ".[dev]"
pytest -q          # ~25 s, includes the defect-corpus benchmark
ruff check src tests && mypy src
python scripts/gen_rules_doc.py   # after editing src/mcpdoctor/rules.py
```

## Adding a rule
1. Add the `Rule` to `src/mcpdoctor/rules.py` (id, title, severity, why, fix, CWE/OWASP refs).
2. Implement the check in `lint.py`, `security_static.py` or `probes.py`.
3. Plant the defect in a server under `examples/servers/` and add its id to `EXPECTED` in `tests/test_corpus.py`.
4. Add a **negative** test: a benign input that must *not* trigger the rule. Precision matters more than recall;
   a scanner that cries wolf gets switched off.
5. Regenerate `docs/RULES.md` and add a line to `CHANGELOG.md`.
