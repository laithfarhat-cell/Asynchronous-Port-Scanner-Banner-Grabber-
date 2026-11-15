# `reports/` — scan output (git-ignored)

This directory is where `asynscan` writes its findings. **Its contents are not
committed**: a report is a point-in-time snapshot of a real network and may
contain hostnames, banners, certificate details and internal IP addresses.

Only this README is tracked, so the directory exists in a fresh clone and the
default output paths work without any manual setup.

## Generating a report

```bash
asynscan -t 192.168.1.0/24 --top-ports 100 -oA reports/lan      # lan.{json,csv,html}
python3 scripts/demo_lab.py                                     # demo.{json,csv,html}
```

`-oA PREFIX` writes all three formats; `-oJ/-oC/-oH` write a single one.

## Committed samples (safe to share)

Runnable examples that are reviewed and tracked live in [`../examples/`](../examples):

| File | Content |
|---|---|
| `examples/demo_report.json` | JSON schema v1, produced by the loopback demo lab |
| `examples/demo_report.csv` | the same findings as flat CSV |
| `examples/demo_report.html` | the same findings as a standalone HTML report |

These are what the preview console falls back to, and what the test suite uses
on a clean checkout.

## Publishing a report deliberately

Because the directory is ignored, Git needs an explicit override:

```bash
git add -f reports/engagement-2026-11.json
```

Before you do that, confirm the report contains nothing sensitive (third-party
IP addresses, client hostnames, certificate subject names). Prefer sharing a
redacted export over the raw file.
