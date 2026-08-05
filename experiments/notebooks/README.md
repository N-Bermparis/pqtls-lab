# Analysis notebooks

Notebooks for exploring results from `experiments/results/`.

## Ground rules

1. **Notebooks read; they never write to `experiments/results/`.** Raw records
   are the primary evidence. Anything derived belongs in a separate output
   directory.
2. **Clear all outputs before committing.** Committed cell outputs turn into
   numbers that look like results but were produced by an unknown version of
   the code against unknown data. `jupyter nbconvert --clear-output --inplace`.
3. **A notebook is not a source of truth.** Any figure that ends up in the
   technical report must be reproducible from `scripts/analyze-results.py`
   against the raw JSONL. If a notebook computes something the script cannot,
   move that computation into the script.
4. **Never plot a number that was not measured.** An empty plot is a correct
   representation of an experiment that has not been run.

## Getting started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install jupyterlab pandas matplotlib
jupyter lab
```

Loading raw records:

```python
import json
import pandas as pd
from pathlib import Path

records = [
    json.loads(line)
    for path in Path("../results").glob("baseline-*.jsonl")
    for line in path.read_text().splitlines()
    if line.strip()
]
df = pd.DataFrame(records)

# Always split on what was NEGOTIATED, never on what was requested.
# A row with requested_profile="hybrid-..." and a classical negotiated_group
# is a downgrade that should have been rejected, and it must not be averaged
# into the hybrid figures.
df.groupby(["requested_profile", "negotiated_group"])["handshake_ms"].describe()
```

## Suggested notebooks

| Notebook | Purpose | Research question |
|---|---|---|
| `01-baseline-comparison.ipynb` | Classical vs hybrid handshake distributions | RQ1 |
| `02-network-conditions.ipynb` | Latency, loss and MTU sweeps | RQ2 |
| `03-edge-devices.ipynb` | Desktop vs VM vs Raspberry Pi | RQ3 |
| `04-handshake-sizes.ipynb` | ClientHello sizes from `tools/pcap_metrics.py` | RQ2 |
| `05-authentication-overhead.ipynb` | ECDSA vs ML-DSA certificate and signature sizes | RQ5 |
| `06-resumption.ipynb` | Full vs resumed handshake cost | RQ6 |

None of these exist yet. Add them as the corresponding experiments are run.

## Status

**No analysis notebooks have been committed.** There are no results to analyse
until an experiment has been executed on identified hardware.
