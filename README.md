# SDN-ML Attack Detection

Detecting and blocking attacks in a software-defined network (SDN) with machine learning.

1. **Full ML model** (`ml/`): Random Forest on the processed UNSW-NB15 dataset (40 features, 10 classes).
   79.9% accuracy, F1 0.909 for attack vs normal on a leak-free held-out split.
2. **Live model** (`ml/train_live.py`): binary attack/normal Random Forest on only the 11 UNSW features that can be
   computed from OpenFlow flow counters. AUC 0.974, F1 0.897 on the same held-out split.
3. **SDN controller** (`controller/`, `topology/`, `traffic/`): OS-Ken OpenFlow 1.3 controller on a Mininet network. Every
   5 s it reads flow statistics, scores each IPv4 flow with the live model and a packet-rate rule, and installs an OpenFlow
   **drop rule** (60 s) for flagged source→destination pairs.

**Verified on a real Mininet/Open vSwitch run** (`logs/mininet_run2_final/`): a burst flow (~1,200 packets/s) was
detected and blocked after 6.1 s (h1→h3 100% ping loss afterwards), and normal traffic was never blocked.

> Honest caveat: the live model is trained on UNSW-NB15, not Mininet traffic. Live, it scored normal TCP up to 0.91 and
> the burst only 0.50, so ML alerts are logged only and the **rate rule** installs the drop rules (`SDN_ML_BLOCK=1` lets
> the ML block too). Details: `EVALUATION_GUIDE.md` §10 and §13, and the report in `report/`.

---

## How to run this project

### 1. Requirements

- **Linux** (tested on Ubuntu). Mininet does not run on Windows or macOS directly — use a Linux VM there.
- **Python 3.12 or newer** (tested with 3.14).
- **Mininet and Open vSwitch** (system packages):

  ```bash
  sudo apt update
  sudo apt install mininet openvswitch-switch
  ```

- `sudo` access (Mininet needs root to create virtual hosts and links).

### 2. Get the code and install Python packages

```bash
git clone git@github.com:Adi-Yadav1/SDS.git
cd SDS
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Both trained models are already in `results/`, so **you can skip straight to step 5** to run the live SDN demo.
Steps 3–4 are only needed to retrain the models or run the dataset-based tests.

### 3. (Optional) Get the dataset

The UNSW-NB15 CSV is not in the repo (see `data/README.md` for the expected columns). Point the project at it:

```bash
export UNSW_PROCESSED_CSV=/path/to/unsw_processed.csv
```

### 4. (Optional) Train and evaluate the models

```bash
.venv/bin/python -m ml.train          # full 40-feature model   (~20 s) -> results/model.joblib, metrics.json
.venv/bin/python -m ml.evaluate       # re-checks the saved model against metrics.json
.venv/bin/python -m ml.train_live     # live 11-feature model   (~15 s) -> results/live_model.joblib
.venv/bin/python -m ml.predict --limit 10   # predictions on held-out dataset rows
.venv/bin/python -m ml.demo                 # 2 sample flows per class, true vs predicted
```

### 5. Run the tests

```bash
.venv/bin/python -m pytest -q tests
```

Expected: `16 passed` with the dataset available, or `9 passed, 7 skipped` without it (the skipped tests need the CSV).

### 6. Run the live SDN demo (detection + blocking)

Open **three terminals** in the project folder.

**Terminal 1 — start the controller** (leave it running):

```bash
.venv/bin/osken-manager controller/sdn_controller.py
```

Wait for `Live model loaded: ...` and `SdnController started ...`.

**Terminal 2 — start the Mininet network** (Mininet uses the system Python, not the venv):

```bash
sudo /usr/bin/python3 topology/mininet_topology.py --auto
```

`--auto` builds 3 hosts + 1 switch, runs `pingAll`, sends normal traffic h1→h2, then a high-rate burst h1→h3, checks
that h1→h3 is blocked and h1→h2 still works, prints the switch flow table, and exits (~40 s).
Without `--auto` you get the interactive Mininet CLI (e.g. `h1 ping h2`, `exit` to quit).

**Terminal 3 — watch the decisions** (optional):

```bash
tail -f logs/mitigations.jsonl      # one line per drop rule installed
tail -f logs/flow_stats.jsonl       # every flow, its ML score and rate, every 5 s
```

### 7. What you should see

- Terminal 1: lines like `10.0.0.1 ->10.0.0.2 ... p_attack=0.66 pps=9.0 -> normal`, then when the burst starts
  `MITIGATION: drop 10.0.0.1 -> 10.0.0.3 for 60s (reasons=rate, ...)`.
- Terminal 2: `pingAll packet loss: 0.0%`, the burst client reports `connection stalled/blocked`,
  `ping 10.0.0.3` → **100% packet loss**, `ping 10.0.0.2` → **0% packet loss**, and the flow table contains
  `priority=100,ip,nw_src=10.0.0.1,nw_dst=10.0.0.3 actions=drop`.

Stop the controller with `Ctrl-C` when done.

### 8. Controller settings (optional)

Set as environment variables before starting the controller, e.g. `SDN_MITIGATION=0 .venv/bin/osken-manager controller/sdn_controller.py`.

| Variable | Default | Meaning |
|---|---|---|
| `SDN_MITIGATION` | `1` | `0` = detect and log only, never install drop rules |
| `SDN_ML_BLOCK` | `0` | `1` = ML alerts also install drop rules (off by default, see caveat above) |
| `SDN_ML_THRESHOLD` | `0.9` | ML attack probability that raises an alert |
| `SDN_RATE_PPS` | `500` | packets/s (since last poll) that trigger the rate rule |
| `SDN_RATE_BPS` | `1000000` | bytes/s that trigger the rate rule |
| `SDN_MIN_PKTS` | `10` | flows with fewer packets are never flagged |
| `SDN_BLOCK_SECONDS` | `60` | how long a drop rule lasts |
| `SDN_POLL_INTERVAL` | `5` | seconds between flow-statistics polls |

### 9. Troubleshooting

| Problem | Fix |
|---|---|
| Mininet complains about existing interfaces / crashed earlier | `sudo mn -c` (cleans up Mininet/OVS leftovers only) |
| `Address already in use` on port 6653 | Another controller is running: stop it, or `pkill -f osken-manager` |
| `Mininet needs root` | Run the topology script with `sudo` |
| `ModuleNotFoundError: mininet` | Use `/usr/bin/python3` (system Python) for the topology, not `.venv/bin/python` |
| `Live model NOT loaded` in the controller | Run `.venv/bin/python -m ml.train_live` (needs the dataset) or restore `results/live_model.joblib` from git |
| `.venv` broken after a system Python upgrade | `rm -rf .venv` and repeat step 2 |
| `EventletDeprecationWarning` | Harmless warning from OS-Ken's dependency; ignore |

---

## Project structure

```
controller/sdn_controller.py   OS-Ken controller: learning switch, flow stats, detection, drop rules
topology/mininet_topology.py   3-host / 1-switch Mininet lab (--auto runs the full demo)
traffic/generate_traffic.py    safe TCP traffic generator (private addresses only)
ml/common.py                   dataset loading, de-duplication, stratified split
ml/train.py, ml/evaluate.py    full 40-feature model
ml/live_features.py            OpenFlow counters -> 11 UNSW features
ml/train_live.py               live 11-feature model
ml/predict.py, ml/demo.py      dataset-based predictions
tests/                         16 automated tests
results/                       trained models, metrics, confusion matrix
logs/mininet_run*/             logs from the real Mininet runs
report/                        project report (.docx, .pdf) and presentation (.pptx)
EVALUATION_GUIDE.md            detailed design, results and limitations
```
