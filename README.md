# SDN-ML Attack Detection

1. **ML** (`ml/`): Random Forest on the processed UNSW-NB15 CSV (10-class attack category, 40 features) — dataset evaluation.
2. **Live model** (`ml/train_live.py`): binary attack/normal Random Forest on only the 11 UNSW features that can be derived
   from OpenFlow flow counters (AUC 0.974, F1 0.897 on held-out data).
3. **SDN** (`controller/`, `topology/`, `traffic/`): OS-Ken OpenFlow 1.3 learning switch on a local Mininet lab that polls
   flow stats, scores each IPv4 flow with the live model + a volumetric rate rule, and installs an OpenFlow **drop rule**
   (60 s) for flagged src->dst pairs.

Honest caveat: the live model is trained on UNSW-NB15, not Mininet traffic; its scores on Mininet flows are poorly
separated, so in the demo the **rate rule** is what blocks the burst flow. See `EVALUATION_GUIDE.md` (§13).

Quick start (from project root):

    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    # dataset is not in the repo: export UNSW_PROCESSED_CSV=/path/to/unsw_processed.csv  (see data/README.md)
    .venv/bin/python -m ml.train && .venv/bin/python -m ml.evaluate   # full model (~20 s)
    .venv/bin/python -m ml.train_live                                   # live model (~15 s)
    .venv/bin/python -m pytest -q tests
    .venv/bin/osken-manager controller/sdn_controller.py                # terminal 1
    sudo /usr/bin/python3 topology/mininet_topology.py --auto           # terminal 2
    tail -f logs/mitigations.jsonl                                      # terminal 3

Trained models are committed: `results/model.joblib` (68 MB) and `results/live_model.joblib` (9 MB).
