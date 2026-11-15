# Evaluation Guide

## 1. Objective
Demonstrate (a) an ML model that detects/categorises attacks on UNSW-NB15 flow records and (b) an SDN setup
(OS-Ken + Mininet/OVS) that collects flow telemetry, and (c) **live detection + mitigation**: a reduced model
trained only on OpenFlow-derivable UNSW features scores every live flow, a volumetric rate rule runs alongside it,
and flagged src->dst pairs get an OpenFlow DROP rule (see §13). The full 40-feature model is still dataset-only.

## 2. Architecture
```
unsw_processed.csv --> ml/train.py --> results/model.joblib (Pipeline: OneHot + RandomForest)
                                   --> results/metrics.json, confusion_matrix.png
                       ml/predict.py: dataset-based inference with the saved pipeline
unsw_processed.csv --> ml/train_live.py --> results/live_model.joblib (11 OpenFlow-derivable features, binary)

Mininet (h1,h2,h3 -- s1 OVS, OpenFlow 1.3) --OpenFlow:6653--> OS-Ken controller/sdn_controller.py
   traffic/generate_traffic.py                                  learning switch + polls flow stats every 5 s
                                                                pair fwd/rev flows -> UNSW features (ml/live_features.py)
                                                                live_model score + rate rule -> is_attack
                                                                attack -> FlowMod prio 100, no actions (DROP), 60 s
                                                                --> logs/flow_stats.jsonl, logs/mitigations.jsonl
```

## 3. Dataset (see data/README.md)
`/home/aditya_yadav/Data/Sem 7/SAD/data/processed/unsw_processed.csv` — 257,673 rows x 47 cols, no NaNs,
raw/unscaled, 3 categorical columns. Class counts: Normal 93,000; Generic 58,871; Exploits 44,525; Fuzzers 24,246;
DoS 16,353; Reconnaissance 13,987; Analysis 2,677; Backdoor 2,329; Shellcode 1,511; Worms 174 (binary: 93,000 normal / 164,673 attack).
Target = `attack_cat` (multiclass); binary "attack" = predicted class != Normal.
**93,988 rows are duplicates** (ignoring `id`); they are dropped before splitting so copies cannot leak across train/test (→ 162,744 rows).

## 4. ML
RandomForest (100 trees, `class_weight=balanced_subsample`, `min_samples_leaf=2`, seed 42) inside an sklearn Pipeline
(one-hot for proto/service/state, fitted on train only). Stratified 80/20 split → 130,195 train / 32,549 test.
Artifacts: `results/model.joblib` (68 MB), `results/metrics.json`, `results/confusion_matrix.png`.

Held-out test results (actual, from `results/metrics.json`):

| | value |
|---|---|
| Accuracy (10-class) | 0.7985 |
| Macro precision / recall / F1 | 0.566 / 0.599 / 0.570 |
| Binary (attack vs normal): acc / prec / recall / F1 | 0.910 / 0.873 / 0.948 / 0.909 |

| Class | P | R | F1 | support |
|---|---|---|---|---|
| Analysis | 0.02 | 0.05 | 0.03 | 407 |
| Backdoor | 0.05 | 0.13 | 0.07 | 376 |
| DoS | 0.42 | 0.26 | 0.32 | 1100 |
| Exploits | 0.84 | 0.82 | 0.83 | 5487 |
| Fuzzers | 0.60 | 0.73 | 0.66 | 4192 |
| Generic | 0.97 | 0.83 | 0.90 | 1520 |
| Normal | 0.95 | 0.88 | 0.91 | 17144 |
| Reconnaissance | 0.82 | 0.77 | 0.79 | 1998 |
| Shellcode | 0.45 | 0.85 | 0.59 | 291 |
| Worms | 0.53 | 0.68 | 0.60 | 34 |

Analysis, Backdoor and DoS are weak (known to overlap in UNSW-NB15). Accuracy is lower than commonly quoted numbers
because duplicates were removed and the split is random on the merged data.

Commands: `python -m ml.train` · `python -m ml.evaluate` (reloads model, checks it reproduces metrics.json) ·
`python -m ml.predict --limit 10` (predictions on held-out rows: class, confidence, is_attack).

## 5. Run the SDN demo (local lab only)
First build the live model once: `python -m ml.train_live` (~15 s). Without it the controller runs the rate rule only.
Python deps are in the venv; `mininet` and `openvswitch-switch` are apt packages (already installed here).
```
# Terminal 1 (project root, venv active)
.venv/bin/osken-manager controller/sdn_controller.py
# Terminal 2 — Mininet needs root and lives in the SYSTEM python, not the venv
sudo /usr/bin/python3 topology/mininet_topology.py --auto      # pingAll + normal + burst traffic, block check, exits
#   or interactive:  sudo /usr/bin/python3 topology/mininet_topology.py   (CLI: h1 ping h2 ...)
# Terminal 3: watch telemetry
tail -f logs/flow_stats.jsonl      # and: tail -f logs/mitigations.jsonl
```
Tunables (env vars for the controller): `SDN_MITIGATION=0` (detect only), `SDN_ML_THRESHOLD` (0.9),
`SDN_ML_BLOCK=1` (let ML alerts install drop rules; off by default, see §13), `SDN_RATE_PPS` (500),
`SDN_RATE_BPS` (1000000 bytes/s), `SDN_MIN_PKTS` (10), `SDN_BLOCK_SECONDS` (60), `SDN_POLL_INTERVAL` (5).
Safe traffic: `traffic/generate_traffic.py` (TCP "normal" 10 msg/s vs "burst" high-rate load, duration-bounded,
refuses non-private targets). It is a load pattern, not an attack tool.
If Mininet leaves state behind after a crash: `sudo mn -c` (removes only Mininet/OVS leftovers).

## 6. Expected output
Controller terminal: `Live model loaded: .../live_model.joblib`, `Datapath registered: dpid=0000000000000001`, then every 5 s
`logged N flow(s)` and lines like `10.0.0.1 ->10.0.0.2 pkts=.. bytes=.. dur=..s p_attack=0.66 pps=9.0 -> normal`
(`-> ALERT(ml)` = ML alert logged but not enforced; `-> ATTACK(rate)` = drop rule installed).
When the burst (h1 -> h3) starts: `MITIGATION: drop 10.0.0.1 -> 10.0.0.3 for 60s (reasons=rate, ...)`; later polls show
the `[DROP RULE]` entry. Mininet output: the burst client reports `connection stalled/blocked`, `h1 ping 10.0.0.3` ->
100% loss, `h1 ping 10.0.0.2` -> 0% loss, and `dump-flows` shows `priority=100,ip,nw_src=10.0.0.1,nw_dst=10.0.0.3 actions=drop`.
`logs/flow_stats.jsonl`: one JSON per flow: timestamp, dpid, priority, match, features {dur, pkts, bytes, pkts_per_s,
bytes_per_s, mean_pkt_size}, `classification` {attack_prob, ml_alert, interval_pps, interval_Bps, rate_alert, is_attack,
reasons, enforce, unsw_features} for IPv4 flows (null for ARP etc.), `mitigation` (null, or the installed/already_blocked drop action).
`logs/mitigations.jsonl`: one line per installed drop rule.

## 7. Shutdown
Ctrl-C the controller; Mininet exits itself (`--auto`) or `exit` in its CLI; `sudo mn -c` if needed.

## 8. Feature mapping (why the full model is not used live)
OpenFlow flow stats give, per direction: duration, packet count, byte count (+ match fields). From these one can derive
`dur, spkts/sbytes (or dpkts/dbytes from the reverse flow), rate, sload, smean`. The model needs 40 features including
`sttl, swin, tcprtt, synack, sjit, sinpkt, ct_*` (connection-window counters), `service`, `state`, `trans_depth`... that
OpenFlow counters do not provide. Feeding partial/zero-filled vectors would give meaningless predictions, so the full
model is never used live. Instead a **reduced model** is trained on exactly the derivable columns (§13).

## 9. Known limitations
- Live ML uses the reduced 11-feature model, trained on UNSW-NB15 only. Its scores on Mininet traffic are not well
  separated (domain shift, §13): on the real run normal TCP scored up to 0.91 and the burst only 0.50. So ML alerts are
  logged but **only the rate rule installs drop rules** by default; the burst is stopped by the rate rule.
- The rate rule also blocks the reverse (ACK) direction of a burst, since ~1200 ACKs/s exceed 500 pps.
- Mitigation is a coarse src->dst IPv4 drop with a 60 s hard timeout (no rate-limiting, no per-port granularity, no allow-list).
- A flow entry aggregates all connections between two hosts for one IP protocol, unlike one UNSW row per connection.
- Weak per-class results for Analysis/Backdoor/DoS.
- Mininet/OVS run needs `sudo`; see §10 for what was and was not executed.
- OS-Ken 3.0.2 pulls in deprecated eventlet (a warning is printed; harmless).

## 10. What was tested
Executed here (`python -m pytest -q tests` → 16 passed): dataset schema/NaN/target checks, leak-free feature set,
reproducible disjoint stratified split, small train → joblib reload → predict consistency, missing-feature and
missing-file errors, saved-model metrics match metrics.json; controller import/handlers, feature derivation, JSONL logging;
and a **real `osken-manager` process against a scripted fake OpenFlow 1.3 switch** (handshake, table-miss flow-mod,
packet-in→packet-out, periodic flow-stats request); live-feature definitions; fwd/rev pairing; ML alert; rate rule →
exactly one priority-100 drop FlowMod with hard timeout, `already_blocked` on later polls, mitigation log; live model
load/score and missing-model fallback; the controller logs `Live model loaded` under `osken-manager`.
**Real Mininet/OVS runs (all in `logs/`):**
- `mininet_run0_telemetry_only/` — 2026-10-15, controller before detection (telemetry only).
- `mininet_run1_ml_block/` — 2026-11-15, detection with ML allowed to block. The burst was blocked by the rate rule
  (1,672 pkts/s, 2.45 MB/s, ML p=0.57), **but the ML also blocked a normal flow**: the reverse ACK flow 10.0.0.2->10.0.0.1
  scored 0.92 (a false positive). This led to the change to make ML alert-only by default.
- `mininet_run2_final/` — 2026-11-15, final controller (`mininet_run2_output.txt` is the Mininet terminal output):
  pingAll 0% loss; normal h1->h2 sent all 120 messages, never blocked (one ML alert at p=0.91, logged only);
  burst h1->h3 detected at 1,197 pkts/s / 1.75 MB/s (ML p=0.50) and blocked after 6.1 s; afterwards
  `ping 10.0.0.3` 100% loss, `ping 10.0.0.2` 0% loss; `dump-flows` shows
  `priority=100,ip,nw_src=10.0.0.1,nw_dst=10.0.0.3 actions=drop` (hard_timeout=60) and its reverse.

## 11. Presentation script
1. **SDN** separates the control plane (controller) from the data plane (switches); the controller programs flow rules
   via OpenFlow, and can read per-flow counters.
2. **UNSW-NB15** is a labelled network-intrusion dataset with flow records for Normal traffic and 9 attack types.
3. **Processed dataset**: I reuse an already-cleaned CSV (257k flows, 40 usable features); I drop label/ID columns and
   duplicates to prevent leakage.
4. **Training**: Random Forest with one-hot encoding, class weighting for imbalance, stratified 80/20 split.
5. **Evaluation**: on held-out data — 79.9% 10-class accuracy, 0.57 macro-F1, and 0.909 F1 for attack-vs-normal;
   weak on Analysis/Backdoor/DoS.
6. **OS-Ken** runs a learning switch and polls flow stats every 5 s, logging duration/packets/bytes/rates to JSONL.
7. **Mininet** builds a 3-host, 1-switch lab connected to the controller; safe local traffic shows normal vs. high-rate flows.
8. **Integration**: OpenFlow exposes only 11 of the UNSW features, so a reduced model is trained on exactly those
   (AUC 0.974, F1 0.897 on the held-out split). The controller pairs each flow with its reverse flow, scores it, and also
   applies a rate rule on per-interval packet/byte rates.
9. **Mitigation**: a flagged src->dst pair gets an OpenFlow drop rule (priority 100, 60 s). Real Mininet run: burst
   detected at ~1,200 pkts/s and blocked after 6 s; h1->h3 then 100% loss, h1->h2 unaffected.
10. **Honesty**: the model is trained on UNSW, not Mininet. Live, it scored normal TCP up to 0.91 and the burst 0.50, and when
   allowed to block it caused a false positive. So ML is alert-only and the rate rule enforces. Next step: label
   Mininet-captured flows and fine-tune/calibrate the model on them.

## 12. Showing the ML classification during the demo
The full 40-feature model classifies **dataset flows only** (replay); live flows use the reduced model (§13).
`python -m ml.demo` — takes 2 held-out flows per class, prints true vs predicted class, confidence and ATTACK/normal,
and appends records to `logs/detections.jsonl` (`source: dataset_replay`, `mitigation: null`).
Note: this sample is class-balanced, so it over-represents weak classes (Analysis/Backdoor) and scores lower than the
full held-out accuracy (79.9%). For a natural distribution use `python -m ml.predict --limit 15`; for real numbers use `results/metrics.json`.

## 13. Live detection and mitigation (reduced model)
**Features** (`ml/live_features.py`): `proto, dur, spkts, dpkts, sbytes, dbytes, rate, sload, dload, smean, dmean`.
From OpenFlow: forward flow A->B gives `spkts/sbytes`, the reverse flow B->A (same ip_proto) gives `dpkts/dbytes`,
`dur` = max of both; `rate=(spkts+dpkts-1)/dur`, `sload=sbytes*8/dur`, `smean=sbytes//spkts` — the definitions were
checked against the CSV. Differences: OpenFlow counts Ethernet frame bytes and one entry aggregates all connections
between two hosts (per IP proto) during its lifetime.

**Model** (`python -m ml.train_live` → `results/live_model.joblib`, `results/live_metrics.json`): Random Forest
(100 trees, max_depth 20, balanced class weights), binary attack vs normal, same de-duplicated stratified split as §4.

| held-out (32,549 rows) | threshold 0.5 | threshold 0.8 |
|---|---|---|
| accuracy | 0.900 | 0.852 |
| precision | 0.876 | 0.982 |
| recall | 0.918 | 0.699 |
| F1 | 0.897 | 0.817 |

ROC-AUC 0.974. Fraction flagged as attack per true category @0.5: Analysis 0.81, Backdoor 0.99, DoS 0.97, Exploits 0.98, Fuzzers 0.77, Generic 0.99, Normal 0.12, Reconnaissance 1.00, Shellcode 0.84, Worms 0.94.
With only 11 counter features it is nearly as good at attack-vs-normal as the 40-feature model (F1 0.909), but it
does not identify the attack type.

**Decision per IPv4 flow** (each poll): `ml_alert` = attack_prob >= 0.9; `rate_alert` = packets/s >= 500 or bytes/s >= 1,000,000,
computed from the counter delta since the previous poll; both require >= 10 packets. `is_attack = ml_alert or rate_alert`
(logged); `enforce = rate_alert or (ml_alert and SDN_ML_BLOCK=1)` (drop rule).
If mitigation is on: FlowMod `priority=100, match(eth_type=IPv4, ipv4_src, ipv4_dst), no instructions` (drop),
`hard_timeout=60`, installed once per pair until it expires.

**Domain shift (measured on the real Mininet run, `logs/mininet_run2_final/flow_stats.jsonl`):**

| live flow | ML attack_prob range |
|---|---|
| ICMP pings (all pairs) | 0.60 – 0.68 |
| normal TCP h1->h2 | 0.61 – 0.91 |
| normal TCP reverse (ACKs) h2->h1 | 0.06 – 0.68 (0.92 in run 1 → false-positive block) |
| burst TCP h1->h3 | 0.50 – 0.62 |
| burst reverse (ACKs) h3->h1 | 0.16 – 0.29 |

The model does not separate Mininet normal and burst traffic (the normal flow even scores higher), so it is used for
alerting only, and the rate rule (burst ~1,200–1,700 pkts/s vs normal ~10 pkts/s) does the mitigation. Fixing this needs
labelled Mininet captures for calibration/fine-tuning.
