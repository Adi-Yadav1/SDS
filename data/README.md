# Data

The dataset is **not copied** into this project. Default path:

    /home/aditya_yadav/Data/Sem 7/SAD/data/processed/unsw_processed.csv

Override with `export UNSW_PROCESSED_CSV=/path/to/file.csv` or `--data` (train/predict).
The file is only ever read, never modified.

Schema (257,673 rows x 47 cols, no missing values): UNSW-NB15 training+testing partitions merged.
- Inputs used (40): `dur, proto, service, state, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload,
  sloss, dloss, sinpkt, dinpkt, sjit, djit, swin, dwin, tcprtt, synack, ackdat, smean, dmean, trans_depth,
  response_body_len, ct_*, is_ftp_login, ct_ftp_cmd, ct_flw_http_mthd, is_sm_ips_ports`
- Target: `attack_cat` (10 classes: Normal, Generic, Exploits, Fuzzers, DoS, Reconnaissance, Analysis, Backdoor, Shellcode, Worms)
- Excluded to prevent leakage / noise: `id, label, label_binary, attack_cat, dataset_name` (labels/identifiers/source marker),
  `stcpb, dtcpb` (random TCP initial sequence numbers).
- Raw, unscaled values; `proto/service/state` are strings (one-hot encoded inside the saved pipeline).
