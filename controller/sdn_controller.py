"""OS-Ken (3.0.2) OpenFlow 1.3 controller: learning switch + flow telemetry + live detection + mitigation.

Every POLL_INTERVAL seconds it requests flow stats from each switch and, for every IPv4 flow:
  1. pairs it with its reverse flow and derives the 11 UNSW-NB15 features that OpenFlow counters
     allow (ml/live_features.py),
  2. scores it with the reduced live model (results/live_model.joblib, from `python -m ml.train_live`),
  3. applies a volumetric rate rule on the counters' delta since the previous poll,
  4. if flagged (and mitigation is enabled) installs a high-priority DROP rule for that
     src->dst IPv4 pair with a hard timeout, and logs the action.

Detection policy (honest): the live model was trained on UNSW-NB15, not on Mininet traffic, and
its scores on Mininet flows are not well separated (domain shift, see EVALUATION_GUIDE.md §13;
normal ACK flows reached 0.92 on the real run). So ML alerts (score >= SDN_ML_THRESHOLD) are
logged but only the rate rule installs drop rules, unless SDN_ML_BLOCK=1. Every record says
which signal fired and whether it was enforced.

Run:  osken-manager controller/sdn_controller.py
Env:  SDN_LOG_DIR, SDN_POLL_INTERVAL (5), SDN_LIVE_MODEL, SDN_MITIGATION (1), SDN_ML_THRESHOLD (0.9), SDN_ML_BLOCK (0),
      SDN_RATE_PPS (500), SDN_RATE_BPS (1000000), SDN_MIN_PKTS (10), SDN_BLOCK_SECONDS (60)
"""
import json
import os
import sys
import time
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ether_types, ipv4, packet
from os_ken.ofproto import ofproto_v1_3

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # osken-manager loads this file by path; make `ml` importable
    sys.path.insert(0, str(ROOT))
from ml.live_features import LIVE_FEATURES, unsw_features  # noqa: E402

LOG_DIR = Path(os.environ.get("SDN_LOG_DIR", ROOT / "logs"))
POLL_INTERVAL = float(os.environ.get("SDN_POLL_INTERVAL", "5"))
LIVE_MODEL = Path(os.environ.get("SDN_LIVE_MODEL", ROOT / "results" / "live_model.joblib"))
MITIGATION = os.environ.get("SDN_MITIGATION", "1") not in ("0", "false", "no", "")
ML_THRESHOLD = float(os.environ.get("SDN_ML_THRESHOLD", "0.9"))
# ML alerts are logged always; they only install drop rules if SDN_ML_BLOCK=1 (off by default:
# on the real Mininet run normal ACK flows scored up to 0.92 -> false-positive blocks).
ML_BLOCK = os.environ.get("SDN_ML_BLOCK", "0") not in ("0", "false", "no", "")
RATE_PPS = float(os.environ.get("SDN_RATE_PPS", "500"))
RATE_BPS = float(os.environ.get("SDN_RATE_BPS", "1000000"))  # bytes/s (= 8 Mbit/s)
MIN_PKTS = int(os.environ.get("SDN_MIN_PKTS", "10"))
BLOCK_SECONDS = int(os.environ.get("SDN_BLOCK_SECONDS", "60"))
FLOW_LOG = "flow_stats.jsonl"
MITIGATION_LOG = "mitigations.jsonl"
IDLE_TIMEOUT = 30
PRIO_FORWARD = 1
PRIO_DROP = 100


def derive_features(stat):
    """Flow-level features that can genuinely be derived from one OpenFlow flow-stats entry."""
    dur = stat.duration_sec + stat.duration_nsec / 1e9
    pkts, byts = stat.packet_count, stat.byte_count
    return {
        "dur": round(dur, 6),
        "pkts": pkts,
        "bytes": byts,
        "pkts_per_s": round(pkts / dur, 3) if dur > 0 else 0.0,
        "bytes_per_s": round(byts / dur, 3) if dur > 0 else 0.0,
        "mean_pkt_size": round(byts / pkts, 2) if pkts else 0.0,
    }


def load_live_model(path, logger=None):
    """Return the saved live pipeline, or None (controller then runs rate-rule only)."""
    try:
        import joblib
        bundle = joblib.load(path)
        if list(bundle["features"]) != LIVE_FEATURES:
            raise ValueError("live model feature list does not match ml/live_features.py")
        if logger:
            logger.info("Live model loaded: %s", path)
        return bundle["pipeline"]
    except Exception as e:  # missing file, version mismatch, ...
        if logger:
            logger.warning("Live model NOT loaded (%s): %s -- run `python -m ml.train_live`; "
                           "using rate rule only", path, e)
        return None


class SdnController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._init_state(LOG_DIR, load_live_model(LIVE_MODEL, self.logger))
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("SdnController started; poll=%ss mitigation=%s ml_threshold=%.2f ml_block=%s "
                         "rate_pps=%s rate_Bps=%s block=%ss, logs in %s", POLL_INTERVAL, MITIGATION,
                         ML_THRESHOLD, ML_BLOCK, RATE_PPS, RATE_BPS, BLOCK_SECONDS, LOG_DIR)

    def _init_state(self, log_dir, model):
        self.mac_to_port = {}
        self.flow_log_path = Path(log_dir) / FLOW_LOG
        self.mitigation_log_path = Path(log_dir) / MITIGATION_LOG
        self.model = model
        self.prev = {}      # (dpid, src, dst, proto) -> (timestamp, pkts, bytes) at previous poll
        self.blocked = {}   # (dpid, src, dst) -> expiry timestamp

    # ---- switch lifecycle ----
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features_handler(self, ev):
        dp = ev.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)  # table-miss -> controller
        self.logger.info("Switch features received: dpid=%016x", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.info("Datapath registered: dpid=%016x", dp.id)
                self.datapaths[dp.id] = dp
        elif dp.id in self.datapaths:
            self.logger.info("Datapath disconnected: dpid=%016x", dp.id)
            del self.datapaths[dp.id]
            self.mac_to_port.pop(dp.id, None)

    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst,
                                      idle_timeout=idle, hard_timeout=hard))

    # ---- L2 learning switch (IPv4 flows are IP-granular for telemetry) ----
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        try:
            self._handle_packet_in(ev)
        except Exception:
            self.logger.exception("Error handling packet-in")

    def _handle_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_type=0x0800,
                                        ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
            else:
                # eth_type is included so e.g. an ARP-reply flow cannot swallow IPv4 traffic
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src,
                                        eth_type=eth.ethertype)
            self._add_flow(dp, PRIO_FORWARD, match, actions, idle=IDLE_TIMEOUT)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    # ---- flow statistics ----
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                try:
                    dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
                except Exception:
                    self.logger.exception("Stats request failed for dpid=%016x", dp.id)
            hub.sleep(POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        try:
            self._log_flow_stats(ev.msg.datapath.id, ev.msg.body, ev.msg.datapath)
        except Exception:
            self.logger.exception("Error processing flow stats reply")

    # ---- detection ----
    def _score(self, feats):
        if self.model is None:
            return None
        import pandas as pd
        return float(self.model.predict_proba(pd.DataFrame([feats])[LIVE_FEATURES])[0, 1])

    def _classify(self, dpid, key, ts, stat, ip_flows):
        """key = (src, dst, proto). Returns the classification dict for one IPv4 flow."""
        src, dst, proto = key
        rev = ip_flows.get((dst, src, proto))
        feats = unsw_features(proto, stat["dur"], stat["pkts"], stat["bytes"],
                              *(rev["dur"], rev["pkts"], rev["bytes"]) if rev else (0.0, 0, 0))
        prob = self._score(feats)

        pk = (dpid, src, dst, proto)
        prev = self.prev.get(pk)
        if prev and ts > prev[0] and stat["pkts"] >= prev[1]:
            dt = ts - prev[0]
            pps, bps = (stat["pkts"] - prev[1]) / dt, (stat["bytes"] - prev[2]) / dt
        else:  # first sighting (or counters reset): lifetime average
            d = stat["dur"] or 1e-9
            pps, bps = stat["pkts"] / d, stat["bytes"] / d
        self.prev[pk] = (ts, stat["pkts"], stat["bytes"])

        enough = stat["pkts"] >= MIN_PKTS
        ml_alert = bool(prob is not None and enough and prob >= ML_THRESHOLD)
        rate_alert = bool(enough and (pps >= RATE_PPS or bps >= RATE_BPS))
        reasons = [r for r, on in (("ml", ml_alert), ("rate", rate_alert)) if on]
        enforce = rate_alert or (ml_alert and ML_BLOCK)
        return {
            "model": "live_rf" if prob is not None else None,
            "attack_prob": None if prob is None else round(prob, 4),
            "ml_threshold": ML_THRESHOLD, "ml_alert": ml_alert,
            "interval_pps": round(pps, 2), "interval_Bps": round(bps, 1), "rate_alert": rate_alert,
            "is_attack": bool(reasons), "reasons": reasons, "enforce": bool(enforce),
            "unsw_features": {k: (round(v, 3) if isinstance(v, float) else v) for k, v in feats.items()},
        }

    def _mitigate(self, dp, dpid, src, dst, cls, ts):
        if not MITIGATION or dp is None:
            return None
        self.blocked = {k: v for k, v in self.blocked.items() if v > ts}
        if (dpid, src, dst) in self.blocked:
            return {"action": "drop", "status": "already_blocked", "until": self.blocked[(dpid, src, dst)]}
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src, ipv4_dst=dst)
        self._add_flow(dp, PRIO_DROP, match, [], hard=BLOCK_SECONDS)  # no actions = drop
        self.blocked[(dpid, src, dst)] = ts + BLOCK_SECONDS
        action = {"action": "drop", "status": "installed", "match": {"ipv4_src": src, "ipv4_dst": dst},
                  "priority": PRIO_DROP, "hard_timeout_s": BLOCK_SECONDS, "reasons": cls["reasons"]}
        with open(self.mitigation_log_path, "a") as f:
            f.write(json.dumps({"timestamp": ts, "dpid": dpid, **action,
                                "attack_prob": cls["attack_prob"], "interval_pps": cls["interval_pps"],
                                "interval_Bps": cls["interval_Bps"]}) + "\n")
        self.logger.warning("MITIGATION: drop %s -> %s for %ss (reasons=%s, p=%s, pps=%.0f, Bps=%.0f)",
                            src, dst, BLOCK_SECONDS, ",".join(cls["reasons"]), cls["attack_prob"],
                            cls["interval_pps"], cls["interval_Bps"])
        return action

    def _log_flow_stats(self, dpid, body, dp=None):
        ts = time.time()
        entries, ip_flows = [], {}
        for stat in body:
            if stat.priority == 0:  # table-miss entry
                continue
            m = {k: str(v) for k, v in dict(stat.match.items()).items()}
            feats = derive_features(stat)
            entries.append((stat.priority, m, feats))
            if stat.priority == PRIO_FORWARD and "ipv4_src" in m and "ip_proto" in m:
                key = (m["ipv4_src"], m["ipv4_dst"], int(m["ip_proto"]))
                agg = ip_flows.setdefault(key, {"dur": 0.0, "pkts": 0, "bytes": 0})
                agg["dur"] = max(agg["dur"], feats["dur"])
                agg["pkts"] += feats["pkts"]
                agg["bytes"] += feats["bytes"]

        records = []
        for prio, m, feats in entries:
            cls = mit = None
            if prio == PRIO_DROP:
                cls = {"is_attack": True, "reasons": ["active_drop_rule"]}
            elif prio == PRIO_FORWARD and "ipv4_src" in m and "ip_proto" in m:
                key = (m["ipv4_src"], m["ipv4_dst"], int(m["ip_proto"]))
                cls = self._classify(dpid, key, ts, ip_flows[key], ip_flows)
                if cls["enforce"]:
                    mit = self._mitigate(dp, dpid, key[0], key[1], cls, ts)
            records.append({
                "timestamp": ts, "time_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
                "dpid": dpid, "priority": prio, "match": m, "features": feats,
                "classification": cls, "mitigation": mit,
            })
        if not records:
            return
        with open(self.flow_log_path, "a") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        self.logger.info("dpid=%016x: logged %d flow(s)", dpid, len(records))
        for r in records:
            ft, c = r["features"], r["classification"] or {}
            tag = ""
            if c.get("reasons") == ["active_drop_rule"]:
                tag = " [DROP RULE]"
            elif "attack_prob" in c or "rate_alert" in c:
                tag = (f" p_attack={c.get('attack_prob')} pps={c.get('interval_pps')}"
                       f" -> {('ATTACK' if c['enforce'] else 'ALERT') + '(' + ','.join(c['reasons']) + ')' if c['is_attack'] else 'normal'}")
            self.logger.info("  %s %s pkts=%d bytes=%d dur=%.1fs%s",
                             r["match"].get("ipv4_src", r["match"].get("eth_src", "?")),
                             "->" + r["match"].get("ipv4_dst", r["match"].get("eth_dst", "?")),
                             ft["pkts"], ft["bytes"], ft["dur"], tag)
