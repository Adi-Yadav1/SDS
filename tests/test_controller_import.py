import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
CTRL = ROOT / "controller" / "sdn_controller.py"


def test_controller_imports_and_has_handlers():
    from controller import sdn_controller as sc
    from os_ken.base import app_manager
    assert issubclass(sc.SdnController, app_manager.OSKenApp)
    for name in ("_features_handler", "_state_change", "_packet_in", "_flow_stats_reply"):
        assert hasattr(sc.SdnController, name)
    assert sc.ofproto_v1_3.OFP_VERSION in sc.SdnController.OFP_VERSIONS


def test_derive_features():
    from controller.sdn_controller import derive_features
    f = derive_features(SimpleNamespace(duration_sec=2, duration_nsec=500_000_000,
                                        packet_count=10, byte_count=5000))
    assert f == {"dur": 2.5, "pkts": 10, "bytes": 5000, "pkts_per_s": 4.0,
                 "bytes_per_s": 2000.0, "mean_pkt_size": 500.0}
    z = derive_features(SimpleNamespace(duration_sec=0, duration_nsec=0, packet_count=0, byte_count=0))
    assert z["pkts_per_s"] == 0.0 and z["mean_pkt_size"] == 0.0


class _RecDp:
    """Records flow-mods the controller sends (stands in for a datapath)."""
    def __init__(self):
        from os_ken.ofproto import ofproto_v1_3 as ofp, ofproto_v1_3_parser as parser
        self.id, self.ofproto, self.ofproto_parser, self.sent = 1, ofp, parser, []
    def send_msg(self, m):
        self.sent.append(m)


def _stat(prio, m, sec, pkts, byts):
    return SimpleNamespace(priority=prio, match=SimpleNamespace(items=lambda: m.items()),
                           duration_sec=sec, duration_nsec=0, packet_count=pkts, byte_count=byts)


def _app(tmp_path, model=None):
    from controller import sdn_controller as sc
    app = object.__new__(sc.SdnController)
    app._init_state(tmp_path, model)
    app.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    return app


def _ip(src, dst, proto=6):
    return {"in_port": 1, "eth_type": 2048, "ipv4_src": src, "ipv4_dst": dst, "ip_proto": proto}


def test_flow_stats_logging(tmp_path):
    """JSONL written, table-miss skipped, non-IP flows unclassified, low-rate IP flow = normal, no drop."""
    app = _app(tmp_path)
    dp = _RecDp()
    app._log_flow_stats(1, [_stat(0, {}, 3, 6, 600),
                            _stat(1, {"eth_src": "00:00:00:00:00:02", "eth_type": 2054}, 3, 2, 120),
                            _stat(1, _ip("10.0.0.1", "10.0.0.2"), 3, 30, 6000)], dp)
    rows = [json.loads(l) for l in app.flow_log_path.read_text().splitlines()]
    assert len(rows) == 2
    assert rows[0]["classification"] is None and rows[0]["mitigation"] is None
    c = rows[1]["classification"]
    assert rows[1]["match"]["ipv4_src"] == "10.0.0.1" and rows[1]["features"]["pkts_per_s"] == 10.0
    assert c["is_attack"] is False and c["attack_prob"] is None and c["interval_pps"] == 10.0
    assert c["unsw_features"]["proto"] == "tcp" and c["unsw_features"]["smean"] == 200
    assert rows[1]["mitigation"] is None and dp.sent == []


def test_rate_rule_triggers_drop_rule_once(tmp_path):
    from controller import sdn_controller as sc
    app = _app(tmp_path)
    dp = _RecDp()
    app._log_flow_stats(1, [_stat(1, _ip("10.0.0.1", "10.0.0.3"), 2, 100, 20000)], dp)   # 50 pps: ok
    assert dp.sent == []
    app.prev[(1, "10.0.0.1", "10.0.0.3", 6)] = (time.time() - 5, 100, 20000)
    app._log_flow_stats(1, [_stat(1, _ip("10.0.0.1", "10.0.0.3"), 7, 20100, 28_020_000)], dp)  # ~4000 pps
    assert len(dp.sent) == 1
    fm = dp.sent[0]
    assert fm.priority == sc.PRIO_DROP and fm.instructions == [] and fm.hard_timeout == sc.BLOCK_SECONDS
    assert dict(fm.match.items())["ipv4_src"] == "10.0.0.1" and dict(fm.match.items())["ipv4_dst"] == "10.0.0.3"
    rows = [json.loads(l) for l in app.flow_log_path.read_text().splitlines()]
    assert rows[-1]["classification"]["rate_alert"] and rows[-1]["mitigation"]["status"] == "installed"
    mit = [json.loads(l) for l in app.mitigation_log_path.read_text().splitlines()]
    assert len(mit) == 1 and mit[0]["reasons"] == ["rate"]
    # next poll: not re-installed; the drop rule itself is reported, not classified
    app._log_flow_stats(1, [_stat(1, _ip("10.0.0.1", "10.0.0.3"), 12, 40100, 56_020_000),
                            _stat(100, {"eth_type": 2048, "ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.3"},
                                  5, 0, 0)], dp)
    assert len(dp.sent) == 1
    rows = [json.loads(l) for l in app.flow_log_path.read_text().splitlines()]
    assert rows[-2]["mitigation"]["status"] == "already_blocked"
    assert rows[-1]["classification"]["reasons"] == ["active_drop_rule"]


def test_ml_alert_is_logged_but_not_enforced_by_default(tmp_path):
    class High:
        def predict_proba(self, X):
            import numpy as np
            return np.array([[0.05, 0.95]])
    app = _app(tmp_path, High())
    dp = _RecDp()
    app._log_flow_stats(1, [_stat(1, _ip("10.0.0.2", "10.0.0.1"), 3, 21, 1386)], dp)
    c = json.loads(app.flow_log_path.read_text().splitlines()[0])["classification"]
    assert c["ml_alert"] and c["is_attack"] and not c["enforce"] and dp.sent == []


def test_ml_alert_and_reverse_flow_pairing(tmp_path, monkeypatch):
    """With SDN_ML_BLOCK on, a model scoring >= threshold blocks on its own; reverse flow fills dpkts/dbytes."""
    from controller import sdn_controller as sc
    monkeypatch.setattr(sc, "ML_BLOCK", True)
    class Always:
        def predict_proba(self, X):
            assert list(X.columns) == __import__("ml.live_features", fromlist=["x"]).LIVE_FEATURES
            assert X.iloc[0]["dpkts"] == 40 or X.iloc[0]["spkts"] == 40
            import numpy as np
            return np.array([[0.05, 0.95]])
    app = _app(tmp_path, Always())
    dp = _RecDp()
    app._log_flow_stats(1, [_stat(1, _ip("10.0.0.1", "10.0.0.2"), 10, 50, 9000),
                            _stat(1, _ip("10.0.0.2", "10.0.0.1"), 10, 40, 3000)], dp)
    rows = [json.loads(l) for l in app.flow_log_path.read_text().splitlines()]
    c = rows[0]["classification"]
    assert c["ml_alert"] and not c["rate_alert"] and c["reasons"] == ["ml"]
    assert c["unsw_features"]["dpkts"] == 40 and c["unsw_features"]["dbytes"] == 3000
    assert len(dp.sent) == 2  # both directions flagged by the (fake) model


def test_live_model_loads_and_scores():
    from controller import sdn_controller as sc
    if not sc.LIVE_MODEL.exists():
        pytest.skip("results/live_model.joblib not built (python -m ml.train_live)")
    model = sc.load_live_model(sc.LIVE_MODEL)
    assert model is not None
    from ml.live_features import unsw_features, LIVE_FEATURES
    import pandas as pd
    p = model.predict_proba(pd.DataFrame([unsw_features(6, 5, 50, 9000, 5, 40, 3000)])[LIVE_FEATURES])
    assert p.shape == (1, 2) and 0 <= p[0, 1] <= 1
    assert sc.load_live_model("/nonexistent/model.joblib") is None


def test_unsw_features_definitions():
    from ml.live_features import unsw_features
    f = unsw_features(6, 2.0, 11, 2200, 1.5, 10, 1000)
    assert f["proto"] == "tcp" and f["dur"] == 2.0
    assert f["rate"] == (11 + 10 - 1) / 2.0 and f["sload"] == 2200 * 8 / 2.0
    assert f["smean"] == 200 and f["dmean"] == 100
    z = unsw_features(99, 0, 0, 0)
    assert z["proto"] == "unas" and z["rate"] == 0.0 and z["smean"] == 0


@pytest.mark.skipif(shutil.which("osken-manager") is None and not (Path(sys.executable).parent / "osken-manager").exists(),
                    reason="osken-manager not found")
def test_real_openflow_handshake_with_fake_switch(tmp_path):
    """Starts the real controller under osken-manager and plays a minimal OF1.3 switch against it.
    Verifies: handshake, features request, table-miss flow-mod, packet-in -> packet-out,
    and periodic OFPFlowStatsRequest. (Not Mininet/OVS.)"""
    from os_ken.ofproto import ofproto_v1_3 as ofp, ofproto_v1_3_parser as parser
    from os_ken.ofproto import ofproto_parser
    from os_ken.lib.packet import packet, ethernet, ipv4, icmp

    port = 16653
    mgr = str(Path(sys.executable).parent / "osken-manager")
    env = dict(os.environ, SDN_LOG_DIR=str(tmp_path), SDN_POLL_INTERVAL="1")
    proc = subprocess.Popen([mgr, "--ofp-tcp-listen-port", str(port), str(CTRL)], env=env,
                            stdout=open(tmp_path / "ctrl.log", "wb"), stderr=subprocess.STDOUT)

    class FakeDp:
        id, ofproto, ofproto_parser = 1, ofp, parser
        xid = 0
        def set_xid(self, m):
            FakeDp.xid += 1; m.set_xid(FakeDp.xid)

    dp = FakeDp()
    def send(sock, m):
        m.serialize(); sock.sendall(m.buf)

    def recv_msg(sock):
        hdr = b""
        while len(hdr) < 8:
            c = sock.recv(8 - len(hdr)); assert c, "connection closed"; hdr += c
        version, typ, length, xid = ofproto_parser.header(hdr)
        body = b""
        while len(body) < length - 8:
            body += sock.recv(length - 8 - len(body))
        return typ, SimpleNamespace(xid=xid, body=body)  # controller->switch: header + raw body is enough

    try:
        sock = None
        for _ in range(50):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=3); break
            except OSError:
                time.sleep(0.2)
        assert sock, "controller did not open OpenFlow port"
        send(sock, parser.OFPHello(dp))
        seen, features_sent, pkt_sent, flowstats_seen = set(), False, False, False
        deadline = time.time() + 15
        while time.time() < deadline and (not {ofp.OFPT_FLOW_MOD, ofp.OFPT_PACKET_OUT} <= seen or not flowstats_seen):
            typ, msg = recv_msg(sock)
            seen.add(typ)
            if typ == ofp.OFPT_FEATURES_REQUEST and not features_sent:
                buf = struct.pack("!BBHI", ofp.OFP_VERSION, ofp.OFPT_FEATURES_REPLY, 32, msg.xid) + \
                        struct.pack("!QIBB2xII", 1, 0, 1, 0, 0, 0)
                sock.sendall(buf); features_sent = True
            if typ == ofp.OFPT_MULTIPART_REQUEST:
                mp_type = struct.unpack("!H", msg.body[:2])[0]
                if mp_type == ofp.OFPMP_PORT_DESC:  # controller asks for ports before MAIN mode
                    sock.sendall(struct.pack("!BBHIHH4x", ofp.OFP_VERSION, ofp.OFPT_MULTIPART_REPLY, 16,
                                             msg.xid, ofp.OFPMP_PORT_DESC, 0))
                elif mp_type == ofp.OFPMP_FLOW:
                    flowstats_seen = True
            if typ == ofp.OFPT_FLOW_MOD and not pkt_sent:
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(dst="00:00:00:00:00:02", src="00:00:00:00:00:01", ethertype=0x0800))
                pkt.add_protocol(ipv4.ipv4(src="10.0.0.1", dst="10.0.0.2", proto=1))
                pkt.add_protocol(icmp.icmp(data=icmp.echo()))
                pkt.serialize()
                mbuf = bytearray(); mlen = parser.OFPMatch(in_port=1).serialize(mbuf, 0)
                body = struct.pack("!IHBBQ", ofp.OFP_NO_BUFFER, len(pkt.data), ofp.OFPR_NO_MATCH, 0, 0) \
                       + bytes(mbuf[:mlen]) + b"\x00\x00" + bytes(pkt.data)
                sock.sendall(struct.pack("!BBHI", ofp.OFP_VERSION, ofp.OFPT_PACKET_IN, 8 + len(body), 99) + body)
                pkt_sent = True
        assert ofp.OFPT_FEATURES_REQUEST in seen or features_sent
        assert ofp.OFPT_FLOW_MOD in seen, "no table-miss flow-mod received"
        assert ofp.OFPT_PACKET_OUT in seen, "no packet-out after packet-in"
        assert flowstats_seen, "no OFPMP_FLOW stats request sent after datapath registered"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
