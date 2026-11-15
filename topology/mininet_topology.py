"""Local Mininet lab (controller detects the burst flow and installs a drop rule): 1 OVS switch (OpenFlow 1.3), 3 hosts, remote OS-Ken controller.

Needs root:  sudo /usr/bin/python3 topology/mininet_topology.py [--auto]  (Mininet is installed for system Python, not the venv)
  --auto  run connectivity test + safe traffic, then exit (non-interactive)
Without --auto an interactive Mininet CLI opens.
"""
import argparse
import os
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRAFFIC = ROOT / "traffic" / "generate_traffic.py"  # path contains spaces -> always shlex.quote


def build(ctrl_ip, ctrl_port):
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController

    net = Mininet(switch=OVSSwitch, controller=None, autoSetMacs=True, build=False)
    net.addController("c0", controller=RemoteController, ip=ctrl_ip, port=ctrl_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for i in (1, 2, 3):
        net.addLink(net.addHost(f"h{i}", ip=f"10.0.0.{i}/24"), s1)
    net.build()
    return net


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--controller-port", type=int, default=6653)
    ap.add_argument("--duration", type=int, default=12)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Mininet needs root: sudo /usr/bin/python3 topology/mininet_topology.py")

    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel("info")
    net = build(a.controller_ip, a.controller_port)
    net.start()
    try:
        h1, h2, h3 = net.get("h1", "h2", "h3")
        print("\n*** Connectivity test (pingAll)")
        loss = net.pingAll()
        print(f"*** pingAll packet loss: {loss}%")
        if a.auto:
            py, tr = shlex.quote(sys.executable), shlex.quote(str(TRAFFIC))
            h2.cmd(f"{py} {tr} server --port 5001 --duration {2 * a.duration + 15} &")
            h3.cmd(f"{py} {tr} server --port 5002 --duration {2 * a.duration + 15} &")
            import time; time.sleep(1)
            print("*** (controller polls flow stats every 5s; traffic runs long enough to be logged)")
            print("*** Generating safe local traffic h1 -> h2 (normal) and h1 -> h3 (burst)")
            print(h1.cmd(f"{py} {tr} client --target 10.0.0.2 --port 5001 --mode normal --duration {a.duration}"))
            print(h1.cmd(f"{py} {tr} client --target 10.0.0.3 --port 5002 --mode burst --duration {a.duration}"))
            time.sleep(6)
            print("*** Mitigation check: h1 -> h3 should now be blocked (drop rule), h1 -> h2 still works")
            print(h1.cmd("ping -c 2 -W 1 10.0.0.3"))
            print(h1.cmd("ping -c 2 -W 1 10.0.0.2"))
            print("*** Switch flow table (look for priority=100 ... actions=drop):")
            print(net.get("s1").cmd("ovs-ofctl -O OpenFlow13 dump-flows s1"))
        else:
            print("*** Try: h2 python3 traffic/generate_traffic.py server --port 5001 &   then   h1 python3 traffic/generate_traffic.py client --target 10.0.0.2 --port 5001")
            CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
