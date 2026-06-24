#!/usr/bin/env python3
"""
Multi-Gateway manager for AimiliVPN.

Manages independent OpenVPN tunnels (tun0, tun1, ...), each representing
a different exit country, with its own proxy port and auto-migration.

Configuration is read from `gateways` key in ui_auth.json:

    {
      "gateways": [
        {"country": "日本", "proxy_port": 7928, "routing_mode": "fixed_region"},
        {"country": "美国", "proxy_port": 7929, "routing_mode": "fixed_region"},
      ]
    }
"""

from __future__ import annotations

import os, sys, time, threading, socket, subprocess, json, signal
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import proxy_server
import vpn_utils

# ── singleton flag ─────────────────────────────────────

_is_multi_gateway = False

def is_active() -> bool:
    """Return True if multi-gateway mode is running."""
    return _is_multi_gateway


# ── types ──────────────────────────────────────────────

GATEWAY_CONFIG_FILE = "ui_auth.json"
CONFIG_DIR_PATH = "configs"

StateFile = Path  # absolute path

# ── helpers reused from original vpngate_manager ───────

# We need to share DATA_DIR, CONFIG_DIR, NODES_FILE, etc.
# These will be set by the caller (vpngate_manager.py) via set_globals().
_data_dir: Path | None = None
_config_dir: Path | None = None
_nodes_file: Path | None = None
_state_file: Path | None = None
_auth_file: Path | None = None
_api_url: str = ""
_openvpn_test_timeout: int = 60


class GatewayState:
    """Runtime state for one gateway tunnel."""

    __slots__ = (
        "name", "country", "proxy_port", "routing_mode",
        "connection_enabled",
        "tun_device", "route_table", "proxy_host",
        "openvpn_process", "openvpn_node_id",
        "is_connecting", "lock",
        "health_ok", "health_ip", "health_latency",
        "stop_event",
    )

    def __init__(self, name: str, country: str, proxy_port: int,
                 proxy_host: str = "127.0.0.1",
                 routing_mode: str = "fixed_region",
                 tun_device: str = "tun0", route_table: int = 100):
        self.name = name
        self.country = country
        self.proxy_port = proxy_port
        self.routing_mode = routing_mode
        self.connection_enabled = True
        self.tun_device = tun_device
        self.route_table = route_table
        self.proxy_host = proxy_host
        self.openvpn_process: subprocess.Popen | None = None
        self.openvpn_node_id: str = ""
        self.is_connecting = False
        self.lock = threading.RLock()
        self.health_ok = False
        self.health_ip = ""
        self.health_latency = 0
        self.stop_event = threading.Event()


# ── gateway index (all tunnels) ────────────────────────

_gateways: list[GatewayState] = []


def set_globals(data_dir: Path, api_url: str, openvpn_test_timeout: int = 60):
    global _data_dir, _config_dir, _nodes_file, _state_file, _auth_file, _api_url, _openvpn_test_timeout
    _data_dir = data_dir
    _config_dir = data_dir / CONFIG_DIR_PATH
    _nodes_file = data_dir / "nodes.json"
    _state_file = data_dir / "state.json"
    _auth_file = data_dir / "vpngate_auth.txt"
    _api_url = api_url
    _openvpn_test_timeout = openvpn_test_timeout


# ── config loading / saving ────────────────────────────

def load_config() -> dict:
    """Load ui_auth.json. Returns empty dict if not found."""
    if _data_dir is None:
        return {}
    path = _data_dir / GATEWAY_CONFIG_FILE
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_config(cfg: dict):
    if _data_dir is None:
        return
    path = _data_dir / GATEWAY_CONFIG_FILE
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def load_gateway_configs() -> list[dict]:
    """Return the `gateways` list from config, with defaults."""
    cfg = load_config()
    gw_list: list[dict] = cfg.get("gateways", [])
    if not gw_list:
        # backward compat: read old-style force_country
        legacy_country = cfg.get("force_country", "日本")
        legacy_port = cfg.get("proxy_port", 7928)
        legacy_mode = cfg.get("routing_mode", "fixed_region")
        legacy_enabled = cfg.get("connection_enabled", True)
        gw_list = [{
            "country": legacy_country,
            "proxy_port": legacy_port,
            "routing_mode": legacy_mode,
            "connection_enabled": legacy_enabled,
        }]
    return gw_list


# ── tun & route management ─────────────────────────────

def _ensure_tun_device(tun_name: str) -> bool:
    """Return True if the tun device already exists."""
    return Path(f"/sys/class/net/{tun_name}").exists()


def setup_policy_routing(interface: str, table: int = 100):
    try:
        subprocess.run(["ip", "rule", "del", "table", str(table)],
                       capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", str(table)],
                       capture_output=True, timeout=2)
    except Exception:
        pass
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", str(table)],
                           check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", str(table)],
                           check=True, timeout=2)
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"],
                                   capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[gw] Policy routing for {interface} (table {table}) OK", flush=True)
            return
        except Exception as e:
            print(f"[gw] Policy routing attempt {attempt} failed: {e}", flush=True)
            time.sleep(1)
    print(f"[ERROR] Failed to set policy routing for {interface}", flush=True)


def cleanup_policy_routing(table: int = 100):
    try:
        subprocess.run(["ip", "rule", "del", "table", str(table)], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", str(table)], capture_output=True, timeout=2)
    except Exception:
        pass


# ── OpenVPN helpers ────────────────────────────────────

def _openvpn_command(config_file: str, dev: str = "tun0") -> list[str]:
    import vpngate_manager as vm
    return vm.openvpn_command(config_file, route_nopull=True, dev=dev)


def _run_openvpn_until_ready(config_file: str, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen | None]:
    import vpngate_manager as vm
    return vm.run_openvpn_until_ready(config_file, keep_alive=True, route_nopull=True, timeout=_openvpn_test_timeout, dev=dev)


def _stop_process(proc: subprocess.Popen | None) -> None:
    import vpngate_manager as vm
    vm.stop_process(proc)


# ── per-gateway operations ─────────────────────────────

def _read_nodes() -> list[dict]:
    if _nodes_file is None:
        return []
    try:
        raw = json.loads(_nodes_file.read_text(encoding="utf-8"))
        return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _write_nodes(nodes: list[dict]):
    if _nodes_file is None:
        return
    _nodes_file.parent.mkdir(parents=True, exist_ok=True)
    _nodes_file.write_text(json.dumps(nodes, indent=2, ensure_ascii=False), encoding="utf-8")


def _apply_routing_filters(candidates: list[dict], gw: GatewayState) -> list[dict]:
    """Filter nodes by country matching gw.country."""
    if not gw.country:
        return candidates
    filtered = []
    for n in candidates:
        n_country = (n.get("country") or "").strip()
        # Try direct match or via translation
        if n_country == gw.country:
            filtered.append(n)
        elif vpn_utils.COUNTRY_TRANSLATIONS.get(gw.country) == n_country:
            filtered.append(n)
        elif vpn_utils.COUNTRY_TRANSLATIONS.get(n_country) == gw.country:
            filtered.append(n)
    return filtered


def _find_best_node(gw: GatewayState) -> dict | None:
    """Pick the best *available* + *inactive* node matching gw.country."""
    nodes = _read_nodes()
    candidates = [
        n for n in nodes
        if n.get("probe_status") == "available"
        and not n.get("active")
    ]
    candidates = _apply_routing_filters(candidates, gw)
    if not candidates:
        # Fallback: also accept nodes where active node is from another tun
        candidates2 = [
            n for n in nodes
            if n.get("probe_status") == "available"
        ]
        candidates2 = _apply_routing_filters(candidates2, gw)
        candidates = candidates2
    if not candidates:
        return None
    candidates.sort(key=lambda n: (
        int(n.get("latency_ms", 999999)) if str(n.get("latency_ms", "")).isdigit() else 999999,
        -int(n.get("score", 0)),
    ))
    return candidates[0]


def connect_gateway_node(gw: GatewayState, node_id: str) -> str:
    """Connect a gateway to a specific node. Raises on failure."""
    with gw.lock:
        if gw.is_connecting:
            raise RuntimeError(f"[{gw.name}] Already connecting, skip")
        gw.is_connecting = True

    try:
        nodes = _read_nodes()
        node = next((n for n in nodes if n.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node {node_id} not found")

        # Stop existing connection for this gateway
        _stop_process(gw.openvpn_process)
        gw.openvpn_process = None
        gw.openvpn_node_id = ""

        config_dir = _config_dir
        if config_dir is None:
            raise RuntimeError("config_dir not set")
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / f"{gw.tun_device}.ovpn"
        try:
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write config: {e}")

        ok, msg, proc = _run_openvpn_until_ready(str(config_path), dev=gw.tun_device)
        if not ok or proc is None:
            if config_path.exists():
                config_path.unlink()
            raise RuntimeError(msg)

        gw.openvpn_process = proc
        gw.openvpn_node_id = node_id

        # Policy routing for this tunnel
        setup_policy_routing(gw.tun_device, gw.route_table)

        # Mark node active
        for n in nodes:
            n["active"] = n.get("id") == node_id
        _write_nodes(nodes)

        print(f"[gw:{gw.name}] Connected {node_id} on {gw.tun_device} port {gw.proxy_port}", flush=True)
        return f"Connected {node_id}"
    finally:
        with gw.lock:
            gw.is_connecting = False


def auto_switch_gateway(gw: GatewayState, attempt: int = 0) -> None:
    """Auto-migrate this gateway's tunnel to another node (same country)."""
    if not gw.connection_enabled:
        return
    if attempt >= 3:
        print(f"[gw:{gw.name}] Auto-switch failed 3x, giving up", flush=True)
        return

    best = _find_best_node(gw)
    if best:
        nid = best.get("id", "")
        try:
            connect_gateway_node(gw, nid)
        except Exception as e:
            print(f"[gw:{gw.name}] Switch to {nid} failed: {e}", flush=True)
            auto_switch_gateway(gw, attempt + 1)
    else:
        print(f"[gw:{gw.name}] No available {gw.country} nodes, will retry later", flush=True)


def disconnect_gateway(gw: GatewayState):
    """Stop the tunnel and clean up for one gateway."""
    with gw.lock:
        _stop_process(gw.openvpn_process)
        gw.openvpn_process = None
        gw.openvpn_node_id = ""
        gw.is_connecting = False
        cleanup_policy_routing(gw.route_table)

    # Remove config file
    if _config_dir is not None:
        cfg = _config_dir / f"{gw.tun_device}.ovpn"
        if cfg.exists():
            try:
                cfg.unlink()
            except Exception:
                pass


# ── health check ────────────────────────────────────────

def check_gateway_health(gw: GatewayState) -> dict:
    """Check one gateway's proxy is listening + can reach the internet."""
    result = {"ok": False, "ip": "", "latency_ms": 0, "error": ""}

    # 1. port listening?
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", gw.proxy_port))
    except Exception as e:
        result["error"] = f"Port {gw.proxy_port} not listening: {e}"
        return result
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

    # 2. tun device exists?
    if not _ensure_tun_device(gw.tun_device):
        result["error"] = f"{gw.tun_device} not found"
        return result

    # 3. curl via this gateway's proxy to verify egress
    if not _data_dir:
        return result
    try:
        import vpngate_manager as vm
        proxy_url = f"http://127.0.0.1:{gw.proxy_port}"
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", "-x", proxy_url, "https://checkip.amazonaws.com"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and r.stdout:
            try:
                ip = r.stdout.strip().strip('"').strip("'")
                result["ok"] = bool(ip)
                result["ip"] = ip
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)

    return result


def gateway_health_loop(gw: GatewayState, interval: int = 60):
    """Background loop: periodically check health and auto-migrate on failure."""
    # Wait for initial connection to establish before first health check
    gw.stop_event.wait(interval * 0.75)
    
    while not gw.stop_event.is_set():
        health = check_gateway_health(gw)
        gw.health_ok = health["ok"]
        gw.health_ip = health["ip"]
        gw.health_latency = health.get("latency_ms", 0)

        if not health["ok"] and gw.connection_enabled:
            # Only auto-switch if we've previously had a successful connection
            if gw.openvpn_node_id:
                print(f"[gw:{gw.name}] Health check failed: {health.get('error', 'unknown')}, auto-switching...", flush=True)
                threading.Thread(target=auto_switch_gateway, args=(gw, 0), daemon=True).start()
        elif health["ok"]:
            print(f"[gw:{gw.name}] Health OK: {health['ip']}", flush=True)

        gw.stop_event.wait(interval)


# ── bootstrap ──────────────────────────────────────────

def get_available_tun_name(index: int) -> str:
    """Return tunX name. tun2 for index 0 (in case tun0/tun1 taken), tun3 for 1, etc."""
    return f"tun{index + 2}"


def init_gateways(proxy_host: str = "0.0.0.0") -> list[GatewayState]:
    """Parse config, create GatewayState for each, start proxy servers."""
    gw_configs = load_gateway_configs()
    gateways: list[GatewayState] = []

    for i, cfg in enumerate(gw_configs):
        country = cfg.get("country", "日本")
        port = int(cfg.get("proxy_port", 7928 + i))
        tun = get_available_tun_name(i)
        table = 100 + i
        mode = cfg.get("routing_mode", "fixed_region")

        gw = GatewayState(
            name=f"{country}-{port}",
            country=country,
            proxy_port=port,
            proxy_host=proxy_host,
            routing_mode=mode,
            tun_device=tun,
            route_table=table,
        )
        gw.connection_enabled = cfg.get("connection_enabled", True)
        gateways.append(gw)

    _gateways.clear()
    _gateways.extend(gateways)
    return gateways


def start_gateways(proxy_host: str = "0.0.0.0"):
    """Start proxy servers + health loops for all gateways."""
    global _is_multi_gateway
    gws = init_gateways(proxy_host)
    _is_multi_gateway = True  # must be set before threads start

    for gw in gws:
        # Start proxy server on this port, binding to this tun
        t = threading.Thread(
            target=proxy_server.start_proxy_server,
            args=(gw.proxy_host, gw.proxy_port, gw.tun_device),
            daemon=True
        )
        t.start()
        print(f"[gw] Proxy {gw.name} on {gw.proxy_host}:{gw.proxy_port} via {gw.tun_device}", flush=True)

    # Wait for proxy ports to be ready
    time.sleep(2)

    # Start health loops
    for gw in gws:
        t = threading.Thread(target=gateway_health_loop, args=(gw, 60), daemon=True)
        t.start()

    # Initial connection attempt for each gateway (in parallel)
    def _initial_connect(gw: GatewayState):
        try:
            auto_switch_gateway(gw)
        except Exception as e:
            print(f"[gw] Initial connect for {gw.name} failed: {e}", flush=True)

    for gw in gws:
        threading.Thread(target=_initial_connect, args=(gw,), daemon=True).start()


def stop_all():
    """Gracefully stop all gateways."""
    global _is_multi_gateway
    _is_multi_gateway = False
    for gw in _gateways:
        gw.stop_event.set()
        disconnect_gateway(gw)


def gateway_status_list() -> list[dict]:
    """Return serialisable status for all gateways (for API)."""
    return [
        {
            "name": gw.name,
            "country": gw.country,
            "proxy_port": gw.proxy_port,
            "tun_device": gw.tun_device,
            "route_table": gw.route_table,
            "node_id": gw.openvpn_node_id,
            "is_connecting": gw.is_connecting,
            "connection_enabled": gw.connection_enabled,
            "health_ok": gw.health_ok,
            "health_ip": gw.health_ip,
            "health_latency": gw.health_latency,
        }
        for gw in _gateways
    ]