import asyncio
import base64
import collections
import ctypes
import io
import json
import logging
import os
import socket
import sys
import threading
import time
import psutil
import pydivert
import flet as ft
from PIL import Image, ImageDraw
from icoextract import IconExtractor
from info import NAME, VERSION, ICON, ASSETS, CONFIG


def make_icon():
    os.makedirs(ASSETS, exist_ok=True)
    path = os.path.join(ASSETS, ICON)
    if os.path.exists(path):
        return
    img = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((8, 8, 248, 248), radius=56, fill=(24, 90, 219, 255))
    d.rectangle((70, 50, 100, 140), fill=(255, 255, 255, 255))
    d.polygon([(50, 140), (120, 140), (85, 200)], fill=(255, 255, 255, 255))
    d.rectangle((156, 116, 186, 206), fill=(120, 230, 160, 255))
    d.polygon([(136, 116), (206, 116), (171, 56)], fill=(120, 230, 160, 255))
    img.save(path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])

logging.getLogger("icoextract").setLevel(logging.ERROR)
icons = {}
rules = {}
buckets = {}
stats = collections.defaultdict(lambda: [0, 0])
net = {"ports": {}}
info = {"err": ""}
gate = {"h": None}
lock = threading.Lock()
MB = 1000000
FILTER = "(tcp or udp) and !loopback"
ACT_W = [250, 95, 95, 150, 70]
RULE_W = [250, 120, 120, 70]
CONN_W = [200, 170, 170, 90]

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate():
    if os.name != "nt" or is_admin():
        return
    args = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, os.getcwd(), 1)
    sys.exit()

def fmt(b):
    return f"{b / MB:.2f}\u00a0MB/s" if b >= MB else f"{b / 1000:.0f}\u00a0KB/s"

def lf(v):
    return f"{v:g}\u00a0MB/s" if v >= 1 else f"{v * 1000:.0f}\u00a0KB/s"

def num(v):
    try:
        return max(float(v), 0.0)
    except (TypeError, ValueError):
        return 0.0

def new_rule():
    return {"down_on": False, "down": 0.0, "up_on": False, "up": 0.0, "blocked": False}

def lim(r, key):
    return lf(r[key]) if r[key + "_on"] and r[key] > 0 else "-"

def is_active(r):
    return bool(r) and (r["blocked"] or (r["down_on"] and r["down"] > 0) or (r["up_on"] and r["up"] > 0))

def keep(r):
    return r["blocked"] or r["down_on"] or r["up_on"] or r["down"] > 0 or r["up"] > 0

def load_rules():
    try:
        with open(CONFIG, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    for n, r in data.items():
        if isinstance(r, dict):
            rules[n] = {**new_rule(), **{k: r[k] for k in new_rule() if k in r}}

def save_rules():
    try:
        if not rules:
            if os.path.exists(CONFIG):
                os.remove(CONFIG)
            os.rmdir(os.path.dirname(CONFIG))
            return
        os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2)
    except OSError:
        pass

def addr(a):
    return f"{a.ip}:{a.port}" if a else "-"

def load_icon(exe):
    try:
        buf = io.BytesIO()
        Image.open(IconExtractor(exe).get_icon()).convert("RGBA").resize((24, 24)).save(buf, "PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None

def app_icon(name, size=22):
    src = icons.get(name)
    return ft.Image(src=src, width=size, height=size) if src else ft.Icon(ft.Icons.APPS, size=size)

def owner(p):
    out = p.is_outbound
    return net["ports"].get(("tcp" if p.tcp else "udp", p.src_port if out else p.dst_port)), out

def allow(name, key, size):
    r = rules.get(name)
    if not is_active(r):
        return True
    if r["blocked"]:
        return False
    if not r[key + "_on"] or r[key] <= 0:
        return True
    rate = r[key] * MB
    now = time.monotonic()
    b = buckets.setdefault((name, key), [rate, now])
    b[0] = min(b[0] + (now - b[1]) * rate, max(rate * 0.25, 65535))
    b[1] = now
    if b[0] < size:
        return False
    b[0] -= size
    return True

def run_limiter(h):
    try:
        for p in h:
            name, out = owner(p)
            if not name or allow(name, "up" if out else "down", len(p.raw)):
                h.send(p)
    except Exception:
        pass

def sync_limiter():
    want = any(is_active(r) for r in rules.values())
    if want and not gate["h"]:
        try:
            h = pydivert.WinDivert(FILTER, priority=100)
            h.open()
            gate["h"] = h
            threading.Thread(target=run_limiter, args=(h,), daemon=True).start()
        except Exception as e:
            info["err"] = f"Limiter unavailable: {e}"
    if not want and gate["h"]:
        h = gate["h"]
        gate["h"] = None
        try:
            h.close()
        except Exception:
            pass

def sniff():
    try:
        with pydivert.WinDivert(FILTER, priority=-100, flags=pydivert.Flag.SNIFF) as w:
            for p in w:
                name, out = owner(p)
                if name:
                    with lock:
                        stats[name][1 if out else 0] += len(p.raw)
    except Exception as e:
        info["err"] = f"Packet driver unavailable: {e}"

def scan():
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.Error:
        conns = []
    counts = collections.Counter(c.pid for c in conns if c.pid and c.status == psutil.CONN_ESTABLISHED)
    apps = {}
    pids = {}
    for p in psutil.process_iter(["pid", "name", "exe"]):
        i = p.info
        n = i["name"] or "Unknown"
        pids[i["pid"]] = n
        a = apps.setdefault(n, {"pid": i["pid"], "n": 0})
        a["n"] += counts.get(i["pid"], 0)
        if n not in icons:
            icons[n] = load_icon(i["exe"]) if i["exe"] else None
    net["ports"] = {("tcp" if c.type == socket.SOCK_STREAM else "udp", c.laddr.port): pids.get(c.pid) for c in conns if c.pid and c.laddr}
    return apps, pids, conns

def table(cols, sort=None):
    return ft.DataTable(columns=[ft.DataColumn(ft.Text(c, no_wrap=True), on_sort=sort) for c in cols], rows=[], show_checkbox_column=False, heading_row_height=40, data_row_min_height=40, data_row_max_height=40, column_spacing=12, horizontal_margin=8)

def scroller(t):
    return ft.Column([ft.Row([t], scroll=ft.ScrollMode.AUTO)], scroll=ft.ScrollMode.AUTO, expand=True)

def cell(v, w):
    return ft.Text(str(v), width=w, no_wrap=True, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS)

def row(values, name, selected, pick, widths):
    first = ft.DataCell(ft.Row([app_icon(name), cell(values[0], widths[0] - 30)], spacing=8))
    cells = [first] + [ft.DataCell(cell(v, w)) for v, w in zip(values[1:], widths[1:])]
    return ft.DataRow(cells=cells, selected=selected, on_select_change=lambda e, n=name: pick(n))

async def main(page: ft.Page):
    page.title = f"{NAME} {VERSION}"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.window.width = 1180
    page.window.height = 800
    page.window.min_width = 1100
    page.window.icon = ICON
    await page.window.center()
    load_rules()
    sync_limiter()
    threading.Thread(target=sniff, daemon=True).start()
    state = {"sel": None, "apps": {}, "pids": {}, "conns": [], "rates": {}, "down": 0.0, "up": 0.0, "last": psutil.net_io_counters(), "t": time.monotonic(), "col": 1, "asc": False}
    down_text = ft.Text("0\u00a0KB/s", size=18, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN_400, no_wrap=True)
    up_text = ft.Text("0\u00a0KB/s", size=18, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_400, no_wrap=True)
    warn = ft.Text("", color=ft.Colors.RED_300, size=12)
    search = ft.TextField(hint_text="Filter applications", prefix_icon=ft.Icons.SEARCH, width=240, height=40, content_padding=8, on_change=lambda e: refresh())
    active = ft.Switch(label="Active only", value=False, on_change=lambda e: refresh())

    def sort(e):
        state["col"] = e.column_index
        state["asc"] = e.ascending
        activity_t.sort_column_index = e.column_index
        activity_t.sort_ascending = e.ascending
        refresh()

    activity_t = table(["Application", "Download", "Upload", "Limits", "Status"], sort)
    activity_t.sort_column_index = 1
    activity_t.sort_ascending = False
    rules_t = table(["Application", "Down Limit", "Up Limit", "Blocked"])
    conns_t = table(["Process", "Local", "Remote", "Status"])
    views = [scroller(activity_t), scroller(rules_t), scroller(conns_t)]
    content = ft.Container(content=views[0], expand=True, bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.WHITE), border_radius=8, padding=8)
    p_icon = ft.Container(width=40, height=40)
    p_name = ft.Text("", size=16, weight=ft.FontWeight.BOLD, no_wrap=True, expand=True, overflow=ft.TextOverflow.ELLIPSIS)
    p_info = ft.Text("", size=12, color=ft.Colors.GREY_400)
    p_down = ft.Text("0\u00a0KB/s", color=ft.Colors.GREEN_400, no_wrap=True)
    p_up = ft.Text("0\u00a0KB/s", color=ft.Colors.BLUE_400, no_wrap=True)

    def commit(e=None):
        sel = state["sel"]
        if not sel:
            return
        d_field.disabled = not d_switch.value
        u_field.disabled = not u_switch.value
        r = {"down_on": d_switch.value, "down": num(d_field.value), "up_on": u_switch.value, "up": num(u_field.value), "blocked": block.value}
        buckets.clear()
        if keep(r):
            rules[sel] = r
        else:
            rules.pop(sel, None)
        save_rules()
        sync_limiter()
        refresh()

    d_switch = ft.Switch(label="Limit download", value=False, on_change=commit)
    u_switch = ft.Switch(label="Limit upload", value=False, on_change=commit)
    d_field = ft.TextField(label="Download limit (MB/s)", value="0", dense=True, disabled=True, on_change=commit)
    u_field = ft.TextField(label="Upload limit (MB/s)", value="0", dense=True, disabled=True, on_change=commit)
    block = ft.Switch(label="Block all traffic", value=False, on_change=commit)
    speeds = ft.Row([ft.Icon(ft.Icons.ARROW_DOWNWARD, size=16, color=ft.Colors.GREEN_400), p_down, ft.Icon(ft.Icons.ARROW_UPWARD, size=16, color=ft.Colors.BLUE_400), p_up], spacing=6, wrap=True)
    body = ft.Column([ft.Row([p_icon, p_name], spacing=10), p_info, ft.Divider(), speeds, ft.Divider(), d_switch, d_field, u_switch, u_field, ft.Divider(), block, ft.OutlinedButton("Reset", icon=ft.Icons.RESTART_ALT, on_click=lambda e: reset(e))], spacing=10, visible=False)
    hint = ft.Text("Select an application to configure its limits", color=ft.Colors.GREY_500)
    panel = ft.Container(ft.Column([ft.Text("Properties", size=14, weight=ft.FontWeight.BOLD), hint, body], spacing=12, scroll=ft.ScrollMode.AUTO), width=280, padding=16)

    def status(name):
        r = rules.get(name)
        if r and r["blocked"]:
            return "Blocked"
        return "Limited" if is_active(r) else "Allowed"

    def limits(name):
        r = rules.get(name)
        if not is_active(r) or r["blocked"]:
            return "-"
        return " ".join(f"{a}{lim(r, k)}" for a, k in (("\u2193", "down"), ("\u2191", "up")) if lim(r, k) != "-")

    def load_rule(name):
        r = rules.get(name, new_rule())
        d_switch.value = r["down_on"]
        u_switch.value = r["up_on"]
        d_field.value = f"{r['down']:g}"
        u_field.value = f"{r['up']:g}"
        d_field.disabled = not r["down_on"]
        u_field.disabled = not r["up_on"]
        block.value = r["blocked"]

    def select(name):
        state["sel"] = None if state["sel"] == name else name
        sel = state["sel"]
        body.visible = sel is not None
        hint.visible = sel is None
        p_name.value = sel or ""
        p_icon.content = app_icon(sel, 36) if sel else None
        load_rule(sel)
        refresh()

    def reset(e):
        rules.pop(state["sel"], None)
        buckets.clear()
        load_rule(None)
        save_rules()
        sync_limiter()
        refresh()

    def refresh():
        apps = state["apps"]
        rates = state["rates"]
        q = (search.value or "").lower()
        items = []
        for n, a in apps.items():
            d, u = rates.get(n, (0.0, 0.0))
            if q in n.lower() and (d or u or a["n"] or not active.value):
                r = rules.get(n)
                items.append((n, [n.lower(), d, u, (r["down"] if r and r["down_on"] else 0) + (r["up"] if r and r["up_on"] else 0), status(n)]))
        items.sort(key=lambda x: x[1][0])
        items.sort(key=lambda x: x[1][state["col"]], reverse=not state["asc"])
        down_text.value = fmt(state["down"])
        up_text.value = fmt(state["up"])
        warn.value = info["err"]
        activity_t.rows = [row([n, fmt(v[1]), fmt(v[2]), limits(n), v[4]], n, n == state["sel"], select, ACT_W) for n, v in items]
        rules_t.rows = [row([n, lim(r, "down"), lim(r, "up"), "Yes" if r["blocked"] else "No"], n, n == state["sel"], select, RULE_W) for n, r in rules.items()]
        named = [(state["pids"].get(c.pid, "Unknown"), c) for c in state["conns"] if c.pid]
        shown = [(n, c) for n, c in named if not state["sel"] or n == state["sel"]][:200]
        conns_t.rows = [row([n, addr(c.laddr), addr(c.raddr), c.status], n, n == state["sel"], select, CONN_W) for n, c in shown]
        sel = state["sel"]
        if sel:
            a = apps.get(sel, {"pid": "-", "n": 0})
            d, u = rates.get(sel, (0.0, 0.0))
            p_info.value = f"PID {a['pid']}  |  {a['n']} connections  |  {status(sel)}"
            p_down.value = fmt(d)
            p_up.value = fmt(u)
        page.update()

    def nav(e):
        content.content = views[e.control.selected_index]
        refresh()

    rail = ft.NavigationRail(selected_index=0, label_type=ft.NavigationRailLabelType.ALL, min_width=84, trailing=ft.Text(f"v{VERSION}", size=11, color=ft.Colors.GREY_500), destinations=[ft.NavigationRailDestination(icon=ft.Icons.SPEED, label="Activity"), ft.NavigationRailDestination(icon=ft.Icons.RULE, label="Rules"), ft.NavigationRailDestination(icon=ft.Icons.LAN, label="Connections")], on_change=nav)
    header = ft.Row([ft.Icon(ft.Icons.ARROW_DOWNWARD, color=ft.Colors.GREEN_400), down_text, ft.Icon(ft.Icons.ARROW_UPWARD, color=ft.Colors.BLUE_400), up_text, warn], spacing=12)
    toolbar = ft.Row([search, active], wrap=True)
    page.add(ft.Row([rail, ft.VerticalDivider(width=1), ft.Container(ft.Column([header, toolbar, content], expand=True, spacing=12), padding=12, expand=True), ft.VerticalDivider(width=1), panel], expand=True))

    async def scanner():
        while True:
            state["apps"], state["pids"], state["conns"] = await asyncio.to_thread(scan)
            await asyncio.sleep(1)

    async def tick():
        while True:
            await asyncio.sleep(0.5)
            c = psutil.net_io_counters()
            now = time.monotonic()
            dt = max(now - state["t"], 0.001)
            state["down"] = (c.bytes_recv - state["last"].bytes_recv) / dt
            state["up"] = (c.bytes_sent - state["last"].bytes_sent) / dt
            state["last"] = c
            state["t"] = now
            with lock:
                snap = {k: tuple(v) for k, v in stats.items()}
                stats.clear()
            old = state["rates"]
            new = {}
            for k in set(old) | set(snap):
                od, ou = old.get(k, (0.0, 0.0))
                d, u = snap.get(k, (0, 0))
                nd = 0.4 * od + 0.6 * d / dt
                nu = 0.4 * ou + 0.6 * u / dt
                if nd > 100 or nu > 100:
                    new[k] = (nd, nu)
            state["rates"] = new
            refresh()

    page.run_task(scanner)
    page.run_task(tick)

if __name__ == "__main__":
    elevate()
    make_icon()
    ft.run(main, assets_dir=ASSETS)