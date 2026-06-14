#!/usr/bin/env python3
"""
main.py - NSO-like Network Config Manager CLI

Usage examples:
  python main.py device add router1 192.168.1.1 --username admin --password secret
  python main.py device list
  python main.py device remove router1
  python main.py device ping router1

  python main.py config fetch router1
  python main.py config fetch --all
  python main.py config show router1
  python main.py config history router1

  python main.py check-sync router1
  python main.py check-sync --all

  python main.py sync router1
  python main.py sync --all

  python main.py history router1
"""

import sys
import click
from tabulate import tabulate

import db
import sync as sync_engine
import connector


# ── Styling helpers ────────────────────────────────────────────────────────────

def _ok(msg):    click.echo(click.style(f"✔  {msg}", fg="green"))
def _err(msg):   click.echo(click.style(f"✘  {msg}", fg="red"), err=True)
def _warn(msg):  click.echo(click.style(f"⚠  {msg}", fg="yellow"))
def _info(msg):  click.echo(click.style(f"   {msg}", fg="cyan"))

STATUS_COLORS = {
    "in-sync":     "green",
    "out-of-sync": "red",
    "synced":      "green",
    "no-snapshot": "yellow",
    "error":       "red",
}

def _colored_status(status):
    color = STATUS_COLORS.get(status, "white")
    return click.style(status.upper(), fg=color, bold=True)


# ── CLI root ───────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """NSO-like Network Config Manager — manage, fetch, and sync device configs."""
    pass


# ── device commands ────────────────────────────────────────────────────────────

@cli.group()
def device():
    """Manage device inventory."""
    pass


@device.command("add")
@click.argument("name")
@click.argument("host")
@click.option("--port",        default=22,          show_default=True, help="SSH port")
@click.option("--device-type", default="cisco_ios",  show_default=True,
              help="Netmiko device type (cisco_ios, cisco_nxos, juniper_junos, arista_eos, …)")
@click.option("--username",    required=True,  prompt=True)
@click.option("--password",    required=True,  prompt=True, hide_input=True)
@click.option("--secret",      default="",     help="Enable secret (Cisco)")
def device_add(name, host, port, device_type, username, password, secret):
    """Add a device to the inventory."""
    try:
        db.add_device(name, host, port, device_type, username, password, secret)
        _ok(f"Device '{name}' added ({host}:{port}, {device_type})")
    except Exception as exc:
        _err(str(exc))
        sys.exit(1)


@device.command("remove")
@click.argument("name")
@click.confirmation_option(prompt="Remove device and all its snapshots?")
def device_remove(name):
    """Remove a device and all its stored configs."""
    if db.remove_device(name):
        _ok(f"Device '{name}' removed")
    else:
        _err(f"Device '{name}' not found")
        sys.exit(1)


@device.command("list")
def device_list():
    """List all devices in the inventory."""
    rows = db.list_devices()
    if not rows:
        _warn("No devices — use 'device add' to register one")
        return
    table = [
        [r["name"], r["host"], r["port"], r["device_type"], r["username"], r["created_at"]]
        for r in rows
    ]
    click.echo(tabulate(table, headers=["Name", "Host", "Port", "Type", "Username", "Added"],
                        tablefmt="rounded_outline"))


@device.command("ping")
@click.argument("name")
def device_ping(name):
    """Test SSH connectivity to a device."""
    row = db.get_device(name)
    if not row:
        _err(f"Device '{name}' not found")
        sys.exit(1)
    _info(f"Connecting to {row['host']}:{row['port']} …")
    ok, msg = connector.test_connectivity(row)
    if ok:
        _ok(msg)
    else:
        _err(msg)
        sys.exit(1)


# ── config commands ────────────────────────────────────────────────────────────

@cli.group()
def config():
    """Download and inspect device configurations."""
    pass


@config.command("fetch")
@click.argument("name", required=False)
@click.option("--all", "all_devices", is_flag=True, help="Fetch from all devices")
def config_fetch(name, all_devices):
    """Fetch and store the running config from one or all devices."""
    if all_devices:
        results = sync_engine.sync_all()
        for r in results:
            if r["status"] == "synced":
                _ok(f"{r['device']:20s}  {r['message']}")
            else:
                _err(f"{r['device']:20s}  {r['message']}")
    elif name:
        _info(f"Fetching config from '{name}' …")
        r = sync_engine.fetch_config(name)
        if r["status"] == "synced":
            _ok(r["message"])
        else:
            _err(r["message"])
            sys.exit(1)
    else:
        _err("Provide a device NAME or pass --all")
        sys.exit(1)


@config.command("show")
@click.argument("name")
@click.option("--pager/--no-pager", default=True, help="Pipe through pager")
def config_show(name, pager):
    """Print the latest stored config for a device."""
    snap = db.get_latest_snapshot(name)
    if not snap:
        _warn(f"No snapshot for '{name}' — run 'config fetch {name}' first")
        sys.exit(1)
    header = (f"─── {name}  |  fetched {snap['fetched_at']} "
              f"|  {len(snap['config']):,} bytes ───")
    click.echo(click.style(header, fg="cyan"))
    if pager:
        click.echo_via_pager(snap["config"])
    else:
        click.echo(snap["config"])


@config.command("history")
@click.argument("name")
@click.option("--limit", default=10, show_default=True)
def config_history(name, limit):
    """List stored config snapshots for a device."""
    snaps = db.list_snapshots(name, limit)
    if not snaps:
        _warn(f"No snapshots for '{name}'")
        return
    table = [[s["id"], s["fetched_at"], f"{s['bytes']:,} B"] for s in snaps]
    click.echo(tabulate(table, headers=["ID", "Fetched At", "Size"],
                        tablefmt="rounded_outline"))


# ── check-sync ─────────────────────────────────────────────────────────────────

@cli.command("check-sync")
@click.argument("name", required=False)
@click.option("--all", "all_devices", is_flag=True)
@click.option("--diff/--no-diff", default=True, help="Print unified diff if out-of-sync")
def check_sync(name, all_devices, diff):
    """Compare stored config snapshot vs live device config."""
    if all_devices:
        results = sync_engine.check_sync_all()
        table = [[r["device"], _colored_status(r["status"]), r["message"]] for r in results]
        click.echo(tabulate(table, headers=["Device", "Status", "Message"],
                            tablefmt="rounded_outline"))
        # Print diffs for out-of-sync devices
        if diff:
            for r in results:
                if r["status"] == "out-of-sync" and r["diff"]:
                    click.echo(click.style(f"\n── Diff: {r['device']} ──", fg="yellow", bold=True))
                    _print_diff(r["diff"])
    elif name:
        r = sync_engine.check_sync(name)
        click.echo(f"Status: {_colored_status(r['status'])}  —  {r['message']}")
        if diff and r["status"] == "out-of-sync" and r["diff"]:
            _print_diff(r["diff"])
    else:
        _err("Provide a device NAME or pass --all")
        sys.exit(1)


def _print_diff(diff_text):
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            click.echo(click.style(line, fg="green"))
        elif line.startswith("-") and not line.startswith("---"):
            click.echo(click.style(line, fg="red"))
        elif line.startswith("@@"):
            click.echo(click.style(line, fg="cyan"))
        else:
            click.echo(line)


# ── sync ───────────────────────────────────────────────────────────────────────

@cli.command("sync")
@click.argument("name", required=False)
@click.option("--all", "all_devices", is_flag=True)
def sync_cmd(name, all_devices):
    """Fetch live config and update the stored snapshot (marks device in-sync)."""
    if all_devices:
        results = sync_engine.sync_all()
        for r in results:
            if r["status"] == "synced":
                _ok(f"{r['device']:20s}  {r['message']}")
            else:
                _err(f"{r['device']:20s}  {r['message']}")
    elif name:
        _info(f"Syncing '{name}' …")
        r = sync_engine.sync_device(name)
        if r["status"] == "synced":
            _ok(r["message"])
        else:
            _err(r["message"])
            sys.exit(1)
    else:
        _err("Provide a device NAME or pass --all")
        sys.exit(1)


# ── history ────────────────────────────────────────────────────────────────────

@cli.command("history")
@click.argument("name")
@click.option("--limit", default=20, show_default=True)
def history(name, limit):
    """Show sync/check-sync history for a device."""
    rows = db.get_sync_history(name, limit)
    if not rows:
        _warn(f"No history for '{name}'")
        return
    table = [
        [r["id"], r["timestamp"], r["action"],
         click.style(r["status"], fg=STATUS_COLORS.get(r["status"], "white")),
         r["detail"][:60] + ("…" if len(r["detail"]) > 60 else "")]
        for r in rows
    ]
    click.echo(tabulate(table, headers=["ID", "Timestamp", "Action", "Status", "Detail"],
                        tablefmt="rounded_outline"))


# ── entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
