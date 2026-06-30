"""
cisco_ios_xe.py — NED for Cisco IOS / IOS-XE devices

NED ID:   cisco-ios-cli-1.0
Protocol: CLI (SSH via Netmiko)
Covers:   CSR1000v, Catalyst 9k, ASR1k, ISR, IOS-XE
"""

import re
from typing import Optional
from .base import BaseDriver, _infer_spec, _schema_to_yaml, _valid_ip, _IP_RE  # noqa: F401


class CiscoIOSXEDriver(BaseDriver):

    # ── NED Identity ─────────────────────────────────────────────────────
    NED_ID = "cisco-ios-cli-1.0"
    NED_VERSION = "1.0"
    PROTOCOL = "cli"

    CAPABILITIES = (
        "rollback",
        "commit-queue",
        "live-status",
        "check-sync",
        "config-backup",
        "interface-list",
    )

    # ── Netmiko ───────────────────────────────────────────────────────────
    NETMIKO_DEVICE_TYPE = "cisco_ios"

    # ── Config commands ───────────────────────────────────────────────────
    COMMANDS = {
        "config_backup": ["show running-config"],
    }

    # ── Live-status (operational) commands ────────────────────────────────
    LIVE_STATUS_COMMANDS = {
        "interfaces":    ["show interfaces"],
        "ip_brief":      ["show ip interface brief"],
        "routes":        ["show ip route"],
        "bgp":           ["show bgp summary"],
        "arp":           ["show arp"],
        "cdp":           ["show cdp neighbors detail"],
        "version":       ["show version"],
        "cpu":           ["show processes cpu sorted"],
        "memory":        ["show processes memory sorted"],
        "spanning_tree": ["show spanning-tree summary"],
        "vlans":         ["show vlan brief"],
        "mac_table":     ["show mac address-table"],
        "ntp":           ["show ntp status", "show ntp associations"],
        "crypto":        ["show crypto isakmp sa", "show crypto ipsec sa"],
    }

    # ── Connectivity ──────────────────────────────────────────────────────

    def test_command(self) -> str:
        return "show version"

    def save_config_command(self) -> Optional[str]:
        return "write memory"

    def parse_version(self, raw_output: str) -> str:
        for line in raw_output.splitlines():
            if "Cisco IOS" in line or "IOS-XE" in line:
                return line.strip()
        return raw_output.strip().splitlines()[0] if raw_output.strip() else "Connected"

    def interfaces_command(self) -> str:
        return "show ip interface brief"

    def parse_interface_names(self, raw_output: str) -> list[str]:
        names = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith("interface"):
                continue
            name = stripped.split()[0]
            if name:
                names.append(name)
        return names

    def parse_platform(self, raw_version: str) -> str:
        for line in raw_version.splitlines():
            stripped = line.strip()
            if "cisco" in stripped.lower() and (
                "CSR" in stripped or "ASR" in stripped
                or "Catalyst" in stripped or "ISR" in stripped
            ):
                return stripped
        return self.parse_version(raw_version)

    # ── CLI → YANG template converter ────────────────────────────────────

    def cli_to_template(self, raw_cli: str) -> dict:
        """
        Convert any IOS / IOS-XE CLI config into a YANG-typed variable schema
        (YAML) + a Jinja2 service template.

        Handles: interfaces, BGP, OSPF, EIGRP, VLANs, static routes,
        ACLs, HSRP/VRRP, NAT, crypto, NTP, SNMP, hostname, and more.
        Falls back to generic IP parameterisation for unknown commands.
        """
        SKIP_RE = re.compile(
            r'^(current configuration|building configuration|end\s*$|!)',
            re.IGNORECASE,
        )

        vars_dict: dict[str, dict] = {}
        tpl_lines: list[str] = []

        def to_var(s: str) -> str:
            return re.sub(r'[^a-z0-9]+', '_', s.strip().lower()).strip('_')

        def set_var(name: str, default: str, type_override: str | None = None) -> str:
            name = to_var(name)
            if name not in vars_dict:
                vars_dict[name] = _infer_spec(name, default, type_override)
            return name

        def set_var_uniq(base: str, default: str, type_override: str | None = None) -> str:
            base = to_var(base)
            name, n = base, 2
            while name in vars_dict:
                name = f'{base}_{n}'; n += 1
            vars_dict[name] = _infer_spec(name, default, type_override)
            return name

        def param_ips(text: str, base: str, uniq: bool = False) -> str:
            first = [True]
            def repl(m: re.Match) -> str:
                vname = (set_var if (first[0] and not uniq) else set_var_uniq)(base, m.group(0))
                first[0] = False
                return f'{{{{ {vname} }}}}'
            return _IP_RE.sub(repl, text)

        ctx = ''   # current block: interface / bgp / ospf / eigrp / vlan / line / isakmp / acl

        for raw_line in raw_cli.splitlines():
            line     = raw_line.strip()
            is_child = bool(raw_line) and raw_line[0] in (' ', '\t')

            if not line or SKIP_RE.match(line):
                continue

            # ── Top-level commands ────────────────────────────────────────
            if not is_child:
                ctx = ''

                # interface <Type><num>
                m = re.match(r'^interface\s+([A-Za-z][\w\-]*[A-Za-z])\s*([\d\/\.]+(?:\.\d+)?)', line, re.I)
                if m:
                    ctx = 'interface'
                    v = set_var('number', m.group(2))
                    tpl_lines.append(f'interface {m.group(1)}{{{{ {v} }}}}'); continue

                # router bgp|ospf|eigrp|rip|isis [process/asn]
                m = re.match(r'^router\s+(\S+)(?:\s+(\S+))?', line, re.I)
                if m:
                    ctx = m.group(1).lower()
                    if m.group(2):
                        is_bgp = ctx == 'bgp'
                        v = set_var('local_asn' if is_bgp else f'{to_var(ctx)}_process',
                                    m.group(2), 'uint32' if is_bgp else None)
                        tpl_lines.append(f'router {m.group(1)} {{{{ {v} }}}}')
                    else:
                        tpl_lines.append(f'router {m.group(1)}')
                    continue

                # vlan <id>
                m = re.match(r'^vlan\s+(\d+)', line, re.I)
                if m:
                    ctx = 'vlan'
                    v = set_var('vlan_id', m.group(1), 'uint16')
                    tpl_lines.append(f'vlan {{{{ {v} }}}}'); continue

                # line vty|console …
                m = re.match(r'^line\s+(\S+)\s+\d+', line, re.I)
                if m:
                    ctx = 'line'; tpl_lines.append(line); continue

                # ip route <net> <mask> <nexthop> [distance]
                m = re.match(r'^ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?', line, re.I)
                if m:
                    nv = set_var_uniq('destination',      m.group(1))
                    mv = set_var_uniq('destination_mask', m.group(2))
                    gv = set_var_uniq('next_hop',         m.group(3))
                    out = f'ip route {{{{ {nv} }}}} {{{{ {mv} }}}} {{{{ {gv} }}}}'
                    if m.group(4):
                        dv = set_var('admin_distance', m.group(4), 'uint8')
                        out += f' {{{{ {dv} }}}}'
                    tpl_lines.append(out); continue

                # ip access-list extended|standard <name>
                m = re.match(r'^ip access-list\s+(\S+)\s+(\S+)', line, re.I)
                if m:
                    ctx = 'acl'
                    v = set_var('acl_name', m.group(2))
                    tpl_lines.append(f'ip access-list {m.group(1)} {{{{ {v} }}}}'); continue

                # hostname
                m = re.match(r'^hostname\s+(\S+)', line, re.I)
                if m:
                    v = set_var('hostname', m.group(1))
                    tpl_lines.append(f'hostname {{{{ {v} }}}}'); continue

                # ip domain-name
                m = re.match(r'^ip domain.name\s+(\S+)', line, re.I)
                if m:
                    v = set_var('domain_name', m.group(1))
                    tpl_lines.append(f'ip domain-name {{{{ {v} }}}}'); continue

                # ntp server <ip>
                m = re.match(r'^ntp server\s+(\S+)', line, re.I)
                if m:
                    v = set_var_uniq('ntp_server', m.group(1))
                    tpl_lines.append(f'ntp server {{{{ {v} }}}}'); continue

                # logging <ip>
                m = re.match(r'^logging\s+(\d{1,3}\.\d)', line, re.I)
                if m:
                    v = set_var_uniq('syslog_server', line.split()[1])
                    tpl_lines.append(f'logging {{{{ {v} }}}}'); continue

                # snmp-server community <str> RO|RW
                m = re.match(r'^snmp-server community\s+(\S+)\s+(RO|RW)(.*)', line, re.I)
                if m:
                    v = set_var('snmp_community', m.group(1))
                    tpl_lines.append(f'snmp-server community {{{{ {v} }}}} {m.group(2).upper()}{m.group(3)}'); continue

                # crypto isakmp policy <priority>
                m = re.match(r'^crypto isakmp policy\s+(\d+)', line, re.I)
                if m:
                    ctx = 'isakmp'
                    v = set_var('isakmp_priority', m.group(1), 'uint16')
                    tpl_lines.append(f'crypto isakmp policy {{{{ {v} }}}}'); continue

                # crypto ipsec transform-set <name> <transforms>
                m = re.match(r'^crypto ipsec transform-set\s+(\S+)\s+(.*)', line, re.I)
                if m:
                    v = set_var('transform_set_name', m.group(1))
                    tpl_lines.append(f'crypto ipsec transform-set {{{{ {v} }}}} {m.group(2)}'); continue

                # ip nat pool <name> <start> <end> netmask <mask>
                m = re.match(r'^ip nat pool\s+(\S+)\s+(\S+)\s+(\S+)\s+netmask\s+(\S+)', line, re.I)
                if m:
                    tpl_lines.append(
                        f'ip nat pool {{{{ {set_var("nat_pool_name", m.group(1))} }}}}'
                        f' {{{{ {set_var("nat_start_ip", m.group(2))} }}}}'
                        f' {{{{ {set_var("nat_end_ip",   m.group(3))} }}}}'
                        f' netmask {{{{ {set_var("nat_mask", m.group(4))} }}}}'
                    ); continue

                # username <name> …
                m = re.match(r'^username\s+(\S+)\s+(.*)', line, re.I)
                if m:
                    v = set_var('username', m.group(1))
                    tpl_lines.append(f'username {{{{ {v} }}}} {m.group(2)}'); continue

                # Generic: any line with IPs
                if _IP_RE.search(line):
                    tpl_lines.append(param_ips(line, to_var(line.split()[0]))); continue

                tpl_lines.append(line)

            # ── Child / indented commands ─────────────────────────────────
            else:
                # ip address <ip> <mask>
                m = re.match(r'^ip address\s+(\S+)\s+(\S+)', line, re.I)
                if m:
                    iv = set_var('ip_address', m.group(1))
                    mv = set_var('netmask',    m.group(2))
                    tpl_lines.append(f' ip address {{{{ {iv} }}}} {{{{ {mv} }}}}'); continue

                # description
                m = re.match(r'^description\s+(.*)', line, re.I)
                if m:
                    v = set_var('description', m.group(1))
                    tpl_lines.append(f' description {{{{ {v} }}}}'); continue

                # ── BGP ───────────────────────────────────────────────────
                if ctx == 'bgp':
                    m = re.match(r'^bgp router-id\s+(\S+)', line, re.I)
                    if m:
                        tpl_lines.append(f' bgp router-id {{{{ {set_var("router_id", m.group(1))} }}}}'); continue

                    m = re.match(r'^neighbor\s+(\S+)\s+remote-as\s+(\d+)', line, re.I)
                    if m:
                        nv = set_var_uniq('neighbor_ip', m.group(1))
                        av = set_var_uniq('remote_asn',  m.group(2), 'uint32')
                        tpl_lines.append(f' neighbor {{{{ {nv} }}}} remote-as {{{{ {av} }}}}'); continue

                    m = re.match(r'^neighbor\s+(\S+)\s+description\s+(.*)', line, re.I)
                    if m:
                        nv = set_var_uniq('neighbor_ip',          m.group(1))
                        dv = set_var_uniq('neighbor_description', m.group(2))
                        tpl_lines.append(f' neighbor {{{{ {nv} }}}} description {{{{ {dv} }}}}'); continue

                    m = re.match(r'^neighbor\s+(\S+)\s+update-source\s+(\S+)', line, re.I)
                    if m:
                        nv = set_var_uniq('neighbor_ip', m.group(1))
                        tpl_lines.append(f' neighbor {{{{ {nv} }}}} update-source {m.group(2)}'); continue

                    m = re.match(r'^neighbor\s+(\S+)\s+(.*)', line, re.I)
                    if m and _valid_ip(m.group(1)):
                        nv = set_var_uniq('neighbor_ip', m.group(1))
                        tpl_lines.append(f' neighbor {{{{ {nv} }}}} {m.group(2)}'); continue

                    m = re.match(r'^network\s+(\S+)\s+mask\s+(\S+)', line, re.I)
                    if m:
                        nv = set_var_uniq('network',      m.group(1))
                        mv = set_var_uniq('network_mask', m.group(2))
                        tpl_lines.append(f' network {{{{ {nv} }}}} mask {{{{ {mv} }}}}'); continue

                # ── OSPF ──────────────────────────────────────────────────
                if ctx == 'ospf':
                    m = re.match(r'^router-id\s+(\S+)', line, re.I)
                    if m:
                        tpl_lines.append(f' router-id {{{{ {set_var("router_id", m.group(1))} }}}}'); continue

                    m = re.match(r'^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', line, re.I)
                    if m:
                        nv = set_var_uniq('network',  m.group(1))
                        wv = set_var_uniq('wildcard', m.group(2))
                        at = 'uint32' if m.group(3).isdigit() else 'string'
                        av = set_var_uniq('area', m.group(3), at)
                        tpl_lines.append(f' network {{{{ {nv} }}}} {{{{ {wv} }}}} area {{{{ {av} }}}}'); continue

                    m = re.match(r'^area\s+(\S+)\s+(.*)', line, re.I)
                    if m:
                        at = 'uint32' if m.group(1).isdigit() else 'string'
                        av = set_var('area', m.group(1), at)
                        tpl_lines.append(f' area {{{{ {av} }}}} {m.group(2)}'); continue

                # ── EIGRP ─────────────────────────────────────────────────
                if ctx == 'eigrp':
                    m = re.match(r'^router-id\s+(\S+)', line, re.I)
                    if m:
                        tpl_lines.append(f' router-id {{{{ {set_var("router_id", m.group(1))} }}}}'); continue

                    m = re.match(r'^network\s+(\S+)(?:\s+(\S+))?', line, re.I)
                    if m:
                        nv = set_var_uniq('network', m.group(1))
                        if m.group(2):
                            wv = set_var_uniq('wildcard', m.group(2))
                            tpl_lines.append(f' network {{{{ {nv} }}}} {{{{ {wv} }}}}')
                        else:
                            tpl_lines.append(f' network {{{{ {nv} }}}}')
                        continue

                # ── VLAN ──────────────────────────────────────────────────
                if ctx == 'vlan':
                    m = re.match(r'^name\s+(.*)', line, re.I)
                    if m:
                        v = set_var('vlan_name', m.group(1))
                        tpl_lines.append(f' name {{{{ {v} }}}}'); continue

                # ── ISAKMP ────────────────────────────────────────────────
                if ctx == 'isakmp':
                    m = re.match(r'^lifetime\s+(\d+)', line, re.I)
                    if m:
                        v = set_var('lifetime_seconds', m.group(1), 'uint32')
                        tpl_lines.append(f' lifetime {{{{ {v} }}}}'); continue

                # ── LINE ──────────────────────────────────────────────────
                if ctx == 'line':
                    m = re.match(r'^exec-timeout\s+(\d+)(?:\s+(\d+))?', line, re.I)
                    if m:
                        mv2 = set_var('exec_timeout_min', m.group(1), 'uint8')
                        if m.group(2):
                            sv = set_var('exec_timeout_sec', m.group(2), 'uint8')
                            tpl_lines.append(f' exec-timeout {{{{ {mv2} }}}} {{{{ {sv} }}}}')
                        else:
                            tpl_lines.append(f' exec-timeout {{{{ {mv2} }}}}')
                        continue

                # ── Interface extras ──────────────────────────────────────
                m = re.match(r'^encapsulation dot1q\s+(\d+)', line, re.I)
                if m:
                    v = set_var('vlan_id', m.group(1), 'uint16')
                    tpl_lines.append(f' encapsulation dot1q {{{{ {v} }}}}'); continue

                m = re.match(r'^ip helper-address\s+(\S+)', line, re.I)
                if m:
                    v = set_var_uniq('dhcp_server', m.group(1))
                    tpl_lines.append(f' ip helper-address {{{{ {v} }}}}'); continue

                m = re.match(r'^standby\s+(\d+)\s+ip\s+(\S+)', line, re.I)
                if m:
                    gv = set_var('hsrp_group', m.group(1), 'uint8')
                    iv = set_var('hsrp_ip',    m.group(2))
                    tpl_lines.append(f' standby {{{{ {gv} }}}} ip {{{{ {iv} }}}}'); continue

                m = re.match(r'^vrrp\s+(\d+)\s+ip\s+(\S+)', line, re.I)
                if m:
                    gv = set_var('vrrp_group', m.group(1), 'uint8')
                    iv = set_var('vrrp_ip',    m.group(2))
                    tpl_lines.append(f' vrrp {{{{ {gv} }}}} ip {{{{ {iv} }}}}'); continue

                m = re.match(r'^switchport access vlan\s+(\d+)', line, re.I)
                if m:
                    v = set_var('vlan_id', m.group(1), 'uint16')
                    tpl_lines.append(f' switchport access vlan {{{{ {v} }}}}'); continue

                m = re.match(r'^switchport trunk allowed vlan\s+([\d,\-]+)', line, re.I)
                if m:
                    v = set_var('allowed_vlans', m.group(1))
                    tpl_lines.append(f' switchport trunk allowed vlan {{{{ {v} }}}}'); continue

                m = re.match(r'^bandwidth\s+(\d+)', line, re.I)
                if m:
                    v = set_var('bandwidth_kbps', m.group(1), 'uint32')
                    tpl_lines.append(f' bandwidth {{{{ {v} }}}}'); continue

                m = re.match(r'^ip ospf cost\s+(\d+)', line, re.I)
                if m:
                    v = set_var('ospf_cost', m.group(1), 'uint16')
                    tpl_lines.append(f' ip ospf cost {{{{ {v} }}}}'); continue

                m = re.match(r'^ip ospf\s+(\d+)\s+area\s+(\S+)', line, re.I)
                if m:
                    pv = set_var('ospf_process', m.group(1), 'uint16')
                    at = 'uint32' if m.group(2).isdigit() else 'string'
                    av = set_var('ospf_area', m.group(2), at)
                    tpl_lines.append(f' ip ospf {{{{ {pv} }}}} area {{{{ {av} }}}}'); continue

                m = re.match(r'^ip access-group\s+(\S+)\s+(in|out)', line, re.I)
                if m:
                    v = set_var('acl_name', m.group(1))
                    tpl_lines.append(f' ip access-group {{{{ {v} }}}} {m.group(2)}'); continue

                # Generic fallback: lines with IPs
                if _IP_RE.search(line):
                    tpl_lines.append(f' {param_ips(line, to_var(line.split()[0]))}'); continue

                tpl_lines.append(' ' + line)

        return {
            'schema':         _schema_to_yaml(vars_dict),
            'template':       '\n'.join(tpl_lines),
            'variable_count': len(vars_dict),
        }
