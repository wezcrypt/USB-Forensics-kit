"""Network state collector (volatile data - collected live)."""

from __future__ import annotations

import socket
from typing import Dict, List

from ..core import commands
from ..core.context import CollectionContext
from ..core.timeutil import utc_now_iso
from ..core.winapi import IS_WINDOWS, is_admin
from .base import Collector, register

PS_QUERIES = {
    "dns_cache": ("Get-DnsClientCache | Select-Object Entry,Name,Type,Status,Section,TimeToLive,DataLength,Data "
                  "| ConvertTo-Json -Depth 3 -Compress"),
    "arp_table": ("Get-NetNeighbor | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,LinkLayerAddress,"
                  "@{n='State';e={[string]$_.State}},AddressFamily | ConvertTo-Json -Depth 3 -Compress"),
    "routing_table": ("Get-NetRoute | Select-Object DestinationPrefix,NextHop,RouteMetric,InterfaceAlias,InterfaceIndex,"
                      "@{n='Protocol';e={[string]$_.Protocol}},AddressFamily | ConvertTo-Json -Depth 3 -Compress"),
    "adapters": ("Get-NetAdapter | Select-Object Name,InterfaceDescription,ifIndex,Status,MacAddress,LinkSpeed,"
                 "MediaType,DriverVersion,DriverDate | ConvertTo-Json -Depth 3 -Compress"),
    "ip_addresses": ("Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressFamily,"
                     "@{n='PrefixOrigin';e={[string]$_.PrefixOrigin}} | ConvertTo-Json -Depth 3 -Compress"),
    "firewall_profiles": ("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,"
                          "LogAllowed,LogBlocked,LogFileName,NotifyOnListen | ForEach-Object { $_.DefaultInboundAction=[string]$_.DefaultInboundAction; "
                          "$_.DefaultOutboundAction=[string]$_.DefaultOutboundAction; $_.Enabled=[string]$_.Enabled; $_ } "
                          "| ConvertTo-Json -Depth 3 -Compress"),
    "firewall_rules": ("$pfs=@{}; Get-NetFirewallPortFilter -All | ForEach-Object { $pfs[$_.InstanceID]=$_ }; "
                       "$afs=@{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $afs[$_.InstanceID]=$_ }; "
                       "Get-NetFirewallRule -Enabled True | ForEach-Object { $pf = $pfs[$_.InstanceID]; "
                       "$af = $afs[$_.InstanceID]; [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; "
                       "Direction=[string]$_.Direction; Action=[string]$_.Action; Profile=[string]$_.Profile; "
                       "Program=$af.Program; Protocol=$pf.Protocol; LocalPort=($pf.LocalPort -join ','); "
                       "RemotePort=($pf.RemotePort -join ','); Group=$_.Group } } | ConvertTo-Json -Depth 3 -Compress"),
}

RAW_COMMANDS = [
    (["ipconfig.exe", "/all"], "ipconfig_all.txt"),
    (["ipconfig.exe", "/displaydns"], "ipconfig_displaydns.txt"),
    (["netstat.exe", "-anob"], "netstat_anob.txt"),
    (["arp.exe", "-a"], "arp_a.txt"),
    (["route.exe", "print"], "route_print.txt"),
    (["netsh.exe", "advfirewall", "show", "allprofiles"], "netsh_firewall_profiles.txt"),
]


@register
class NetworkCollector(Collector):
    name = "network"
    title = "Network Analysis"
    category = "Network"
    description = ("TCP/UDP connections and listening ports with owning process, DNS cache, ARP, routes, adapters, "
                   "IP configuration and Windows Firewall profiles/rules.")
    requires_admin = "partial"
    admin_note = "Owning process of some system connections and `netstat -b` require Administrator."
    windows_only = False

    def run(self, ctx: CollectionContext) -> None:
        self._connections(ctx)
        if IS_WINDOWS:  # pragma: no cover
            for i, (name, script) in enumerate(PS_QUERIES.items()):
                ctx.check_cancel()
                ctx.progress(0.2 + 0.6 * i / len(PS_QUERIES), name)
                try:
                    rows = ctx.powershell_json(script, name, timeout=300)
                    ctx.write_records(name, rows)
                except Exception as exc:
                    ctx.error(f"{name}: {exc}", "error")
            for args, fname in RAW_COMMANDS:
                if args[0] == "netstat.exe" and not is_admin():
                    args = ["netstat.exe", "-ano"]
                ctx.run_command([commands.system32(args[0])] + args[1:], name=fname, timeout=180)
        else:
            self._interfaces(ctx)

    def _connections(self, ctx: CollectionContext) -> None:
        try:
            import psutil
        except ImportError:  # pragma: no cover
            ctx.error("psutil not available", "error")
            return
        snapshot = utc_now_iso()
        names: Dict[int, Dict] = {}
        for p in psutil.process_iter(["pid", "name", "exe"]):
            names[p.pid] = {"name": p.info.get("name"), "exe": p.info.get("exe")}
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            ctx.error("listing network connections requires elevated rights on this platform", "requires_admin")
            return
        out: List[Dict] = []
        listening: List[Dict] = []
        for c in conns:
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            proc = names.get(c.pid or -1, {})
            rec = {
                "snapshot_utc": snapshot,
                "protocol": proto + ("6" if c.family == socket.AF_INET6 else ""),
                "local_address": c.laddr.ip if c.laddr else None,
                "local_port": c.laddr.port if c.laddr else None,
                "remote_address": c.raddr.ip if c.raddr else None,
                "remote_port": c.raddr.port if c.raddr else None,
                "state": c.status if proto == "TCP" else None,
                "pid": c.pid,
                "process": proc.get("name"),
                "process_path": proc.get("exe"),
            }
            out.append(rec)
            if (proto == "TCP" and c.status == "LISTEN") or (proto == "UDP" and not c.raddr):
                listening.append(rec)
        ctx.write_records("connections", out)
        ctx.write_records("listening_ports", listening)
        if any(r["pid"] is None for r in out):
            ctx.error("some connections have no owning PID (insufficient rights)", "requires_admin" if not is_admin() else "access_denied")

    def _interfaces(self, ctx: CollectionContext) -> None:
        import psutil

        stats = psutil.net_if_stats()
        rows = []
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            rows.append({"name": name, "is_up": st.isup if st else None, "speed_mbps": st.speed if st else None,
                         "addresses": [{"family": str(a.family), "address": a.address, "netmask": a.netmask} for a in addrs]})
        ctx.write_records("adapters", rows)
