#!/usr/bin/env python3

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import re
import socket
import sys
import time
import traceback
import uuid
from typing import Dict, List, Optional, Tuple

import colorama
from colorama import Fore, Style
from impacket.dcerpc.v5 import rrp, transport
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection, SessionError
from ldap3 import ALL, NTLM, Connection, Server


class Logger:
    """Handles color-coded logging (error, info, debug) in a single place."""

    def __init__(self, debug: bool = False) -> None:
        colorama.init(autoreset=True)
        self.debug_mode = debug
        self.RED = Fore.RED
        self.GREEN = Fore.GREEN
        self.YELLOW = Fore.YELLOW
        self.CYAN = Fore.CYAN
        self.MAGENTA = Fore.MAGENTA
        self.RESET = Style.RESET_ALL

    def error(self, message: str) -> None:
        print(f"{self.RED}{message}{self.RESET}")

    def info(self, message: str) -> None:
        print(f"{self.CYAN}{message}{self.RESET}")

    def debug(self, message: str) -> None:
        if self.debug_mode:
            print(f"{self.YELLOW}[debug]{self.RESET} {message}")

    def banner(self) -> None:
        print(
            f"""{self.MAGENTA}
           _       ____  ______
    ____  (_)   __/ __ \\_  __/
   / __ \\/ / | / / / / / / /   
  / /_/ / /| |/ / /_/ / / /    
 / .___/_/ |___/\\____/ /_/     
/_/                            

  pivOT: A pivoting utility for enumerating OT references
{self.RESET}"""
        )


class OTSubnetManager:
    """Responsible for parsing and handling OT subnets."""

    def __init__(self, subnet_strings: List[str], logger: Logger) -> None:
        self.logger = logger
        self.ot_networks = self._parse_ot_subnets(subnet_strings)

    def _parse_ot_subnets(
        self,
        subnet_strings: List[str],
    ) -> List[ipaddress.ip_network]:
        networks = []
        for subnet in subnet_strings:
            subnet = subnet.strip()
            if not subnet:
                continue
            if "/" not in subnet:
                if subnet.count(".") == 2 and subnet.endswith("."):
                    subnet = f"{subnet}0.0/16"
                else:
                    subnet = f"{subnet}/32"
            try:
                net_obj = ipaddress.ip_network(subnet, strict=False)
                networks.append(net_obj)
            except ValueError:
                self.logger.error(f"[!] Invalid subnet format '{subnet}' - skipping.")
        return networks

    def is_ip_in_ot_subnets(self, ip_address: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return False
        return any(ip_obj in net for net in self.ot_networks)


def quick_smb_check(host: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Quick test to see if TCP/445 is open on the target."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class LDAPEnumerator:
    """Handles LDAP connectivity and domain computer enumeration."""

    def __init__(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: Optional[str],
        lm_hash: str,
        nt_hash: str,
        use_kerberos: bool,
        logger: Logger,
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.use_kerberos = use_kerberos
        self.logger = logger

    def _create_ldap3_connection(self) -> Connection:
        """Establishes an LDAP3 connection with an NTLM bind."""
        host_for_ldap = self.dc_ip if self.dc_ip else self.domain
        server_url = f"ldap://{host_for_ldap}:389"
        self.logger.debug(f"Attempting LDAP connect to: {server_url}")

        server = Server(server_url, get_info=ALL, use_ssl=False)

        if self.nt_hash:
            pass_the_hash = f"{self.lm_hash if self.lm_hash else ''}:{self.nt_hash}"
            effective_password = pass_the_hash
            self.logger.debug(f"Using hash: {pass_the_hash}")
        else:
            effective_password = self.password

        user_credentials = f"{self.domain}\\{self.username}"
        conn = Connection(
            server,
            user=user_credentials,
            password=effective_password,
            authentication=NTLM,
            auto_referrals=False,
            receive_timeout=60,
        )
        if conn.bind():
            self.logger.debug("NTLM LDAP bind success")
            return conn
        else:
            raise Exception(f"Failed LDAP bind: {conn.result}")

    def enumerate_domain_computers(self) -> List[str]:
        computers = []
        try:
            conn = self._create_ldap3_connection()
            if not conn.bound:
                return computers

            base_dn = None
            if conn.server.info:
                naming_contexts = conn.server.info.naming_contexts
                if naming_contexts:
                    base_dn = naming_contexts[0]

            if not base_dn:
                base_dn = "DC=" + ",DC=".join(self.domain.split("."))

            self.logger.debug(f"Using baseDN: {base_dn}")

            search_filter = "(objectClass=computer)"
            attributes = ["dNSHostName", "sAMAccountName"]
            conn.search(base_dn, search_filter, attributes=attributes, paged_size=1000)

            for entry in conn.response:
                if entry.get("type") == "searchResEntry":
                    att_map = entry.get("attributes", {})
                    dns_name = att_map.get("dNSHostName")
                    sam_name = att_map.get("sAMAccountName")
                    if isinstance(dns_name, list) and dns_name:
                        dns_name = dns_name[0]
                    if isinstance(sam_name, list) and sam_name:
                        sam_name = sam_name[0]
                    if dns_name:
                        computers.append(dns_name.lower())
                    elif sam_name:
                        computers.append(sam_name.replace("$", "").lower())

            conn.unbind()
        except Exception as exc:
            self.logger.debug(f"LDAP enumeration error: {exc}")
            if self.logger.debug_mode:
                traceback.print_exc()
            return []

        return list(set(computers)) if computers else []


class SMBConnectionFactory:
    """Creates SMBConnection objects with Kerberos → NTLM fallback logic."""

    def __init__(self, logger: Logger) -> None:
        self.logger = logger

    def create_smb_session_kerb_fallback(
        self,
        target_host: str,
        domain: str,
        username: str,
        password: str,
        lm_hash: str = "",
        nt_hash: str = "",
        use_kerberos: bool = False,
    ) -> SMBConnection:
        if use_kerberos:
            try:
                self.logger.debug("Attempting Kerberos SMB login...")
                smb_conn = SMBConnection(
                    remoteName=target_host,
                    remoteHost=target_host,
                    sess_port=445,
                )
                smb_conn.kerberosLogin(
                    username,
                    password,
                    domain,
                    lmhash=lm_hash,
                    nthash=nt_hash,
                )
                self.logger.debug("Kerberos SMB login succeeded!")
                return smb_conn
            except SessionError as kerb_exc:
                err_code = (
                    kerb_exc.getErrorCode() if hasattr(kerb_exc, "getErrorCode") else 0
                )
                self.logger.debug(
                    f"Kerberos login failed with code=0x{err_code:x}, "
                    "falling back to NTLM...",
                )

        self.logger.debug("Using NTLM/pass-the-hash.")
        smb_conn = SMBConnection(
            remoteName=target_host,
            remoteHost=target_host,
            sess_port=445,
        )
        smb_conn.login(
            user=username,
            password=password,
            domain=domain,
            lmhash=lm_hash,
            nthash=nt_hash,
        )
        self.logger.debug("NTLM SMB login succeeded.")
        return smb_conn


class RegistrySearcher:
    """Checks for references to IP addresses within OT subnets in remote registry."""

    def __init__(
        self,
        smb_conn: SMBConnection,
        ot_subnet_manager: OTSubnetManager,
        logger: Logger,
    ) -> None:
        self.smb_conn = smb_conn
        self.logger = logger
        self.ot_subnet_manager = ot_subnet_manager

    def search_for_ot(self) -> List[Tuple[str, str, str]]:
        matches = []
        try:
            pipe_uri = f"ncacn_np:{self.smb_conn.getRemoteHost()}[\\PIPE\\winreg]"
            self.logger.debug(f"Opening named pipe for registry: {pipe_uri}")
            rpc_transport = transport.DCERPCTransportFactory(pipe_uri)
            rpc_transport.set_smb_connection(self.smb_conn)

            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            local_machine = rrp.hOpenLocalMachine(dce)
            lm_handle = local_machine["phKey"]

            net_key = rrp.hBaseRegOpenKey(
                dce,
                lm_handle,
                "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
            )
            interfaces_handle = net_key["phkResult"]

            idx = 0
            while True:
                try:
                    enum_key = rrp.hBaseRegEnumKey(dce, interfaces_handle, idx)
                    sub_key_name = enum_key["lpNameOut"]
                    idx += 1

                    sub_open = rrp.hBaseRegOpenKey(dce, interfaces_handle, sub_key_name)
                    sub_handle = sub_open["phkResult"]

                    val_idx = 0
                    while True:
                        try:
                            valenum = rrp.hBaseRegEnumValue(dce, sub_handle, val_idx)
                            val_idx += 1

                            value_name = valenum["lpValueNameOut"]
                            value_type = valenum["lpType"]
                            raw_data = valenum["lpData"]
                            data_parsed = rrp.unpackValue(value_type, raw_data)

                            if isinstance(data_parsed, str):
                                if self.ot_subnet_manager.is_ip_in_ot_subnets(
                                    data_parsed,
                                ):
                                    matches.append(
                                        (sub_key_name, value_name, data_parsed),
                                    )
                            elif isinstance(data_parsed, list):
                                for item in data_parsed:
                                    if self.ot_subnet_manager.is_ip_in_ot_subnets(item):
                                        matches.append((sub_key_name, value_name, item))

                        except DCERPCException as dcerpc_exc:
                            if (
                                hasattr(dcerpc_exc, "error_code")
                                and dcerpc_exc.error_code == 0x103
                            ):
                                break
                            else:
                                self.logger.debug(
                                    f"Registry value enum error: {dcerpc_exc}",
                                )
                                break

                    rrp.hBaseRegCloseKey(dce, sub_handle)

                except DCERPCException as dcerpc_exc:
                    if (
                        hasattr(dcerpc_exc, "error_code")
                        and dcerpc_exc.error_code == 0x103
                    ):
                        break
                    else:
                        self.logger.debug(f"Registry subkey enum error: {dcerpc_exc}")
                        break

            rrp.hBaseRegCloseKey(dce, interfaces_handle)
            rrp.hBaseRegCloseKey(dce, lm_handle)
            dce.disconnect()

        except DCERPCException as dcerpc_exc:
            if "ACCESS_DENIED" in str(dcerpc_exc).upper():
                self.logger.debug("[!] Registry Access Denied.")
                raise
            else:
                if self.logger.debug_mode:
                    traceback.print_exc()
                raise
        except Exception as exc:
            if self.logger.debug_mode:
                traceback.print_exc()
            raise exc

        return matches


class WMIExecutor:
    """Handles WMI/DCOM-based command execution (e.g., netstat)."""

    def __init__(
        self,
        smb_conn: SMBConnection,
        target: str,
        username: str,
        password: str,
        domain: str,
        kerberos: bool,
        lm_hash: str,
        nt_hash: str,
        logger: Logger,
    ) -> None:
        self.smb_conn = smb_conn
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.kerberos = kerberos
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.logger = logger

    def _generate_random_filename(self) -> str:
        return f"tmp_{uuid.uuid4().hex[:6]}.log"

    def _execute_command(self, command: str) -> str:
        share_name = "ADMIN$"
        output_file = self._generate_random_filename()
        remote_output_path = f"\\\\127.0.0.1\\{share_name}\\{output_file}"

        self.logger.debug(f"Using output file: {output_file}")
        self.logger.debug(f"Remote path: {remote_output_path}")

        dcom = DCOMConnection(
            self.target,
            self.username,
            self.password,
            self.domain,
            self.lm_hash,
            self.nt_hash,
            None,
            oxidResolver=True,
            doKerberos=self.kerberos,
            remoteHost=self.target,
        )

        try:
            i_interface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login,
                wmi.IID_IWbemLevel1Login,
            )
            i_wbem_login = wmi.IWbemLevel1Login(i_interface)
            i_wbem_services = i_wbem_login.NTLMLogin("//./root/cimv2", NULL, NULL)
            i_wbem_login.RemRelease()

            win32_process, _ = i_wbem_services.GetObject("Win32_Process")
            working_dir = "C:\\Windows\\System32"
            final_cmd = f"cmd.exe /Q /c {command} > {remote_output_path} 2>&1"
            self.logger.debug(f"Final WMI command: {final_cmd}")

            process_info = win32_process.Create(final_cmd, working_dir, None)
            if process_info.ReturnValue != 0:
                return f"[!] WMI command exec failed: {process_info.ReturnValue}"

            time.sleep(3)

            output_data = b""
            max_retries = 3
            attempts = 0

            while attempts < max_retries:
                try:
                    self.logger.debug(
                        f"Reading attempt {attempts + 1} from {share_name}:{output_file}",
                    )

                    def output_callback(data_block):
                        nonlocal output_data
                        output_data += data_block

                    self.smb_conn.getFile(share_name, output_file, output_callback)
                    break
                except Exception as read_exc:
                    attempts += 1
                    if attempts == max_retries:
                        self.logger.debug(f"Final read attempt failed: {str(read_exc)}")
                        return (
                            f"[!] Error reading output after {max_retries} attempts: "
                            f"{read_exc}"
                        )
                    time.sleep(2)

            try:
                self.smb_conn.deleteFile(share_name, output_file)
            except:
                pass

            try:
                return output_data.decode("cp437", errors="replace")
            except:
                return output_data.decode("utf-8", errors="replace")

        finally:
            dcom.disconnect()

    def get_netstat_ot_matches(self, ot_subnet_manager: OTSubnetManager) -> List[str]:
        findings = []
        netstat_out = self._execute_command("netstat -ano")
        if netstat_out.startswith("[!]"):
            findings.append(netstat_out)
            return findings

        for line in netstat_out.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith(("Proto", "Active")):
                continue

            match = re.match(
                r"^(TCP|UDP)\s+([\d\.]+):(\d+)\s+([\d\.]+):(\d+)\s+(.*)",
                line_stripped,
            )
            if match:
                remote_ip = match.group(4)
                if ot_subnet_manager.is_ip_in_ot_subnets(remote_ip):
                    findings.append(line_stripped)

        return findings


class OTScanner:
    """Orchestrates checks for a single target: SMB connectivity, registry, WMI netstat."""

    def __init__(
        self,
        domain: str,
        username: str,
        password: str,
        lm_hash: str,
        nt_hash: str,
        use_kerberos: bool,
        ot_subnet_manager: OTSubnetManager,
        do_registry: bool,
        do_netstat: bool,
        logger: Logger,
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.use_kerberos = use_kerberos
        self.ot_subnet_manager = ot_subnet_manager
        self.do_registry = do_registry
        self.do_netstat = do_netstat
        self.logger = logger
        self.smb_factory = SMBConnectionFactory(logger)

    def check_target_for_ot(self, target: str) -> Dict:
        if not quick_smb_check(target):
            self.logger.error(f"{target}: SMB 445 unreachable, skipping.")
            return {
                "target": target,
                "registry_ot_matches": ["[!] Unreachable"],
                "netstat_ot_matches": ["[!] Unreachable"],
            }

        result = {"target": target, "registry_ot_matches": [], "netstat_ot_matches": []}

        try:
            smb_conn = self.smb_factory.create_smb_session_kerb_fallback(
                target,
                self.domain,
                self.username,
                self.password,
                lm_hash=self.lm_hash,
                nt_hash=self.nt_hash,
                use_kerberos=self.use_kerberos,
            )
            self.logger.debug(f"SMB Dialect={smb_conn.getDialect()} on {target}")
        except Exception as smb_exc:
            error_message = f"[!] SMB connection error: {smb_exc}"
            self.logger.debug(error_message)
            if self.logger.debug_mode:
                traceback.print_exc()
            result["registry_ot_matches"] = [error_message]
            result["netstat_ot_matches"] = [error_message]
            return result

        if self.do_registry:
            try:
                reg_searcher = RegistrySearcher(
                    smb_conn,
                    self.ot_subnet_manager,
                    self.logger,
                )
                reg_hits = reg_searcher.search_for_ot()
                result["registry_ot_matches"] = reg_hits
            except DCERPCException as reg_exc:
                err_msg = f"[!] Registry check error: {reg_exc}"
                self.logger.debug(err_msg)
                if self.logger.debug_mode:
                    traceback.print_exc()
                result["registry_ot_matches"] = [err_msg]
            except Exception as reg_exc:
                err_msg = f"[!] Registry check error: {reg_exc}"
                self.logger.debug(err_msg)
                if self.logger.debug_mode:
                    traceback.print_exc()
                result["registry_ot_matches"] = [err_msg]

        if self.do_netstat:
            wmi_exec = WMIExecutor(
                smb_conn=smb_conn,
                target=target,
                username=self.username,
                password=self.password,
                domain=self.domain,
                kerberos=self.use_kerberos,
                lm_hash=self.lm_hash,
                nt_hash=self.nt_hash,
                logger=self.logger,
            )
            net_hits = wmi_exec.get_netstat_ot_matches(self.ot_subnet_manager)
            result["netstat_ot_matches"] = net_hits

        smb_conn.close()
        return result


def save_results_json(filename: str, data: List[Dict]) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_results_csv(filename: str, data: List[Dict]) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "RegistryOTMatches", "NetstatOTMatches"])
        for row in data:
            target = row["target"]
            reg = "; ".join(str(item) for item in row["registry_ot_matches"])
            net = "; ".join(str(item) for item in row["netstat_ot_matches"])
            writer.writerow([target, reg, net])


def main() -> None:
    logger = Logger()

    parser = argparse.ArgumentParser(
        description=(
            "pivOT: WMI/Registry-based checks for OT IP addresses, "
            "supporting pass-the-hash & password auth."
        ),
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Domain name for SMB/DCOM/LDAP operations.",
    )
    parser.add_argument(
        "-u",
        "--username",
        required=True,
        help="User account for authentication.",
    )
    parser.add_argument(
        "-p",
        "--password",
        default="",
        help="Password (omit if pass-the-hash).",
    )
    parser.add_argument(
        "-H",
        "--hashes",
        metavar="LM:NT",
        help="Pass-the-hash in 'LM:NT' or ':NT' format.",
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use Kerberos (requires valid TGT or password).",
    )
    parser.add_argument(
        "--dc-ip",
        help="Domain Controller IP for LDAP or Kerberos if needed.",
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Single target host (hostname or IP).",
    )
    parser.add_argument(
        "-f",
        "--targets-file",
        help="File with a list of targets, one per line.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of parallel threads to use.",
    )
    parser.add_argument(
        "--no-registry",
        action="store_true",
        help="Skip the registry check.",
    )
    parser.add_argument(
        "--no-netstat",
        action="store_true",
        help="Skip the netstat check.",
    )
    parser.add_argument(
        "--ot-subnets",
        nargs="+",
        default=["10.10.0.0/16", "192.168.100.0/24"],
        help="List of OT subnets to search for.",
    )
    parser.add_argument(
        "--ldap-enum",
        action="store_true",
        help="If no targets are specified, enumerate domain computers via LDAP.",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "csv"],
        help="Save results in JSON or CSV format.",
    )
    parser.add_argument(
        "--output-file",
        help="Output filename for the results.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug output.",
    )

    args = parser.parse_args()

    logger = Logger(debug=args.debug)
    logger.banner()

    lm_hash, nt_hash = "", ""
    if args.hashes:
        parts = args.hashes.split(":")
        if len(parts) == 2:
            lm_hash, nt_hash = parts
        else:
            lm_hash, nt_hash = "", parts[0]

    targets = []
    if args.targets_file:
        with open(args.targets_file, "r") as tf:
            for line in tf:
                line = line.strip()
                if line:
                    targets.append(line)
    elif args.target:
        targets = [args.target]
    else:
        if args.ldap_enum:
            logger.debug("No direct targets. Enumerating from LDAP...")
            ldap_enum = LDAPEnumerator(
                domain=args.domain,
                username=args.username,
                password=args.password,
                dc_ip=args.dc_ip,
                lm_hash=lm_hash,
                nt_hash=nt_hash,
                use_kerberos=args.kerberos,
                logger=logger,
            )
            targets = ldap_enum.enumerate_domain_computers() or []
            if not targets:
                logger.error("[!] No targets found or specified. Exiting.")
                sys.exit(1)
            logger.debug(f"LDAP enumeration found {len(targets)} host(s).")
        else:
            logger.error("[!] No targets specified and --ldap-enum not set. Exiting.")
            sys.exit(0)

    if not targets:
        logger.error("[!] No targets found or specified. Exiting.")
        sys.exit(1)

    ot_subnet_manager = OTSubnetManager(args.ot_subnets, logger)
    if not ot_subnet_manager.ot_networks:
        logger.error("[!] No valid OT subnets provided. Exiting.")
        sys.exit(1)

    run_registry_check = not args.no_registry
    run_netstat_check = not args.no_netstat

    logger.debug(
        f"Starting scans on {len(targets)} host(s) with {args.threads} threads."
    )

    scanner = OTScanner(
        domain=args.domain,
        username=args.username,
        password=args.password,
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        use_kerberos=args.kerberos,
        ot_subnet_manager=ot_subnet_manager,
        do_registry=run_registry_check,
        do_netstat=run_netstat_check,
        logger=logger,
    )

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_host = {
            executor.submit(scanner.check_target_for_ot, t): t for t in targets
        }

        completed = 0
        total = len(future_to_host)
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                scan_result = future.result()
                results.append(scan_result)
            except Exception as scan_exc:
                if args.debug:
                    traceback.print_exc()
                results = []

    print(
        f"\n{Fore.BLUE}================= SCAN RESULTS ================={Style.RESET_ALL}"
    )
    for r in results:
        print(f"\n{logger.MAGENTA}---- {r['target']} ----{logger.RESET}")
        registry_matches = r["registry_ot_matches"]
        netstat_matches = r["netstat_ot_matches"]

        if run_registry_check:
            if (
                len(registry_matches) == 1
                and isinstance(registry_matches[0], str)
                and registry_matches[0].startswith("[!]")
            ):
                logger.error(f"  [Registry] {registry_matches[0]}")
            elif registry_matches:
                print(
                    f"{logger.GREEN}  [Registry] Potential OT references:{logger.RESET}"
                )
                for item in registry_matches:
                    if isinstance(item, tuple) and len(item) == 3:
                        iface_key, value_name, ip_val = item
                        print(
                            f"    Interface={iface_key}, Key={value_name}, Value={ip_val}",
                        )
                    else:
                        print(f"    {item}")
            else:
                print("  [Registry] No OT references found.")

        if run_netstat_check:
            if len(netstat_matches) == 1 and netstat_matches[0].startswith("[!]"):
                logger.error(f"  [Netstat] {netstat_matches[0]}")
            elif netstat_matches and netstat_matches[0].startswith("[*]"):
                print(f"  [Netstat] {netstat_matches[0]}")
            elif netstat_matches:
                print(
                    f"{logger.GREEN}  [Netstat] Potential OT connections:{logger.RESET}"
                )
                for line in netstat_matches:
                    print(f"    {line}")
            else:
                print("  [Netstat] No OT connections found.")

    if args.output_format and args.output_file:
        if args.output_format == "json":
            save_results_json(args.output_file, results)
            logger.info(f"[*] Results saved to JSON: {args.output_file}")
        else:
            save_results_csv(args.output_file, results)
            logger.info(f"[*] Results saved to CSV: {args.output_file}")
    else:
        print("[*] No output file or format specified. Skipping file export.")

    print("\n[*] Done. Exiting.")


if __name__ == "__main__":
    main()
