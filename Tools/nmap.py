"""Comprehensive Nmap wrapper and output cleaner designed for AI agents."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Optional, Sequence, Union


TargetType = Union[str, Sequence[str]]


class Nmap:
    """Agent-friendly Python wrapper around the Nmap CLI.

    Provides dedicated methods for all major Nmap scan types (host discovery,
    TCP/UDP/IP port scans, service/OS detection, NSE scripting, firewall
    evasion, and custom flags) along with an output cleaner that parses Nmap
    XML or plain-text output into compact, structured data for an AI agent.
    """

    # Lines commonly emitted by Nmap that add token noise without analytical value
    _NOISE_PATTERNS = (
        re.compile(r"^Starting Nmap\b.*", re.IGNORECASE),
        re.compile(r"^Service detection performed\. Please report.*", re.IGNORECASE),
        re.compile(r"^OS detection performed\. Please report.*", re.IGNORECASE),
        re.compile(r"^OS and Service detection performed\. Please report.*", re.IGNORECASE),
        re.compile(r"^Read data files from:.*", re.IGNORECASE),
        re.compile(r"^Note: Host seems down\. If it is really up.*", re.IGNORECASE),
        re.compile(r"^SF[-:].*"),
        re.compile(r"^=+\s*NEXT SERVICE FINGERPRINT.*", re.IGNORECASE),
        re.compile(r"^=+\s*END SERVICE FINGERPRINT.*", re.IGNORECASE),
        re.compile(r"^TRACEROUTE \(using .*\)$", re.IGNORECASE),
    )

    _PRIVILEGE_ERROR_MARKERS = (
        "requires root privileges",
        "operation not permitted",
        "you requested a scan type which requires root",
        "dnet: failed to open device",
    )

    _OUTPUT_FLAGS = {"-oN", "-oX", "-oS", "-oG", "-oA"}

    def __init__(
        self,
        nmap_path: str = "nmap",
        timeout: int = 300,
        use_sudo: bool = False,
        default_timing: Optional[int] = None,
        output_format: str = "dict",
    ) -> None:
        """Initialize the Nmap tool.

        Args:
            nmap_path: Path or binary name for nmap (default: "nmap").
            timeout: Default per-scan timeout in seconds (default: 300).
            use_sudo: Prefix commands with ``sudo -n`` for privileged scans.
            default_timing: Optional default timing template (0 to 5 for -T0..-T5).
            output_format: Return format for scans: ``"dict"`` (default),
                ``"json"``, or ``"text"``.
        """
        if output_format not in {"dict", "json", "text"}:
            raise ValueError("output_format must be one of 'dict', 'json', or 'text'.")
        if default_timing is not None:
            self._validate_timing(default_timing)

        self.nmap_path = nmap_path
        self.timeout = timeout
        self.use_sudo = use_sudo
        self.default_timing = default_timing
        self.output_format = output_format

    # ------------------------------------------------------------------
    # Validation & Command Building Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_targets(target: TargetType) -> list[str]:
        """Validate and normalize one or more targets (IP, CIDR, range, hostname)."""
        if isinstance(target, str):
            targets = target.split()
        elif isinstance(target, Iterable):
            targets = [str(t).strip() for t in target if str(t).strip()]
        else:
            raise ValueError("target must be a string or iterable of target strings.")

        if not targets:
            raise ValueError("At least one scan target must be provided.")

        for item in targets:
            if item.startswith("-"):
                raise ValueError(
                    f"Invalid target '{item}': targets must not start with '-'."
                )
        return targets

    @staticmethod
    def _validate_timing(timing: Union[int, str]) -> str:
        """Validate timing template (0..5 or 'T0'..'T5') and return '-T<n>'."""
        if isinstance(timing, str):
            cleaned = timing.strip().upper()
            if cleaned.startswith("-T"):
                cleaned = cleaned[2:]
            elif cleaned.startswith("T"):
                cleaned = cleaned[1:]
            if not cleaned.isdigit():
                raise ValueError(f"Invalid timing template: {timing!r}. Expected 0-5.")
            level = int(cleaned)
        elif isinstance(timing, int):
            level = timing
        else:
            raise ValueError(f"Invalid timing template: {timing!r}. Expected 0-5.")

        if not 0 <= level <= 5:
            raise ValueError(f"Timing template must be between 0 and 5, got {level}.")
        return f"-T{level}"

    @staticmethod
    def _validate_ports(ports: Union[int, str, Sequence[int]]) -> str:
        """Normalize ports specification (e.g. 80, '22,80,443', '1-1000', '-')."""
        if isinstance(ports, int):
            if not 1 <= ports <= 65535:
                raise ValueError(f"Port number must be 1-65535, got {ports}.")
            return str(ports)
        if isinstance(ports, str):
            cleaned = ports.strip()
            if not cleaned:
                raise ValueError("ports string cannot be empty.")
            if cleaned != "-" and not re.fullmatch(r"[0-9,\-:TUSPtusp]+", cleaned):
                raise ValueError(f"Invalid port specification: {ports!r}.")
            return cleaned
        if isinstance(ports, Iterable):
            port_list = []
            for p in ports:
                num = int(p)
                if not 1 <= num <= 65535:
                    raise ValueError(f"Port number must be 1-65535, got {num}.")
                port_list.append(str(num))
            if not port_list:
                raise ValueError("ports sequence cannot be empty.")
            return ",".join(port_list)
        raise ValueError(f"Unsupported ports type: {type(ports).__name__}.")

    def _build_command(
        self,
        target: TargetType,
        args: Optional[Sequence[str]] = None,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        ipv6: bool = False,
        interface: Optional[str] = None,
        exclude: Optional[TargetType] = None,
        extra_args: Optional[Union[str, Sequence[str]]] = None,
        use_xml: bool = True,
    ) -> list[str]:
        """Construct the complete nmap argument vector safely (no shell)."""
        targets = self._normalize_targets(target)
        cmd: list[str] = []

        if self.use_sudo:
            cmd.extend(["sudo", "-n"])

        cmd.append(self.nmap_path)

        flag_list: list[str] = list(args) if args else []

        if extra_args:
            if isinstance(extra_args, str):
                flag_list.extend(shlex.split(extra_args))
            else:
                flag_list.extend(str(a) for a in extra_args)

        if ipv6 and "-6" not in flag_list:
            flag_list.append("-6")

        effective_timing = timing if timing is not None else self.default_timing
        if effective_timing is not None and not any(
            f.startswith("-T") for f in flag_list
        ):
            flag_list.append(self._validate_timing(effective_timing))

        if ports is not None:
            port_spec = self._validate_ports(ports)
            if port_spec == "-":
                flag_list.append("-p-")
            else:
                flag_list.extend(["-p", port_spec])

        if interface:
            flag_list.extend(["-e", interface])

        if exclude:
            excluded_targets = self._normalize_targets(exclude)
            flag_list.extend(["--exclude", ",".join(excluded_targets)])

        has_output_flag = any(
            f in self._OUTPUT_FLAGS or f.startswith(("-oN", "-oX", "-oS", "-oG", "-oA"))
            for f in flag_list
        )
        if use_xml and not has_output_flag:
            flag_list.extend(["-oX", "-"])

        cmd.extend(flag_list)
        cmd.extend(targets)
        return cmd

    def _format_return(self, cleaned: dict[str, Any]) -> Union[dict[str, Any], str]:
        """Format cleaned scan output according to ``self.output_format``."""
        if self.output_format == "json":
            return json.dumps(cleaned, indent=2)
        if self.output_format == "text":
            return self.format_summary(cleaned)
        return cleaned

    # ------------------------------------------------------------------
    # Core Execution
    # ------------------------------------------------------------------

    def check_available(self) -> dict[str, Any]:
        """Check whether Nmap is installed and return its version string."""
        resolved = shutil.which(self.nmap_path)
        if not resolved:
            return {
                "available": False,
                "path": self.nmap_path,
                "error": f"Nmap binary not found: {self.nmap_path}",
            }

        try:
            proc = subprocess.run(
                [resolved, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            first_line = (proc.stdout or proc.stderr).strip().splitlines()
            return {
                "available": proc.returncode == 0,
                "path": resolved,
                "version": first_line[0] if first_line else "",
                **({"error": proc.stderr.strip()} if proc.returncode != 0 else {}),
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {
                "available": False,
                "path": resolved,
                "error": str(exc),
            }

    def run_scan(
        self,
        target: TargetType,
        args: Optional[Sequence[str]] = None,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        ipv6: bool = False,
        interface: Optional[str] = None,
        exclude: Optional[TargetType] = None,
        extra_args: Optional[Union[str, Sequence[str]]] = None,
        timeout: Optional[int] = None,
        use_xml: bool = True,
        include_down_hosts: bool = False,
        include_closed_ports: bool = False,
    ) -> Union[dict[str, Any], str]:
        """Execute an Nmap scan and return cleaned, agent-ready output."""
        cmd = self._build_command(
            target=target,
            args=args,
            ports=ports,
            timing=timing,
            ipv6=ipv6,
            interface=interface,
            exclude=exclude,
            extra_args=extra_args,
            use_xml=use_xml,
        )
        effective_timeout = timeout if timeout is not None else self.timeout

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
            cleaned = self.clean_output(
                {
                    "STDOUT": proc.stdout,
                    "STDERR": proc.stderr,
                    "RETURN_CODE": proc.returncode,
                    "COMMAND": " ".join(cmd),
                },
                include_down_hosts=include_down_hosts,
                include_closed_ports=include_closed_ports,
            )
            return self._format_return(cleaned)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            cleaned = {
                "status": "timeout",
                "command": " ".join(cmd),
                "error": f"Nmap scan timed out after {effective_timeout} seconds.",
                "hosts": [],
            }
            if stdout.strip():
                partial = self.clean_output({"STDOUT": stdout, "STDERR": stderr})
                if partial.get("hosts"):
                    cleaned["hosts"] = partial["hosts"]
            return self._format_return(cleaned)
        except FileNotFoundError:
            cleaned = {
                "status": "error",
                "command": " ".join(cmd),
                "error": f"Nmap executable '{self.nmap_path}' not found in PATH.",
                "hosts": [],
            }
            return self._format_return(cleaned)
        except PermissionError as exc:
            cleaned = {
                "status": "error",
                "command": " ".join(cmd),
                "error": f"Permission denied executing Nmap: {exc}",
                "hint": "Check execute permissions or run with appropriate privileges.",
                "hosts": [],
            }
            return self._format_return(cleaned)

    def custom_scan(
        self,
        target: TargetType,
        flags: Union[str, Sequence[str]],
        timeout: Optional[int] = None,
        use_xml: bool = True,
    ) -> Union[dict[str, Any], str]:
        """Run Nmap with arbitrary user/agent-supplied flags."""
        parsed_flags = shlex.split(flags) if isinstance(flags, str) else list(flags)
        return self.run_scan(
            target=target,
            args=parsed_flags,
            timeout=timeout,
            use_xml=use_xml,
        )

    # ------------------------------------------------------------------
    # Host Discovery Scans
    # ------------------------------------------------------------------

    def ping_scan(
        self,
        target: TargetType,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Host discovery only without port scanning (-sn)."""
        return self.run_scan(target, args=["-sn"], timing=timing, timeout=timeout)

    def arp_discovery(
        self,
        target: TargetType,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Fast local-network ARP host discovery (-sn -PR)."""
        return self.run_scan(target, args=["-sn", "-PR"], timing=timing, timeout=timeout)

    def list_scan(
        self,
        target: TargetType,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """List targets and perform reverse-DNS resolution without probing (-sL)."""
        return self.run_scan(
            target,
            args=["-sL"],
            timeout=timeout,
            include_down_hosts=True,
        )

    def no_ping_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Skip host discovery and treat all targets as online (-Pn)."""
        return self.run_scan(
            target,
            args=["-Pn"],
            ports=ports,
            timing=timing,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Standard & Port Scans
    # ------------------------------------------------------------------

    def basic_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Default Nmap scan (top 1000 TCP ports, or specified ports)."""
        return self.run_scan(target, ports=ports, timing=timing, timeout=timeout)

    def quick_scan(
        self,
        target: TargetType,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Fast scan of the top 100 most common ports (-T4 -F)."""
        return self.run_scan(target, args=["-F"], timing=4, timeout=timeout)

    def top_ports_scan(
        self,
        target: TargetType,
        top_n: int = 100,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Scan the ``top_n`` most common ports (--top-ports)."""
        if top_n < 1:
            raise ValueError("top_n must be a positive integer.")
        return self.run_scan(
            target,
            args=["--top-ports", str(top_n)],
            timing=timing,
            timeout=timeout,
        )

    def port_scan(
        self,
        target: TargetType,
        ports: Union[int, str, Sequence[int]],
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Scan specific port(s) or port ranges (-p)."""
        return self.run_scan(target, ports=ports, timing=timing, timeout=timeout)

    def full_port_scan(
        self,
        target: TargetType,
        timing: Optional[Union[int, str]] = 4,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Scan all 65,535 TCP ports (-p-)."""
        return self.run_scan(target, ports="-", timing=timing, timeout=timeout)

    # ------------------------------------------------------------------
    # TCP / UDP / Protocol Scan Techniques
    # ------------------------------------------------------------------

    def syn_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Half-open TCP SYN stealth scan (-sS). Requires root privileges."""
        return self.run_scan(
            target, args=["-sS"], ports=ports, timing=timing, timeout=timeout
        )

    def tcp_connect_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Full TCP connect scan (-sT). Works without root privileges."""
        return self.run_scan(
            target, args=["-sT"], ports=ports, timing=timing, timeout=timeout
        )

    def udp_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        top_n: Optional[int] = 100,
        timing: Optional[Union[int, str]] = 4,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """UDP port scan (-sU). Defaults to top 100 UDP ports unless ``ports`` is set."""
        args = ["-sU"]
        if ports is None and top_n is not None:
            if top_n < 1:
                raise ValueError("top_n must be a positive integer.")
            args.extend(["--top-ports", str(top_n)])
        return self.run_scan(
            target, args=args, ports=ports, timing=timing, timeout=timeout
        )

    def ack_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """TCP ACK scan (-sA) to map firewall rulesets (filtered vs unfiltered)."""
        return self.run_scan(
            target, args=["-sA"], ports=ports, timing=timing, timeout=timeout
        )

    def window_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """TCP Window scan (-sW)."""
        return self.run_scan(
            target, args=["-sW"], ports=ports, timing=timing, timeout=timeout
        )

    def fin_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """TCP FIN stealth scan (-sF)."""
        return self.run_scan(
            target, args=["-sF"], ports=ports, timing=timing, timeout=timeout
        )

    def null_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """TCP NULL stealth scan (-sN)."""
        return self.run_scan(
            target, args=["-sN"], ports=ports, timing=timing, timeout=timeout
        )

    def xmas_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """TCP Xmas stealth scan (-sX)."""
        return self.run_scan(
            target, args=["-sX"], ports=ports, timing=timing, timeout=timeout
        )

    def ip_protocol_scan(
        self,
        target: TargetType,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Determine supported IP protocols on target host(s) (-sO)."""
        return self.run_scan(target, args=["-sO"], timing=timing, timeout=timeout)

    # ------------------------------------------------------------------
    # Service, Version, OS & Comprehensive Scans
    # ------------------------------------------------------------------

    def service_version_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        intensity: Optional[int] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Probe open ports to determine service and version info (-sV)."""
        args = ["-sV"]
        if intensity is not None:
            if not 0 <= intensity <= 9:
                raise ValueError("version intensity must be between 0 and 9.")
            args.extend(["--version-intensity", str(intensity)])
        return self.run_scan(
            target, args=args, ports=ports, timing=timing, timeout=timeout
        )

    def os_detection_scan(
        self,
        target: TargetType,
        guess: bool = False,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Enable OS fingerprinting (-O, optionally --osscan-guess). Requires root."""
        args = ["-O"]
        if guess:
            args.append("--osscan-guess")
        return self.run_scan(target, args=args, timing=timing, timeout=timeout)

    def detailed_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        include_os: bool = False,
        all_ports: bool = False,
        timing: Optional[Union[int, str]] = 4,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Detailed enumeration scan (-sC -sV, optionally -O and -p-)."""
        args = ["-sC", "-sV"]
        if include_os:
            args.append("-O")
        effective_ports = "-" if (all_ports and ports is None) else ports
        return self.run_scan(
            target,
            args=args,
            ports=effective_ports,
            timing=timing,
            timeout=timeout,
        )

    def aggressive_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = 4,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Aggressive scan (-A): OS detection, version detection, default scripts, traceroute."""
        return self.run_scan(
            target, args=["-A"], ports=ports, timing=timing, timeout=timeout
        )

    def traceroute_scan(
        self,
        target: TargetType,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Trace hop path to each host (--traceroute)."""
        return self.run_scan(
            target, args=["--traceroute"], timing=timing, timeout=timeout
        )

    # ------------------------------------------------------------------
    # NSE (Nmap Scripting Engine) Scans
    # ------------------------------------------------------------------

    def default_script_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Run Nmap's default safe NSE scripts (-sC)."""
        return self.run_scan(
            target, args=["-sC"], ports=ports, timing=timing, timeout=timeout
        )

    def script_scan(
        self,
        target: TargetType,
        scripts: Union[str, Sequence[str]],
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        script_args: Optional[Union[str, dict[str, Any]]] = None,
        version_detection: bool = False,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Run specific NSE script(s) or categories (--script)."""
        script_spec = (
            scripts.strip()
            if isinstance(scripts, str)
            else ",".join(s.strip() for s in scripts if s.strip())
        )
        if not script_spec:
            raise ValueError("At least one NSE script or category must be specified.")

        args = []
        if version_detection:
            args.append("-sV")
        args.extend(["--script", script_spec])

        if script_args:
            if isinstance(script_args, dict):
                formatted = ",".join(f"{k}={v}" for k, v in script_args.items())
            else:
                formatted = str(script_args)
            args.extend(["--script-args", formatted])

        return self.run_scan(
            target, args=args, ports=ports, timing=timing, timeout=timeout
        )

    def vuln_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = 4,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Run vulnerability detection NSE scripts (-sV --script vuln)."""
        return self.script_scan(
            target=target,
            scripts="vuln",
            ports=ports,
            version_detection=True,
            timing=timing,
            timeout=timeout,
        )

    def banner_grab(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Grab service banners from open ports (--script banner)."""
        return self.script_scan(
            target=target,
            scripts="banner",
            ports=ports,
            timing=timing,
            timeout=timeout,
        )

    def ssl_scan(
        self,
        target: TargetType,
        ports: Union[int, str, Sequence[int]] = "443",
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Inspect SSL/TLS certificates and supported ciphers."""
        return self.script_scan(
            target=target,
            scripts=["ssl-cert", "ssl-enum-ciphers"],
            ports=ports,
            version_detection=True,
            timing=timing,
            timeout=timeout,
        )

    def http_enum_scan(
        self,
        target: TargetType,
        ports: Union[int, str, Sequence[int]] = "80,443,8080,8443",
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Enumerate web services (titles, headers, methods, common paths)."""
        return self.script_scan(
            target=target,
            scripts=["http-title", "http-headers", "http-methods", "http-enum"],
            ports=ports,
            version_detection=True,
            timing=timing,
            timeout=timeout,
        )

    def smb_enum_scan(
        self,
        target: TargetType,
        ports: Union[int, str, Sequence[int]] = "139,445",
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Enumerate SMB OS details, shares, and security modes."""
        return self.script_scan(
            target=target,
            scripts=[
                "smb-os-discovery",
                "smb-enum-shares",
                "smb-security-mode",
                "smb2-security-mode",
            ],
            ports=ports,
            timing=timing,
            timeout=timeout,
        )

    def dns_enum_scan(
        self,
        target: TargetType,
        ports: Union[int, str, Sequence[int]] = "53",
        timing: Optional[Union[int, str]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Enumerate DNS server capabilities and service discovery info."""
        return self.script_scan(
            target=target,
            scripts=["dns-nsid", "dns-recursion", "dns-service-discovery"],
            ports=ports,
            version_detection=True,
            timing=timing,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Firewall / IDS Evasion & Stealth Scans
    # ------------------------------------------------------------------

    def firewall_evasion_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        fragment: bool = True,
        mtu: Optional[int] = None,
        decoys: Optional[Union[str, Sequence[str]]] = None,
        source_port: Optional[int] = None,
        data_length: Optional[int] = None,
        timing: Optional[Union[int, str]] = 2,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Scan with firewall/IDS evasion options (-f/--mtu, -D, --source-port, --data-length)."""
        args: list[str] = []
        if mtu is not None:
            if mtu <= 0 or mtu % 8 != 0:
                raise ValueError("mtu must be a positive multiple of 8.")
            args.extend(["--mtu", str(mtu)])
        elif fragment:
            args.append("-f")

        if decoys:
            decoy_str = (
                decoys if isinstance(decoys, str) else ",".join(str(d) for d in decoys)
            )
            args.extend(["-D", decoy_str])

        if source_port is not None:
            if not 1 <= source_port <= 65535:
                raise ValueError("source_port must be between 1 and 65535.")
            args.extend(["--source-port", str(source_port)])

        if data_length is not None:
            if data_length < 0:
                raise ValueError("data_length must be non-negative.")
            args.extend(["--data-length", str(data_length)])

        return self.run_scan(
            target, args=args, ports=ports, timing=timing, timeout=timeout
        )

    def stealth_scan(
        self,
        target: TargetType,
        ports: Optional[Union[int, str, Sequence[int]]] = None,
        timeout: Optional[int] = None,
    ) -> Union[dict[str, Any], str]:
        """Low-and-slow fragmented SYN scan (-sS -T2 -f). Requires root privileges."""
        return self.run_scan(
            target,
            args=["-sS", "-f"],
            ports=ports,
            timing=2,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Output Cleaning & Formatting for Agents
    # ------------------------------------------------------------------

    def clean_output(
        self,
        output: Union[dict[str, Any], str],
        include_down_hosts: bool = False,
        include_closed_ports: bool = False,
    ) -> dict[str, Any]:
        """Clean raw Nmap output (XML or plain text) into compact structured data.

        Accepts either:
        - A dictionary with ``"STDOUT"`` and optional ``"STDERR"``,
          ``"RETURN_CODE"``, ``"COMMAND"`` keys.
        - A raw string containing Nmap XML or plain-text output.

        Returns a clean, JSON-serializable dictionary stripped of banners,
        boilerplate notices, and closed-port spam, optimized for LLM consumption.
        """
        if isinstance(output, str):
            stdout = output
            stderr = ""
            return_code: Optional[int] = None
            command = ""
        elif isinstance(output, dict):
            stdout = str(output.get("STDOUT") or output.get("stdout") or "")
            stderr = str(output.get("STDERR") or output.get("stderr") or "")
            return_code = output.get("RETURN_CODE", output.get("returncode"))
            command = str(output.get("COMMAND") or output.get("command") or "")
        else:
            raise TypeError("output must be a dict or str.")

        warnings, errors = self._clean_stderr(stderr)

        stripped_stdout = stdout.strip()
        if "<nmaprun" in stripped_stdout:
            result = self._parse_xml_output(
                stripped_stdout,
                include_down_hosts=include_down_hosts,
                include_closed_ports=include_closed_ports,
            )
        else:
            result = self._parse_text_output(
                stripped_stdout,
                include_down_hosts=include_down_hosts,
                include_closed_ports=include_closed_ports,
            )

        if command and not result.get("command"):
            result["command"] = command

        if warnings:
            result["warnings"] = warnings

        if errors:
            result["errors"] = errors
            if any(
                marker in " ".join(errors).lower()
                for marker in self._PRIVILEGE_ERROR_MARKERS
            ):
                result["hint"] = (
                    "This scan requires root privileges. Initialize Nmap(use_sudo=True) "
                    "or use an unprivileged scan such as tcp_connect_scan (-sT)."
                )

        if return_code is not None and return_code != 0:
            if not result.get("hosts"):
                result["status"] = "error"
            elif result.get("status") == "success":
                result["status"] = "partial"
            result["return_code"] = return_code
        elif errors and not result.get("hosts"):
            result["status"] = "error"

        return result

    def _parse_xml_output(
        self,
        xml_text: str,
        include_down_hosts: bool = False,
        include_closed_ports: bool = False,
    ) -> dict[str, Any]:
        """Parse Nmap XML (-oX -) output into a clean dictionary."""
        start_idx = xml_text.find("<?xml")
        if start_idx == -1:
            start_idx = xml_text.find("<nmaprun")
        xml_slice = xml_text[start_idx:]

        try:
            root = ET.fromstring(xml_slice)
        except ET.ParseError as exc:
            fallback = self._parse_text_output(
                xml_text,
                include_down_hosts=include_down_hosts,
                include_closed_ports=include_closed_ports,
            )
            fallback["parse_warning"] = f"Incomplete or invalid Nmap XML: {exc}"
            return fallback

        result: dict[str, Any] = {
            "status": "success",
            "command": root.attrib.get("args", ""),
            "hosts": [],
        }

        # Run statistics
        runstats = root.find("runstats")
        if runstats is not None:
            stats: dict[str, Any] = {}
            finished = runstats.find("finished")
            if finished is not None:
                if finished.attrib.get("elapsed"):
                    stats["elapsed_seconds"] = float(finished.attrib["elapsed"])
                if finished.attrib.get("summary"):
                    result["summary"] = finished.attrib["summary"]
                if finished.attrib.get("exit") == "error":
                    result["status"] = "error"
                    if finished.attrib.get("errormsg"):
                        result["error"] = finished.attrib["errormsg"]
            hosts_el = runstats.find("hosts")
            if hosts_el is not None:
                stats["hosts_up"] = int(hosts_el.attrib.get("up", 0))
                stats["hosts_down"] = int(hosts_el.attrib.get("down", 0))
                stats["hosts_total"] = int(hosts_el.attrib.get("total", 0))
            if stats:
                result["stats"] = stats

        # Parse hosts
        parsed_hosts: list[dict[str, Any]] = []
        for host_el in root.findall("host"):
            host_data = self._parse_xml_host(
                host_el, include_closed_ports=include_closed_ports
            )
            state = host_data.get("state", "")
            if state == "down" and not include_down_hosts:
                continue
            parsed_hosts.append(host_data)

        result["hosts"] = parsed_hosts
        return result

    def _parse_xml_host(
        self,
        host_el: ET.Element,
        include_closed_ports: bool = False,
    ) -> dict[str, Any]:
        """Extract clean host fields from a single <host> XML element."""
        host: dict[str, Any] = {}

        # Status
        status_el = host_el.find("status")
        if status_el is not None:
            host["state"] = status_el.attrib.get("state", "unknown")
            reason = status_el.attrib.get("reason")
            if reason and reason not in {"user-set", "syn-ack", "echo-reply"}:
                host["state_reason"] = reason

        # Addresses
        for addr_el in host_el.findall("address"):
            addr_type = addr_el.attrib.get("addrtype", "")
            addr = addr_el.attrib.get("addr", "")
            if addr_type == "ipv4":
                host["ip"] = addr
            elif addr_type == "ipv6":
                host["ipv6"] = addr
            elif addr_type == "mac":
                host["mac"] = addr
                if addr_el.attrib.get("vendor"):
                    host["vendor"] = addr_el.attrib["vendor"]

        # Hostnames (deduplicated, order-preserving)
        hostnames: list[str] = []
        for hn_el in host_el.findall("./hostnames/hostname"):
            name = hn_el.attrib.get("name", "").strip()
            if name and name not in hostnames:
                hostnames.append(name)
        if hostnames:
            host["hostnames"] = hostnames

        # Ports & extraports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            port_summary: dict[str, int] = {}
            for extra_el in ports_el.findall("extraports"):
                state = extra_el.attrib.get("state", "unknown")
                count = int(extra_el.attrib.get("count", 0))
                if count > 0:
                    port_summary[state] = port_summary.get(state, 0) + count

            ports_list: list[dict[str, Any]] = []
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"

                if state == "closed" and not include_closed_ports:
                    port_summary["closed"] = port_summary.get("closed", 0) + 1
                    continue

                port_info: dict[str, Any] = {
                    "port": int(port_el.attrib["portid"]),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state": state,
                }

                service_el = port_el.find("service")
                if service_el is not None:
                    svc_name = service_el.attrib.get("name")
                    if svc_name:
                        port_info["service"] = svc_name
                    for attr, key in (
                        ("product", "product"),
                        ("version", "version"),
                        ("extrainfo", "extra_info"),
                        ("tunnel", "tunnel"),
                    ):
                        val = service_el.attrib.get(attr)
                        if val:
                            port_info[key] = val
                    cpes = [
                        cpe.text.strip()
                        for cpe in service_el.findall("cpe")
                        if cpe.text and cpe.text.strip()
                    ]
                    if cpes:
                        port_info["cpe"] = cpes

                port_scripts: dict[str, str] = {}
                for script_el in port_el.findall("script"):
                    sid = script_el.attrib.get("id", "")
                    sout = self._clean_script_text(script_el.attrib.get("output", ""))
                    if sid and sout:
                        port_scripts[sid] = sout
                if port_scripts:
                    port_info["scripts"] = port_scripts

                ports_list.append(port_info)

            if ports_list:
                host["ports"] = ports_list
            if port_summary:
                host["port_summary"] = port_summary

        # OS detection (keep top 3 matches to avoid noise)
        os_el = host_el.find("os")
        if os_el is not None:
            os_matches: list[dict[str, Any]] = []
            for match in os_el.findall("osmatch")[:3]:
                entry: dict[str, Any] = {
                    "name": match.attrib.get("name", ""),
                    "accuracy": int(match.attrib.get("accuracy", 0)),
                }
                osclass = match.find("osclass")
                if osclass is not None:
                    if osclass.attrib.get("osfamily"):
                        entry["family"] = osclass.attrib["osfamily"]
                    if osclass.attrib.get("osgen"):
                        entry["generation"] = osclass.attrib["osgen"]
                if entry["name"]:
                    os_matches.append(entry)
            if os_matches:
                host["os"] = os_matches

        # Host-level NSE scripts
        host_scripts: dict[str, str] = {}
        for script_el in host_el.findall("./hostscript/script"):
            sid = script_el.attrib.get("id", "")
            sout = self._clean_script_text(script_el.attrib.get("output", ""))
            if sid and sout:
                host_scripts[sid] = sout
        if host_scripts:
            host["host_scripts"] = host_scripts

        # Distance & uptime
        distance_el = host_el.find("distance")
        if distance_el is not None and distance_el.attrib.get("value"):
            host["distance_hops"] = int(distance_el.attrib["value"])

        uptime_el = host_el.find("uptime")
        if uptime_el is not None and uptime_el.attrib.get("seconds"):
            host["uptime_seconds"] = int(uptime_el.attrib["seconds"])

        # Traceroute
        trace_el = host_el.find("trace")
        if trace_el is not None:
            hops: list[dict[str, Any]] = []
            for hop_el in trace_el.findall("hop"):
                hop: dict[str, Any] = {"ttl": int(hop_el.attrib.get("ttl", 0))}
                if hop_el.attrib.get("ipaddr"):
                    hop["ip"] = hop_el.attrib["ipaddr"]
                if hop_el.attrib.get("host"):
                    hop["host"] = hop_el.attrib["host"]
                if hop_el.attrib.get("rtt"):
                    hop["rtt_ms"] = float(hop_el.attrib["rtt"])
                hops.append(hop)
            if hops:
                host["traceroute"] = hops

        return host

    def _parse_text_output(
        self,
        text: str,
        include_down_hosts: bool = False,
        include_closed_ports: bool = False,
    ) -> dict[str, Any]:
        """Fallback parser for standard plain-text Nmap output."""
        result: dict[str, Any] = {
            "status": "success",
            "hosts": [],
        }
        if not text:
            return result

        current_host: Optional[dict[str, Any]] = None
        current_port: Optional[dict[str, Any]] = None
        current_script_target: Optional[dict[str, str]] = None
        current_script_id: Optional[str] = None
        in_host_scripts = False
        unparsed_lines: list[str] = []

        host_re = re.compile(
            r"^Nmap scan report for\s+(?:(?P<hostname>[^\s()]+)\s+\((?P<ip_in_paren>[^)]+)\)|(?P<ip_only>\S+))(?:\s+\[host down\])?$"
        )
        port_re = re.compile(
            r"^(?P<port>\d+)/(?P<proto>tcp|udp|sctp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.+))?$"
        )
        not_shown_re = re.compile(
            r"^Not shown:\s+(?P<count>\d+)\s+(?P<state>closed|filtered|open\|filtered)\b",
            re.IGNORECASE,
        )
        mac_re = re.compile(r"^MAC Address:\s+(?P<mac>[0-9A-Fa-f:]+)(?:\s+\((?P<vendor>[^)]+)\))?")
        done_re = re.compile(
            r"^Nmap done:\s+(?P<total>\d+)\s+IP address(?:es)?\s+\((?P<up>\d+)\s+hosts?\s+up\)\s+scanned in\s+(?P<elapsed>[0-9.]+)\s+seconds"
        )
        script_re = re.compile(r"^\|[_\s]\s*(?P<body>.+)$")

        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            if any(pat.match(stripped) for pat in self._NOISE_PATTERNS):
                continue

            done_match = done_re.match(stripped)
            if done_match:
                total = int(done_match.group("total"))
                up = int(done_match.group("up"))
                result["stats"] = {
                    "hosts_total": total,
                    "hosts_up": up,
                    "hosts_down": max(0, total - up),
                    "elapsed_seconds": float(done_match.group("elapsed")),
                }
                result["summary"] = stripped
                continue

            host_match = host_re.match(stripped)
            if host_match:
                if current_host is not None:
                    if current_host.get("state") != "down" or include_down_hosts:
                        result["hosts"].append(current_host)
                is_down = "[host down]" in stripped.lower()
                current_host = {"state": "down" if is_down else "up"}
                if host_match.group("ip_in_paren"):
                    current_host["ip"] = host_match.group("ip_in_paren")
                    current_host["hostnames"] = [host_match.group("hostname")]
                else:
                    target_val = host_match.group("ip_only")
                    if re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", target_val):
                        current_host["ip"] = target_val
                    else:
                        current_host["hostnames"] = [target_val]
                current_port = None
                current_script_target = None
                current_script_id = None
                in_host_scripts = False
                continue

            if current_host is None:
                unparsed_lines.append(stripped)
                continue

            if stripped.startswith("Host is "):
                current_host["state"] = "up" if "Host is up" in stripped else "down"
                continue

            if stripped.startswith("PORT ") and "STATE" in stripped:
                in_host_scripts = False
                continue

            if stripped.startswith("Host script results:"):
                in_host_scripts = True
                current_port = None
                current_script_id = None
                continue

            not_shown_match = not_shown_re.match(stripped)
            if not_shown_match:
                ps = current_host.setdefault("port_summary", {})
                st = not_shown_match.group("state").lower()
                ps[st] = ps.get(st, 0) + int(not_shown_match.group("count"))
                continue

            port_match = port_re.match(stripped)
            if port_match:
                in_host_scripts = False
                state = port_match.group("state")
                if state == "closed" and not include_closed_ports:
                    ps = current_host.setdefault("port_summary", {})
                    ps["closed"] = ps.get("closed", 0) + 1
                    current_port = None
                    continue
                port_entry: dict[str, Any] = {
                    "port": int(port_match.group("port")),
                    "protocol": port_match.group("proto"),
                    "state": state,
                    "service": port_match.group("service"),
                }
                if port_match.group("version"):
                    port_entry["version"] = port_match.group("version").strip()
                current_host.setdefault("ports", []).append(port_entry)
                current_port = port_entry
                current_script_id = None
                continue

            script_match = script_re.match(stripped)
            if script_match:
                body = script_match.group("body").strip()
                if in_host_scripts:
                    current_script_target = current_host.setdefault("host_scripts", {})
                elif current_port is not None:
                    current_script_target = current_port.setdefault("scripts", {})
                else:
                    current_script_target = current_host.setdefault("host_scripts", {})

                if ":" in body and not stripped.startswith("|   "):
                    key, val = body.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    if re.fullmatch(r"[a-zA-Z0-9._-]+", key):
                        current_script_id = key
                        current_script_target[key] = val
                        continue
                if current_script_id and current_script_target is not None:
                    existing = current_script_target.get(current_script_id, "")
                    current_script_target[current_script_id] = (
                        f"{existing}\n{body}".strip() if existing else body
                    )
                continue

            mac_match = mac_re.match(stripped)
            if mac_match:
                current_host["mac"] = mac_match.group("mac")
                if mac_match.group("vendor"):
                    current_host["vendor"] = mac_match.group("vendor")
                continue

            if stripped.startswith(("OS details:", "Aggressive OS guesses:", "Running:")):
                label, val = stripped.split(":", 1)
                current_host.setdefault("os_info", {})[label.strip().lower().replace(" ", "_")] = val.strip()
                continue

            if stripped.startswith("Service Info:"):
                current_host["service_info"] = stripped.split(":", 1)[1].strip()
                continue

        if current_host is not None:
            if current_host.get("state") != "down" or include_down_hosts:
                result["hosts"].append(current_host)

        if not result["hosts"] and unparsed_lines:
            result["raw_notes"] = unparsed_lines

        return result

    @staticmethod
    def _clean_script_text(text: str) -> str:
        """Normalize NSE script output by trimming noise and blank lines."""
        lines = [line.rstrip() for line in text.splitlines()]
        cleaned_lines = [line for line in lines if line.strip()]
        return "\n".join(cleaned_lines).strip()

    @staticmethod
    def _clean_stderr(stderr: str) -> tuple[list[str], list[str]]:
        """Split Nmap stderr into deduplicated warnings and errors."""
        warnings: list[str] = []
        errors: list[str] = []
        seen: set[str] = set()

        for raw_line in stderr.splitlines():
            line = raw_line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            if line.lower().startswith("warning:"):
                warnings.append(line[len("warning:"):].strip())
            else:
                errors.append(line)
        return warnings, errors

    @staticmethod
    def format_summary(cleaned: dict[str, Any]) -> str:
        """Render cleaned Nmap output into a concise LLM-readable text summary."""
        lines: list[str] = []
        status = cleaned.get("status", "unknown")
        if cleaned.get("summary"):
            lines.append(f"Summary: {cleaned['summary']}")
        else:
            lines.append(f"Status: {status}")

        if cleaned.get("error"):
            lines.append(f"Error: {cleaned['error']}")
        if cleaned.get("errors"):
            for err in cleaned["errors"]:
                lines.append(f"Error: {err}")
        if cleaned.get("hint"):
            lines.append(f"Hint: {cleaned['hint']}")
        if cleaned.get("warnings"):
            for warn in cleaned["warnings"]:
                lines.append(f"Warning: {warn}")

        hosts = cleaned.get("hosts", [])
        if not hosts and status == "success":
            lines.append("No active hosts found.")
            return "\n".join(lines)

        for host in hosts:
            ident = host.get("ip") or host.get("ipv6") or "unknown"
            hostnames = host.get("hostnames")
            if hostnames:
                ident = f"{ident} ({', '.join(hostnames)})"
            header = f"\nHost: {ident} [{host.get('state', 'unknown')}]"
            if host.get("mac"):
                vendor = f" ({host['vendor']})" if host.get("vendor") else ""
                header += f" MAC: {host['mac']}{vendor}"
            lines.append(header)

            if host.get("os"):
                top_os = ", ".join(
                    f"{o['name']} ({o['accuracy']}%)" for o in host["os"]
                )
                lines.append(f"  OS: {top_os}")

            if host.get("ports"):
                lines.append("  Ports:")
                for p in host["ports"]:
                    svc_parts = [p.get("service", "")]
                    if p.get("product"):
                        svc_parts.append(p["product"])
                    if p.get("version"):
                        svc_parts.append(p["version"])
                    if p.get("extra_info"):
                        svc_parts.append(f"({p['extra_info']})")
                    svc_desc = " ".join(part for part in svc_parts if part)
                    lines.append(
                        f"    - {p['port']}/{p['protocol']} {p['state']} {svc_desc}".rstrip()
                    )
                    for sid, sout in p.get("scripts", {}).items():
                        indented = sout.replace("\n", "\n        ")
                        lines.append(f"      [{sid}] {indented}")

            if host.get("port_summary"):
                summary_parts = [
                    f"{cnt} {st}" for st, cnt in host["port_summary"].items()
                ]
                lines.append(f"  Other ports: {', '.join(summary_parts)}")

            if host.get("host_scripts"):
                lines.append("  Host Scripts:")
                for sid, sout in host["host_scripts"].items():
                    indented = sout.replace("\n", "\n      ")
                    lines.append(f"    [{sid}] {indented}")

            if host.get("traceroute"):
                hops_str = " -> ".join(
                    h.get("host") or h.get("ip") or "*" for h in host["traceroute"]
                )
                lines.append(f"  Traceroute: {hops_str}")

        return "\n".join(lines).strip()

    # ------------------------------------------------------------------
    # AI Agent Tool Schema & Dispatcher
    # ------------------------------------------------------------------

    _DISPATCHABLE_ACTIONS = (
        "ping_scan",
        "arp_discovery",
        "list_scan",
        "no_ping_scan",
        "basic_scan",
        "quick_scan",
        "top_ports_scan",
        "port_scan",
        "full_port_scan",
        "syn_scan",
        "tcp_connect_scan",
        "udp_scan",
        "ack_scan",
        "window_scan",
        "fin_scan",
        "null_scan",
        "xmas_scan",
        "ip_protocol_scan",
        "service_version_scan",
        "os_detection_scan",
        "detailed_scan",
        "aggressive_scan",
        "traceroute_scan",
        "default_script_scan",
        "script_scan",
        "vuln_scan",
        "banner_grab",
        "ssl_scan",
        "http_enum_scan",
        "smb_enum_scan",
        "dns_enum_scan",
        "firewall_evasion_scan",
        "stealth_scan",
        "custom_scan",
    )

    def execute_tool(self, action: str, **kwargs: Any) -> Union[dict[str, Any], str]:
        """Dispatch an Nmap scan method by name for agent tool-calling."""
        if action not in self._DISPATCHABLE_ACTIONS:
            return self._format_return(
                {
                    "status": "error",
                    "error": f"Unknown Nmap action '{action}'.",
                    "available_actions": list(self._DISPATCHABLE_ACTIONS),
                    "hosts": [],
                }
            )
        method = getattr(self, action)
        try:
            return method(**kwargs)
        except (TypeError, ValueError) as exc:
            return self._format_return(
                {
                    "status": "error",
                    "action": action,
                    "error": f"Invalid arguments for '{action}': {exc}",
                    "hosts": [],
                }
            )

    @classmethod
    def get_tool_definition(cls) -> dict[str, Any]:
        """Return an OpenAI Responses API function-tool schema for this Nmap tool."""
        return {
            "type": "function",
            "name": "nmap_scan",
            "description": (
                "Run an Nmap network scan against a target IP, CIDR range, or hostname "
                "and return cleaned, structured results."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": list(cls._DISPATCHABLE_ACTIONS),
                        "description": "The Nmap scan type to perform.",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target IP, CIDR block, range, or hostname.",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional port list or range (e.g. '22,80,443', '1-1000', '-').",
                    },
                    "timing": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 5,
                        "description": "Optional Nmap timing template 0 (paranoid) to 5 (insane).",
                    },
                    "scripts": {
                        "type": "string",
                        "description": "NSE script name(s) or categories (required for script_scan).",
                    },
                    "script_args": {
                        "type": "string",
                        "description": "Optional --script-args string for script_scan.",
                    },
                    "flags": {
                        "type": "string",
                        "description": "Raw Nmap flags string (required for custom_scan).",
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top common ports for top_ports_scan or udp_scan.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional timeout override in seconds.",
                    },
                },
                "required": ["action", "target"],
            },
        }
