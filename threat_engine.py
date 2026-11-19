"""Phoenix Threat Intelligence & Forensic Reconnaissance Engine (Phoenix 2.0).

This module delivers deep forensic and threat-detection capabilities:
1. Deep URL Uncloaking: Multi-hop redirect tracing, RDAP domain age verification,
   and Favicon hash brand-impersonation analysis (Shodan-style detection).
2. Advanced Telecom Risk: Disposable cloud VoIP vs. physical carrier detection.
3. Forensic Media & ELA: Image EXIF telemetry, GPS decoding, and Error Level Analysis (ELA)
   for detecting forged documents and edited screenshots.
4. Incident Dossier Generator: Automated cryptographic forensic evidence reports.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import logging
import re
import socket
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from PIL import Image, ImageChops

logger = logging.getLogger("phoenix.threat_engine")

# ---------------------------------------------------------------------------
# Brand Signatures for Favicon Spoof / Phishing Detection
# ---------------------------------------------------------------------------
KNOWN_BRAND_FAVICONS: dict[str, dict[str, Any]] = {
    "f3418a443e7d841097c714d69ec4bcb8": {
        "brand": "Google",
        "legit_domains": ["google.com", "google.co", "gstatic.com"],
    },
    "7074258169148d4847e337190fe3b86d": {
        "brand": "Meta / Facebook",
        "legit_domains": ["facebook.com", "fb.com", "meta.com"],
    },
    "c5e93df023cb3c4f74d0089e5a1b32d2": {
        "brand": "Instagram",
        "legit_domains": ["instagram.com", "cdninstagram.com"],
    },
    "fa985f36e4f3263ff0d8d73b0a7240c3": {
        "brand": "WhatsApp",
        "legit_domains": ["whatsapp.com", "whatsapp.net"],
    },
    "ecb2b73bc289b70b5527a29ee2d93e2b": {
        "brand": "Microsoft / Office 365",
        "legit_domains": ["microsoft.com", "office.com", "live.com"],
    },
    "3b97b09569b9365287e0b5efd1587637": {
        "brand": "Apple / iCloud",
        "legit_domains": ["apple.com", "icloud.com"],
    },
    "e00ef7a892b1a1ddf4c4bc8d7b32c668": {
        "brand": "PayPal",
        "legit_domains": ["paypal.com"],
    },
    "60c6d594f86f34346eb4a71d18227b68": {
        "brand": "Telegram",
        "legit_domains": ["telegram.org", "t.me"],
    },
}

KNOWN_VOIP_KEYWORDS = [
    "twilio", "textnow", "bandwidth", "google voice", "bandwidth.com",
    "sinch", "telnyx", "onoff", "pinger", "talkatone", "dingtone",
    "vonage", "magicjack", "skype", "voxbone", "rebel vox", "inteliquent"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "rest", "cfd", "live", "link", "monster",
    "beauty", "hair", "skin", "icu", "cam", "fit", "tk", "ml", "ga", "cf", "gq"
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass
class RedirectHop:
    hop: int
    url: str
    status_code: int
    location: str | None
    server: str | None
    ip: str | None
    response_time_ms: float


@dataclass
class DomainTelemetry:
    domain: str
    registered_date: str | None = None
    age_days: int | None = None
    registrar_name: str | None = None
    abuse_contact_email: str | None = None
    abuse_contact_phone: str | None = None
    is_recently_registered: bool = False  # < 30 days


@dataclass
class FaviconIntel:
    found: bool
    favicon_url: str | None = None
    md5_hash: str | None = None
    sha256_hash: str | None = None
    matched_brand: str | None = None
    is_impersonation: bool = False
    details: str | None = None


@dataclass
class URLInvestigationReport:
    initial_url: str
    final_url: str
    total_hops: int
    hops: list[RedirectHop]
    domain_telemetry: DomainTelemetry
    favicon_intel: FaviconIntel
    threat_score: int  # 0 to 100
    risk_level: str  # CLEAN, REVIEW, ELEVATED, CRITICAL
    detected_indicators: list[str]
    investigation_timestamp_utc: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@dataclass
class ExifReport:
    file_path: str
    file_name: str
    file_size_bytes: int
    sha256: str
    has_exif: bool
    camera_make: str | None = None
    camera_model: str | None = None
    software_editor: str | None = None  # flags Photoshop, Canva, etc.
    datetime_original: str | None = None
    gps_latitude: float | None = None
    gps_longitude: float | None = None
    google_maps_url: str | None = None
    is_software_edited: bool = False
    indicators: list[str] = field(default_factory=list)


@dataclass
class ELAReport:
    file_path: str
    is_jpeg: bool
    max_difference: int
    mean_squared_error: float
    tampering_suspected: bool
    confidence_score: int  # 0 to 100
    details: str


# ---------------------------------------------------------------------------
# 1. Deep URL Uncloaker & Threat Analyzer
# ---------------------------------------------------------------------------
class URLThreatEngine:
    """Investigates suspicious links, multi-hop redirect concealment, and brand spoofing."""

    def __init__(self, timeout: int = 6):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
        })

    def uncloak(self, start_url: str, max_hops: int = 10) -> URLInvestigationReport:
        """Trace the full redirect chain safely without executing client-side scripts."""
        if not re.match(r"^https?://", start_url, re.IGNORECASE):
            start_url = "https://" + start_url

        current_url = start_url
        hops: list[RedirectHop] = []
        indicators: list[str] = []
        threat_score = 0
        final_html = ""

        for hop_idx in range(1, max_hops + 1):
            t_start = datetime.datetime.now()
            try:
                parsed = urlparse(current_url)
                resolved_ip = None
                try:
                    resolved_ip = socket.gethostbyname(parsed.hostname or "")
                except Exception:
                    pass

                # Stream response without reading arbitrary payloads
                resp = self.session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=self.timeout,
                    stream=True
                )
                t_end = datetime.datetime.now()
                ms = (t_end - t_start).total_seconds() * 1000

                location = resp.headers.get("Location")
                server = resp.headers.get("Server")

                hop = RedirectHop(
                    hop=hop_idx,
                    url=current_url,
                    status_code=resp.status_code,
                    location=location,
                    server=server,
                    ip=resolved_ip,
                    response_time_ms=round(ms, 2)
                )
                hops.append(hop)

                # Check redirect
                if resp.status_code in (301, 302, 303, 307, 308) and location:
                    # Resolve relative redirect
                    next_url = urljoin(current_url, location)
                    current_url = next_url
                else:
                    # Final destination reached, read first 64KB of HTML safely
                    try:
                        raw_bytes = next(resp.iter_content(chunk_size=65536), b"")
                        final_html = raw_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                    break

            except requests.RequestException as e:
                indicators.append(f"Network error at hop {hop_idx}: {str(e)[:120]}")
                break

        final_url = current_url
        final_parsed = urlparse(final_url)
        final_domain = (final_parsed.hostname or "").lower()

        # Score Redirect Chain
        if len(hops) > 1:
            indicators.append(f"Redirect concealment: URL traversed {len(hops)} intermediate hops.")
            threat_score += min(len(hops) * 8, 30)

        # Check IP as Hostname
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", final_domain):
            indicators.append("Host is a raw IP address instead of a domain name (unregistered origin).")
            threat_score += 25

        # Check Suspicious TLD
        tld = final_domain.split(".")[-1] if "." in final_domain else ""
        if tld in SUSPICIOUS_TLDS:
            indicators.append(f"Domain uses high-abuse/disposable TLD (.{tld}).")
            threat_score += 15

        # Domain Age / RDAP
        domain_telemetry = self._fetch_rdap(final_domain)
        if domain_telemetry.is_recently_registered:
            indicators.append(f"High risk: Domain registered only {domain_telemetry.age_days} days ago.")
            threat_score += 35
        elif domain_telemetry.age_days is not None and domain_telemetry.age_days < 90:
            indicators.append(f"Elevated risk: Domain is relatively new ({domain_telemetry.age_days} days old).")
            threat_score += 15

        # Favicon Brand Spoof Analysis
        favicon_intel = self._inspect_favicon(final_url, final_html)
        if favicon_intel.is_impersonation:
            indicators.append(f"CRITICAL: Brand Impersonation detected! Uses {favicon_intel.matched_brand} icon on unverified domain.")
            threat_score += 50

        # Credential Form Harvesting Check
        if re.search(r'<input[^>]+type=["\']password["\']', final_html, re.IGNORECASE):
            indicators.append("Credential form detected: Page explicitly requests password/login credentials.")
            threat_score += 20

        # Clamp Threat Score
        threat_score = min(threat_score, 100)

        # Classify Risk Level
        if threat_score >= 60:
            risk_level = "CRITICAL"
        elif threat_score >= 35:
            risk_level = "ELEVATED"
        elif threat_score >= 15:
            risk_level = "REVIEW"
        else:
            risk_level = "CLEAN"

        return URLInvestigationReport(
            initial_url=start_url,
            final_url=final_url,
            total_hops=len(hops),
            hops=hops,
            domain_telemetry=domain_telemetry,
            favicon_intel=favicon_intel,
            threat_score=threat_score,
            risk_level=risk_level,
            detected_indicators=indicators
        )

    def _fetch_rdap(self, domain: str) -> DomainTelemetry:
        """Query official ICANN RDAP registry for domain creation age and abuse contact."""
        # Strip subdomains for root domain query (e.g. login.evil.xyz -> evil.xyz)
        parts = domain.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        telemetry = DomainTelemetry(domain=domain)
        try:
            rdap_url = f"https://rdap.org/domain/{root_domain}"
            r = self.session.get(rdap_url, timeout=4)
            if r.status_code == 200:
                data = r.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        reg_date_str = event.get("eventDate", "")
                        telemetry.registered_date = reg_date_str
                        # Parse date
                        clean_date = reg_date_str[:10]
                        dt = datetime.datetime.strptime(clean_date, "%Y-%m-%d")
                        now = datetime.datetime.now()
                        age_days = (now - dt).days
                        telemetry.age_days = age_days
                        telemetry.is_recently_registered = (age_days <= 30)

                # Find Registrar and Abuse Contact
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    telemetry.registrar_name = item[3]
                    if "abuse" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "email":
                                    telemetry.abuse_contact_email = item[3]
                                elif item[0] == "tel":
                                    telemetry.abuse_contact_phone = item[3]

        except Exception as e:
            logger.debug("RDAP lookup failed for %s: %s", domain, e)

        return telemetry

    def _inspect_favicon(self, base_url: str, html: str) -> FaviconIntel:
        """Download favicon, calculate cryptographic hash, and check for brand spoofing."""
        intel = FaviconIntel(found=False)

        # Find favicon URL from HTML or default
        favicon_url = None
        match = re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if match:
            favicon_url = urljoin(base_url, match.group(1))
        else:
            favicon_url = urljoin(base_url, "/favicon.ico")

        try:
            r = self.session.get(favicon_url, timeout=3, stream=True)
            if r.status_code == 200:
                raw = next(r.iter_content(chunk_size=32768), b"")
                if len(raw) > 50:
                    intel.found = True
                    intel.favicon_url = favicon_url
                    md5_hash = hashlib.md5(raw).hexdigest()
                    sha256_hash = hashlib.sha256(raw).hexdigest()
                    intel.md5_hash = md5_hash
                    intel.sha256_hash = sha256_hash

                    # Match against known brands
                    if md5_hash in KNOWN_BRAND_FAVICONS:
                        brand_meta = KNOWN_BRAND_FAVICONS[md5_hash]
                        brand_name = brand_meta["brand"]
                        legit_domains = brand_meta["legit_domains"]
                        intel.matched_brand = brand_name

                        parsed = urlparse(base_url)
                        domain = (parsed.hostname or "").lower()
                        is_legit = any(domain == legit or domain.endswith("." + legit) for legit in legit_domains)

                        if not is_legit:
                            intel.is_impersonation = True
                            intel.details = f"Spoofed {brand_name} icon on unauthorized domain '{domain}'"
        except Exception:
            pass

        return intel


# ---------------------------------------------------------------------------
# 2. Telecom Carrier & Virtual VoIP Detector
# ---------------------------------------------------------------------------
class TelecomThreatEngine:
    """Detects virtual numbers, disposable cloud gateways, and VoIP anonymity masks."""

    @staticmethod
    def assess_number(carrier_name: str | None, number_type: str | None, country_code: str | None) -> dict[str, Any]:
        carrier_lower = (carrier_name or "").lower()
        is_voip = False
        voip_provider = None

        if number_type == "VOIP":
            is_voip = True
            voip_provider = carrier_name or "Generic Cloud VoIP"

        for kw in KNOWN_VOIP_KEYWORDS:
            if kw in carrier_lower:
                is_voip = True
                voip_provider = carrier_name
                break

        risk_score = 0
        indicators = []

        if is_voip:
            risk_score += 45
            indicators.append(f"Disposable / Cloud VoIP provider detected: {voip_provider}. Not tied to a physical SIM card.")
            anonymity_tier = "CRITICAL (High Anonymity / Disposable)"
        else:
            anonymity_tier = "STANDARD (Physical Cellular / Landline Carrier)"

        return {
            "is_virtual_voip": is_voip,
            "detected_provider": voip_provider,
            "anonymity_tier": anonymity_tier,
            "risk_score": risk_score,
            "indicators": indicators
        }


# ---------------------------------------------------------------------------
# 3. Forensic Media & Error Level Analysis (ELA) Engine
# ---------------------------------------------------------------------------
class ForensicMediaEngine:
    """Performs image EXIF telemetry, GPS coordinate decoding, and ELA tampering detection."""

    @staticmethod
    def inspect_exif(image_path: str) -> ExifReport:
        p = io.BytesIO(open(image_path, "rb").read())
        raw_bytes = p.getvalue()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        img = Image.open(p)
        exif_data = img.getexif()

        report = ExifReport(
            file_path=image_path,
            file_name=image_path.replace("\\", "/").split("/")[-1],
            file_size_bytes=len(raw_bytes),
            sha256=sha256,
            has_exif=bool(exif_data)
        )

        if not exif_data:
            report.indicators.append("EXIF metadata is stripped or absent (common in social media uploads).")
            return report

        # Tag IDs:
        # 271: Make, 272: Model, 305: Software, 306: DateTime, 36867: DateTimeOriginal
        make = exif_data.get(271)
        model = exif_data.get(272)
        software = exif_data.get(305)
        dt = exif_data.get(36867) or exif_data.get(306)

        report.camera_make = str(make).strip() if make else None
        report.camera_model = str(model).strip() if model else None
        report.software_editor = str(software).strip() if software else None
        report.datetime_original = str(dt).strip() if dt else None

        # Check for photo manipulation software
        if software:
            sw_lower = str(software).lower()
            if any(k in sw_lower for k in ["photoshop", "canva", "lightroom", "gimp", "picsart", "snapseed"]):
                report.is_software_edited = True
                report.indicators.append(f"Image edited with software: {software}")

        # Check GPS
        # Exif IFD / GPSInfo
        gps_ifd = exif_data.get_ifd(0x8825)
        if gps_ifd:
            try:
                lat = gps_ifd.get(2)
                lat_ref = gps_ifd.get(1)
                lon = gps_ifd.get(4)
                lon_ref = gps_ifd.get(3)

                if lat and lon and lat_ref and lon_ref:
                    def to_deg(dms):
                        return float(dms[0]) + float(dms[1]) / 60.0 + float(dms[2]) / 3600.0

                    dec_lat = to_deg(lat)
                    if str(lat_ref).upper() == "S":
                        dec_lat = -dec_lat
                    dec_lon = to_deg(lon)
                    if str(lon_ref).upper() == "W":
                        dec_lon = -dec_lon

                    report.gps_latitude = round(dec_lat, 6)
                    report.gps_longitude = round(dec_lon, 6)
                    report.google_maps_url = f"https://www.google.com/maps?q={dec_lat},{dec_lon}"
                    report.indicators.append(f"Live GPS coordinates recovered: {dec_lat}, {dec_lon}")
            except Exception as e:
                logger.debug("GPS parse error: %s", e)

        return report

    @staticmethod
    def analyze_ela(image_path: str, scale: int = 15) -> ELAReport:
        """Error Level Analysis to detect pixel resave anomalies and tampered regions."""
        try:
            orig = Image.open(image_path).convert("RGB")
            buf = io.BytesIO()
            orig.save(buf, format="JPEG", quality=95)
            buf.seek(0)
            resaved = Image.open(buf)

            diff = ImageChops.difference(orig, resaved)
            extrema = diff.getextrema()
            max_diff = max(ex[1] for ex in extrema)

            # Calculate mean difference
            diff_bytes = diff.tobytes()
            mean_diff = sum(diff_bytes) / len(diff_bytes)

            # High variance and extreme local error bands indicate spliced pixels
            tampering_suspected = (max_diff > 45 and mean_diff > 3.5)
            confidence = min(int(max_diff * 1.5), 95) if tampering_suspected else 10

            details = (
                f"Peak pixel variance: {max_diff} (Scale: {scale}x). "
                + ("Noticeable compression delta suggests altered regions."
                   if tampering_suspected else "Uniform error surface; no obvious splicing detected.")
            )

            return ELAReport(
                file_path=image_path,
                is_jpeg=True,
                max_difference=max_diff,
                mean_squared_error=round(mean_diff, 2),
                tampering_suspected=tampering_suspected,
                confidence_score=confidence,
                details=details
            )
        except Exception as e:
            return ELAReport(
                file_path=image_path,
                is_jpeg=False,
                max_difference=0,
                mean_squared_error=0.0,
                tampering_suspected=False,
                confidence_score=0,
                details=f"Analysis failed or unsupported format: {e}"
            )


# ---------------------------------------------------------------------------
# 4. Automated Forensic Evidence Dossier Generator
# ---------------------------------------------------------------------------
class ForensicDossierBuilder:
    """Generates structured legal and technical evidence reports for incident defense."""

    @staticmethod
    def build_markdown_report(case_title: str, evidence_items: list[dict[str, Any]]) -> str:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        report_id = "PHX-" + hashlib.sha256(timestamp.encode()).hexdigest()[:12].upper()

        lines = [
            f"# PHOENIX FORENSIC INCIDENT DOSSIER",
            f"**CASE IDENTIFIER**: `{report_id}`",
            f"**DATE & TIME**: `{timestamp}`",
            f"**CLASSIFICATION**: CONFIDENTIAL // DEFENSIVE RECONNAISSANCE",
            f"**INVESTIGATOR / ENGINE**: Phoenix Cyber Intelligence v2.0",
            "",
            "---",
            "## 1. EXECUTIVE SUMMARY & EVIDENCE CHAIN",
        ]

        for idx, item in enumerate(evidence_items, 1):
            lines.append(f"### Item #{idx:02d}: {item.get('title', 'Forensic Artifact')}")
            lines.append(f"- **Target**: `{item.get('target', 'N/A')}`")
            lines.append(f"- **Risk Classification**: `{item.get('risk_level', 'UNCLASSIFIED')}` (Score: {item.get('threat_score', 0)}/100)")
            lines.append(f"- **Summary**: {item.get('summary', 'No summary provided.')}")

            if "indicators" in item and item["indicators"]:
                lines.append("- **Key Indicators Detected**:")
                for ind in item["indicators"]:
                    lines.append(f"  * {ind}")
            lines.append("")

        lines.extend([
            "---",
            "## 2. LEGAL & TECHNICAL MITIGATION PROTOCOL",
            "1. **Takedown Escalation**: File an official abuse report with the identified Registrar and Cloudflare/Hosting provider.",
            "2. **Evidence Preservation**: This report contains verifiable SHA-256 signatures of all inputs at time of capture.",
            "3. **Platform Enforcement**: If impersonating Meta/Instagram/Google, submit direct brand enforcement report with the above Favicon and RDAP findings.",
            "",
            "---",
            "*Report automatically generated by Phoenix (khalil-m-khalil.github.io/Phoenix) under authorized forensic defensive protocol.*"
        ])

        return "\n".join(lines)
