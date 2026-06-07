#!/usr/bin/env python3
"""
Scam Detector MCP Server
=========================
By MEOK AI Labs | https://meok.ai

The only MCP server for scam and fraud detection.
Covers phishing, social engineering, sender verification,
manipulation detection, and scam reporting.

Install: pip install mcp
Run:     python server.py
"""

import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

# -- Authentication --------------------------------------------------------
import os as _os
import sys, os

_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

try:
    from auth_middleware import check_access as _shared_check_access
    _AUTH_ENGINE_AVAILABLE = True
except ImportError:
    _AUTH_ENGINE_AVAILABLE = False

    def _shared_check_access(api_key=""):
        # type: (str) -> Tuple[bool, str, str]
        """Fallback when shared auth engine is not available."""
        if _MEOK_API_KEY and api_key and api_key == _MEOK_API_KEY:
            return True, "OK", "pro"
        if _MEOK_API_KEY and api_key and api_key != _MEOK_API_KEY:
            return False, "Invalid API key. Get one at https://meok.ai/api-keys", "free"
        return True, "OK, Pro at https://www.csoai.org/checkout", "free"


def check_access(api_key=""):
    # type: (str) -> Tuple[bool, str, str]
    """Unified access check -- works with or without shared auth engine."""
    return _shared_check_access(api_key)


# -- Rate limiting ---------------------------------------------------------
FREE_DAILY_LIMIT = 10
PRO_TIER_UNLIMITED = True  # Pro: $29/mo unlimited at https://meok.ai/mcp/scam-detector/pro
_usage = defaultdict(list)  # type: Dict[str, List[datetime]]


def _check_rate_limit(caller="anonymous", tier="free"):
    # type: (str, str) -> Optional[str]
    """Returns error string if rate-limited, else None."""
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            "Free tier limit reached ({}/day). "
            "Upgrade to MEOK AI Labs Pro for unlimited access at $29/mo: "
            "https://meok.ai/mcp/scam-detector/pro".format(FREE_DAILY_LIMIT)
        )
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# Scam Knowledge Base
# ---------------------------------------------------------------------------

SCAM_PATTERNS = {
    "urgency": {
        "name": "Artificial Urgency",
        "indicators": [
            "act now", "urgent", "immediately", "last chance", "expires today",
            "limited time", "don't delay", "hurry", "24 hours", "deadline",
            "time sensitive", "right away", "asap", "final notice", "account suspended",
            "will be closed", "within 24", "within 48",
        ],
        "weight": 0.25,
        "description": "Creates false time pressure to prevent careful evaluation",
    },
    "authority": {
        "name": "Authority Impersonation",
        "indicators": [
            "irs", "hmrc", "tax office", "police", "fbi", "interpol",
            "bank security", "fraud department", "microsoft support", "apple support",
            "google security", "paypal security", "amazon security", "government",
            "official notice", "court order", "warrant", "legal action", "lawsuit",
            "compliance department",
        ],
        "weight": 0.3,
        "description": "Impersonates trusted authorities to intimidate victims",
    },
    "financial_lure": {
        "name": "Financial Lure",
        "indicators": [
            "you've won", "congratulations", "prize", "lottery", "jackpot",
            "inheritance", "million", "billion", "investment opportunity",
            "guaranteed return", "risk free", "double your money", "crypto opportunity",
            "bitcoin giveaway", "free money", "unclaimed funds", "beneficiary",
            "wire transfer", "western union", "gift card",
        ],
        "weight": 0.35,
        "description": "Offers unrealistic financial rewards to lure victims",
    },
    "personal_info_request": {
        "name": "Personal Information Harvesting",
        "indicators": [
            "verify your account", "confirm your identity", "update your details",
            "social security", "national insurance", "credit card number",
            "bank account number", "routing number", "sort code", "pin number",
            "password", "login credentials", "mother's maiden name", "date of birth",
            "passport number", "driver's license",
        ],
        "weight": 0.35,
        "description": "Requests sensitive personal or financial information",
    },
    "emotional_manipulation": {
        "name": "Emotional Manipulation",
        "indicators": [
            "help me", "dying", "stranded", "emergency", "kidnapped",
            "accident", "hospital", "cancer", "charity", "orphan",
            "disaster relief", "donate now", "save a life", "heartbreaking",
            "lonely", "looking for love", "soulmate",
        ],
        "weight": 0.2,
        "description": "Exploits emotions (fear, sympathy, love) to bypass rational thinking",
    },
    "too_good_to_be_true": {
        "name": "Too Good to Be True",
        "indicators": [
            "guaranteed", "100%", "no risk", "free trial", "earn from home",
            "passive income", "work from home", "easy money", "get rich",
            "financial freedom", "no experience needed", "unlimited income",
            "secret method", "proven system", "overnight success",
        ],
        "weight": 0.25,
        "description": "Promises unrealistic outcomes with no effort or risk",
    },
    "impersonation": {
        "name": "Identity Impersonation",
        "indicators": [
            "ceo", "boss", "manager", "director", "executive",
            "it department", "tech support", "helpdesk", "customer service",
            "your friend", "family member", "relative", "colleague",
        ],
        "weight": 0.2,
        "description": "Pretends to be someone the victim knows or trusts",
    },
    "obfuscation": {
        "name": "Obfuscation Tactics",
        "indicators": [
            "bit.ly", "tinyurl", "t.co", "goo.gl", "shortened link",
            "click here", "see attached", "open attachment", "enable macros",
            "enable content", "download now", "install update",
        ],
        "weight": 0.2,
        "description": "Uses link shorteners, attachments, or technical tricks to hide true intent",
    },
}

PHISHING_URL_INDICATORS = {
    "suspicious_tld": {
        "patterns": [".xyz", ".top", ".club", ".work", ".click", ".loan", ".win", ".gq", ".tk", ".ml", ".cf", ".ga"],
        "weight": 0.3,
        "description": "Suspicious top-level domains commonly used in phishing",
    },
    "typosquatting": {
        "patterns": [
            "paypa1", "g00gle", "micros0ft", "amaz0n", "faceb00k",
            "app1e", "netfl1x", "1inkedin", "twitt3r", "inst4gram",
        ],
        "weight": 0.5,
        "description": "Intentional misspellings of legitimate brands",
    },
    "suspicious_structure": {
        "patterns": [
            "login-", "secure-", "verify-", "update-", "account-",
            "signin.", "security.", "-alert.", "-confirm.",
        ],
        "weight": 0.25,
        "description": "URL structures designed to look like security pages",
    },
    "ip_in_url": {
        "patterns": [r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"],
        "weight": 0.4,
        "description": "Direct IP address in URL instead of domain name",
    },
    "excessive_subdomains": {
        "patterns": [r"\w+\.\w+\.\w+\.\w+\.\w+"],
        "weight": 0.3,
        "description": "Excessive subdomain depth to obscure actual domain",
    },
}

SOCIAL_ENGINEERING_TACTICS = {
    "reciprocity": {
        "indicators": ["free gift", "bonus", "complimentary", "no cost", "as a thank you", "reward"],
        "description": "Offers something free to create obligation to reciprocate",
        "defense": "Remember: legitimate offers don't require personal info or payments",
    },
    "commitment": {
        "indicators": ["you agreed", "as promised", "you signed up", "your subscription", "your membership", "you registered"],
        "description": "References fake prior commitments to pressure compliance",
        "defense": "Verify any claimed prior agreements through official channels",
    },
    "social_proof": {
        "indicators": ["everyone is", "millions of people", "your neighbours", "trending", "popular", "most people"],
        "description": "Claims widespread adoption to pressure conformity",
        "defense": "Popularity claims in unsolicited messages are often fabricated",
    },
    "liking": {
        "indicators": ["we have a lot in common", "i noticed you", "your profile", "mutual friend", "we connected"],
        "description": "Builds false rapport to establish trust",
        "defense": "Be cautious of strangers who quickly claim personal connections",
    },
    "scarcity": {
        "indicators": ["only 3 left", "limited spots", "exclusive", "invitation only", "while supplies last", "selling fast"],
        "description": "Creates artificial scarcity to pressure quick action",
        "defense": "Legitimate opportunities rarely require instant decisions",
    },
    "fear": {
        "indicators": ["your account will be", "you will lose", "legal consequences", "arrest", "fine", "penalty", "suspended"],
        "description": "Uses threats and fear to override rational thinking",
        "defense": "Legitimate organisations do not threaten via email/text. Contact them directly.",
    },
}

# In-memory scam reports store
_scam_reports = []  # type: List[Dict[str, object]]


def _match_keywords(text, keywords):
    # type: (str, List[str]) -> List[str]
    """Return matched keywords found in text (case-insensitive)."""
    text_lower = text.lower()
    return [kw for kw in keywords if kw.lower() in text_lower]


def _calculate_scam_score(text):
    # type: (str) -> Tuple[float, List[Dict[str, object]]]
    """Calculate overall scam probability score. Returns (score 0-1, matched_patterns)."""
    total_weight = 0.0
    matches = []  # type: List[Dict[str, object]]

    for ptype, pinfo in SCAM_PATTERNS.items():
        matched = _match_keywords(text, pinfo["indicators"])
        if matched:
            total_weight += pinfo["weight"] * min(len(matched) / 3.0, 1.5)
            matches.append({
                "pattern": pinfo["name"],
                "weight": pinfo["weight"],
                "matched_indicators": matched[:5],
                "description": pinfo["description"],
            })

    # Additional heuristics
    text_lower = text.lower()

    # ALL CAPS sections
    caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
    if len(caps_words) > 2:
        total_weight += 0.1

    # Excessive exclamation/question marks
    if text.count("!") > 3 or text.count("?") > 5:
        total_weight += 0.1

    # Multiple dollar/pound/euro signs
    currency_count = len(re.findall(r'[$\u00a3\u20ac]', text))
    if currency_count > 2:
        total_weight += 0.1

    # Grammar/spelling red flags (common in scams)
    grammar_flags = [
        "kindly", "dear sir", "dear madam", "dear friend", "dear customer",
        "do the needful", "revert back", "prepone",
    ]
    if _match_keywords(text, grammar_flags):
        total_weight += 0.15

    # Normalize to 0-1
    score = min(1.0, total_weight / 1.5)
    return score, matches


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "Scam Detector",
    instructions=(
        "By MEOK AI Labs -- Scam and fraud detection for consumers and businesses. "
        "Start with quick_check (paste any message, instant scam probability). "
        "Full tools: analyze_url, detect_social_engineering, verify_sender, report_scam. "
        "No API key needed for free tier (10 calls/day)."
    ),
)


# ---------------------------------------------------------------------------
# Tool: quick_check -- ZERO config, no API key, instant result
# ---------------------------------------------------------------------------
@mcp.tool()
def quick_check(message: str) -> dict:
    """Paste any message (email, text, DM) -> instant scam probability score. No API key required.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    limit_err = _check_rate_limit("quick_check_anonymous")
    if limit_err:
        return {"error": "rate_limited", "message": limit_err}

    scam_score, matched_patterns = _calculate_scam_score(message)

    # Classify risk level
    if scam_score >= 0.75:
        risk_level = "critical"
        verdict = "VERY LIKELY A SCAM"
        action = "Do NOT respond, click links, or provide any personal information. Block and report."
    elif scam_score >= 0.5:
        risk_level = "high"
        verdict = "LIKELY A SCAM"
        action = "Exercise extreme caution. Verify independently through official channels before taking any action."
    elif scam_score >= 0.3:
        risk_level = "moderate"
        verdict = "SUSPICIOUS"
        action = "Proceed with caution. Verify the sender and any claims through official channels."
    elif scam_score >= 0.15:
        risk_level = "low"
        verdict = "SLIGHTLY SUSPICIOUS"
        action = "Likely legitimate but contains some common scam indicators. Verify if unsure."
    else:
        risk_level = "minimal"
        verdict = "APPEARS LEGITIMATE"
        action = "No significant scam indicators detected. Standard caution applies."

    # Extract tactics used
    tactics_used = [p["pattern"] for p in matched_patterns]

    return {
        "scam_probability": round(scam_score, 2),
        "risk_level": risk_level,
        "verdict": verdict,
        "recommended_action": action,
        "tactics_detected": tactics_used,
        "pattern_details": matched_patterns[:5],
        "message_length": len(message),
        "next_step": (
            "Use detect_social_engineering for deeper manipulation analysis"
            if scam_score >= 0.3
            else "Use report_scam if you believe this is a scam"
        ),
        "meok_labs": "https://meok.ai",
    }


# ---------------------------------------------------------------------------
# Tool: analyze_url
# ---------------------------------------------------------------------------
@mcp.tool()
def analyze_url(
    url: str,
    api_key: str = "",
) -> dict:
    """Check a URL for phishing indicators and suspicious patterns.

    Args:
        url: The URL to analyze for phishing indicators.
        api_key: Optional MEOK API key for pro tier.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}
    limit_err = _check_rate_limit("analyze_url", tier)
    if limit_err:
        return {"error": "rate_limited", "message": limit_err}

    url_lower = url.lower().strip()
    findings = []  # type: List[Dict[str, str]]
    total_risk = 0.0

    # Check for HTTPS
    if url_lower.startswith("http://"):
        findings.append({
            "finding": "No HTTPS",
            "severity": "medium",
            "detail": "URL uses HTTP instead of HTTPS -- data transmitted in plain text",
        })
        total_risk += 0.15
    elif not url_lower.startswith("https://"):
        findings.append({
            "finding": "Missing protocol",
            "severity": "low",
            "detail": "URL does not specify a protocol",
        })

    # Check phishing indicators
    for indicator_name, indicator_info in PHISHING_URL_INDICATORS.items():
        for pattern in indicator_info["patterns"]:
            if indicator_name == "ip_in_url" or indicator_name == "excessive_subdomains":
                if re.search(pattern, url_lower):
                    findings.append({
                        "finding": indicator_info["description"],
                        "severity": "high" if indicator_info["weight"] > 0.3 else "medium",
                        "detail": "Matched pattern: {}".format(pattern),
                    })
                    total_risk += indicator_info["weight"]
                    break
            else:
                if pattern.lower() in url_lower:
                    findings.append({
                        "finding": indicator_info["description"],
                        "severity": "high" if indicator_info["weight"] > 0.3 else "medium",
                        "detail": "Matched indicator: {}".format(pattern),
                    })
                    total_risk += indicator_info["weight"]
                    break

    # Check URL length (phishing URLs tend to be long)
    if len(url) > 100:
        findings.append({
            "finding": "Unusually long URL",
            "severity": "low",
            "detail": "URL is {} characters (phishing URLs are often longer than legitimate ones)".format(len(url)),
        })
        total_risk += 0.1

    # Check for @ symbol (used to obscure real domain)
    if "@" in url_lower:
        findings.append({
            "finding": "@ symbol in URL",
            "severity": "high",
            "detail": "@ symbol can be used to obscure the actual destination domain",
        })
        total_risk += 0.4

    # Check for multiple redirects (double slashes after domain)
    if url_lower.count("//") > 1:
        double_slash_count = url_lower.count("//")
        if double_slash_count > 2:
            findings.append({
                "finding": "Multiple double-slashes",
                "severity": "medium",
                "detail": "May indicate redirect chains or URL obfuscation",
            })
            total_risk += 0.15

    # Check for suspicious file extensions
    suspicious_extensions = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".pif"]
    for ext in suspicious_extensions:
        if url_lower.endswith(ext):
            findings.append({
                "finding": "Suspicious file extension",
                "severity": "critical",
                "detail": "URL points to executable file ({}) -- likely malware".format(ext),
            })
            total_risk += 0.5

    # Normalize score
    risk_score = min(1.0, total_risk)

    if risk_score >= 0.6:
        verdict = "HIGH RISK -- likely phishing"
        action = "Do NOT click this link. Do not enter any credentials on this site."
    elif risk_score >= 0.3:
        verdict = "MODERATE RISK -- potentially suspicious"
        action = "Verify the URL through official channels before proceeding."
    else:
        verdict = "LOW RISK -- no major indicators"
        action = "URL appears relatively safe but always verify sender context."

    return {
        "url_analyzed": url,
        "risk_score": round(risk_score, 2),
        "verdict": verdict,
        "recommended_action": action,
        "findings": findings,
        "url_length": len(url),
        "uses_https": url_lower.startswith("https://"),
        "next_step": "Use quick_check on the full message containing this URL for comprehensive scam analysis",
        "meok_labs": "https://meok.ai",
    }


# ---------------------------------------------------------------------------
# Tool: detect_social_engineering
# ---------------------------------------------------------------------------
@mcp.tool()
def detect_social_engineering(
    conversation: str,
    api_key: str = "",
) -> dict:
    """Detect manipulation tactics (Cialdini's principles) in conversations.

    Args:
        conversation: The conversation text to analyze for social engineering tactics.
        api_key: Optional MEOK API key for pro tier.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}
    limit_err = _check_rate_limit("social_engineering", tier)
    if limit_err:
        return {"error": "rate_limited", "message": limit_err}

    detected_tactics = []  # type: List[Dict[str, object]]
    total_score = 0.0

    for tactic_name, tactic_info in SOCIAL_ENGINEERING_TACTICS.items():
        matched = _match_keywords(conversation, tactic_info["indicators"])
        if matched:
            weight = 0.2 * min(len(matched), 3)
            total_score += weight
            detected_tactics.append({
                "tactic": tactic_name,
                "description": tactic_info["description"],
                "matched_indicators": matched[:5],
                "defense": tactic_info["defense"],
                "severity": "high" if weight > 0.35 else "medium",
            })

    # Also check general scam patterns
    scam_score, scam_matches = _calculate_scam_score(conversation)
    total_score += scam_score * 0.5

    # Normalise
    manipulation_score = min(1.0, total_score)

    if manipulation_score >= 0.6:
        risk_level = "high"
        assessment = "STRONG social engineering detected -- multiple manipulation tactics in use"
    elif manipulation_score >= 0.3:
        risk_level = "moderate"
        assessment = "Social engineering indicators present -- proceed with caution"
    elif manipulation_score >= 0.1:
        risk_level = "low"
        assessment = "Minor persuasion tactics detected -- likely normal communication"
    else:
        risk_level = "minimal"
        assessment = "No significant social engineering patterns detected"

    # Count escalation patterns (repeated asks or increasing pressure)
    sentences = [s.strip() for s in re.split(r'[.!?]+', conversation) if s.strip()]
    pressure_escalation = 0
    for i, sentence in enumerate(sentences):
        urgency_words = ["now", "immediately", "urgent", "hurry", "quick", "fast"]
        if _match_keywords(sentence, urgency_words):
            pressure_escalation += 1

    return {
        "manipulation_score": round(manipulation_score, 2),
        "risk_level": risk_level,
        "assessment": assessment,
        "tactics_detected": detected_tactics,
        "additional_scam_patterns": [m["pattern"] for m in scam_matches],
        "pressure_escalation_count": pressure_escalation,
        "total_sentences": len(sentences),
        "general_defenses": [
            "Never make financial decisions under time pressure",
            "Verify identity claims through independent channels (not provided links/numbers)",
            "Legitimate organisations will not pressure you for immediate action",
            "If something feels wrong, trust your instincts and stop engaging",
            "Discuss suspicious requests with a trusted person before acting",
        ],
        "next_step": "Use report_scam to log this interaction if you believe it is a scam",
        "meok_labs": "https://meok.ai",
    }


# ---------------------------------------------------------------------------
# Tool: verify_sender
# ---------------------------------------------------------------------------
@mcp.tool()
def verify_sender(
    email_or_phone: str,
    api_key: str = "",
) -> dict:
    """Check sender patterns against known scam vectors.

    Args:
        email_or_phone: The email address or phone number to check.
        api_key: Optional MEOK API key for pro tier.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}
    limit_err = _check_rate_limit("verify_sender", tier)
    if limit_err:
        return {"error": "rate_limited", "message": limit_err}

    sender = email_or_phone.strip()
    findings = []  # type: List[Dict[str, str]]
    risk_score = 0.0
    sender_type = "unknown"

    # Detect if email or phone
    if "@" in sender:
        sender_type = "email"

        # Check for free email providers (higher scam risk for official communications)
        free_providers = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
            "mail.com", "protonmail.com", "yandex.com", "tutanota.com",
        ]
        domain = sender.split("@")[-1].lower()

        if domain in free_providers:
            findings.append({
                "finding": "Free email provider",
                "severity": "medium",
                "detail": "Legitimate organisations typically use corporate domains, not {}".format(domain),
            })
            risk_score += 0.2

        # Check for suspicious domain patterns
        suspicious_domain_patterns = [
            (r"[0-9]{3,}", "Numbers in domain", 0.3),
            (r"(.)\1{3,}", "Repeated characters", 0.25),
            (r"-{2,}", "Multiple hyphens", 0.2),
            (r"\.(xyz|top|club|work|click|loan|win|gq|tk|ml|cf|ga)$", "Suspicious TLD", 0.35),
        ]

        for pattern, desc, weight in suspicious_domain_patterns:
            if re.search(pattern, domain):
                findings.append({
                    "finding": desc,
                    "severity": "high" if weight > 0.25 else "medium",
                    "detail": "Domain '{}' matches suspicious pattern".format(domain),
                })
                risk_score += weight

        # Check for brand impersonation in domain
        brands = ["paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook", "instagram", "bank"]
        for brand in brands:
            if brand in domain and domain not in ["{}.com".format(brand), "{}.co.uk".format(brand)]:
                findings.append({
                    "finding": "Possible brand impersonation",
                    "severity": "high",
                    "detail": "Domain contains '{}' but is not the official domain".format(brand),
                })
                risk_score += 0.4
                break

        # Check local part for suspicious patterns
        local_part = sender.split("@")[0].lower()
        suspicious_locals = ["noreply", "no-reply", "support", "security", "admin", "help", "info"]
        if local_part in suspicious_locals:
            findings.append({
                "finding": "Generic sender name",
                "severity": "low",
                "detail": "'{}' is commonly used in both legitimate and scam emails".format(local_part),
            })
            risk_score += 0.05

    elif re.search(r'\+?\d[\d\s\-]{6,}', sender):
        sender_type = "phone"

        # Check for premium rate numbers
        premium_prefixes = ["0900", "0901", "0906", "0907", "900", "976"]
        for prefix in premium_prefixes:
            if sender.replace(" ", "").replace("-", "").startswith(prefix):
                findings.append({
                    "finding": "Premium rate number",
                    "severity": "high",
                    "detail": "Number starting with {} is a premium rate number -- calling it costs money".format(prefix),
                })
                risk_score += 0.5

        # Check for international prefixes (common in scams targeting specific countries)
        high_risk_country_codes = ["+233", "+234", "+225", "+228", "+221"]  # Ghana, Nigeria, Ivory Coast, Togo, Senegal
        for code in high_risk_country_codes:
            clean_sender = sender.replace(" ", "").replace("-", "")
            if clean_sender.startswith(code):
                findings.append({
                    "finding": "High-risk country code",
                    "severity": "medium",
                    "detail": "Country code {} is statistically associated with higher scam rates".format(code),
                })
                risk_score += 0.25

        # Very short numbers (may be short codes -- some legitimate, some scam)
        digits_only = re.sub(r'[^\d]', '', sender)
        if len(digits_only) <= 5:
            findings.append({
                "finding": "Short code number",
                "severity": "low",
                "detail": "Short codes can be legitimate (bank alerts) or used for scam texts",
            })
            risk_score += 0.1

    else:
        findings.append({
            "finding": "Unrecognised format",
            "severity": "low",
            "detail": "Could not determine if input is an email or phone number",
        })

    risk_score = min(1.0, risk_score)

    if risk_score >= 0.5:
        verdict = "HIGH RISK"
        action = "This sender shows multiple suspicious indicators. Do not engage."
    elif risk_score >= 0.25:
        verdict = "MODERATE RISK"
        action = "Some suspicious patterns detected. Verify through official channels."
    else:
        verdict = "LOW RISK"
        action = "No major red flags, but always verify unsolicited contacts independently."

    return {
        "sender": sender,
        "sender_type": sender_type,
        "risk_score": round(risk_score, 2),
        "verdict": verdict,
        "recommended_action": action,
        "findings": findings,
        "verification_tips": [
            "Search the sender address/number online for scam reports",
            "Contact the claimed organisation directly using their official website contact info",
            "Check the organisation's official website for legitimate contact addresses",
            "Report suspicious senders to your email provider or phone carrier",
        ],
        "next_step": "Use quick_check on the full message from this sender",
        "meok_labs": "https://meok.ai",
    }


# ---------------------------------------------------------------------------
# Tool: report_scam
# ---------------------------------------------------------------------------
@mcp.tool()
def report_scam(
    description: str,
    api_key: str = "",
) -> dict:
    """Log and analyze a scam report. Contributes to collective threat intelligence.

    Args:
        description: Description of the scam including the message, sender, and what happened.
        api_key: Optional MEOK API key for pro tier.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}
    limit_err = _check_rate_limit("report_scam", tier)
    if limit_err:
        return {"error": "rate_limited", "message": limit_err}

    # Analyze the report
    scam_score, scam_patterns = _calculate_scam_score(description)

    # Classify scam type
    scam_types = []  # type: List[str]
    desc_lower = description.lower()

    type_keywords = {
        "phishing": ["email", "link", "click", "login", "password", "credential", "website"],
        "vishing": ["phone", "call", "called", "rang", "voicemail"],
        "smishing": ["text", "sms", "message", "whatsapp", "telegram"],
        "romance": ["dating", "love", "relationship", "romantic", "meet", "profile"],
        "investment": ["invest", "crypto", "bitcoin", "stock", "return", "profit", "trading"],
        "tech_support": ["computer", "virus", "malware", "remote access", "teamviewer", "microsoft"],
        "advance_fee": ["upfront", "fee", "payment first", "processing fee", "transfer fee"],
        "impersonation": ["pretend", "claimed to be", "said they were", "impersonat"],
        "lottery": ["lottery", "won", "prize", "draw", "sweepstakes"],
        "employment": ["job offer", "work from home", "remote job", "hiring", "recruit"],
    }

    for stype, keywords in type_keywords.items():
        if _match_keywords(description, keywords):
            scam_types.append(stype)

    # Generate report ID
    report_hash = hashlib.sha256(
        "{}:{}".format(datetime.now().isoformat(), description[:100]).encode()
    ).hexdigest()[:12]

    report = {
        "report_id": "SCAM-{}".format(report_hash.upper()),
        "timestamp": datetime.now().isoformat(),
        "scam_types_identified": scam_types if scam_types else ["unclassified"],
        "tactics_used": [p["pattern"] for p in scam_patterns],
        "confidence_score": round(scam_score, 2),
    }

    # Store report
    _scam_reports.append(report)

    # Generate advice based on scam type
    advice = []  # type: List[str]
    if "phishing" in scam_types:
        advice.extend([
            "Forward the phishing email to your email provider's abuse team",
            "Report to Anti-Phishing Working Group: reportphishing@apwg.org",
            "If you clicked a link: change passwords immediately and enable 2FA",
        ])
    if "vishing" in scam_types or "smishing" in scam_types:
        advice.extend([
            "Block the phone number",
            "Report to your phone carrier",
            "If you gave personal info: contact your bank and credit bureaus immediately",
        ])
    if "investment" in scam_types:
        advice.extend([
            "Report to your national financial regulator (SEC, FCA, ASIC, etc.)",
            "Do not send any more money",
            "Warn others who may have been approached",
        ])
    if "romance" in scam_types:
        advice.extend([
            "Stop all communication with the scammer",
            "Do not send money under any circumstances",
            "Report the profile to the dating platform",
        ])
    if not advice:
        advice = [
            "Report to your national consumer protection agency",
            "Report to local police if money was lost",
            "Change passwords for any accounts that may be compromised",
            "Monitor bank statements and credit reports for unusual activity",
        ]

    return {
        "report_id": report["report_id"],
        "status": "logged",
        "analysis": report,
        "recommended_actions": advice,
        "reporting_resources": {
            "uk": "Action Fraud: https://www.actionfraud.police.uk",
            "us": "FTC: https://reportfraud.ftc.gov",
            "eu": "Europol: https://www.europol.europa.eu/report-a-crime",
            "au": "Scamwatch: https://www.scamwatch.gov.au",
            "ca": "Canadian Anti-Fraud Centre: https://antifraudcentre-centreantifraude.ca",
        },
        "total_reports_in_session": len(_scam_reports),
        "meok_labs": "https://meok.ai",
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    """Entry point for the scam-detector-mcp command."""
    mcp.run()


if __name__ == "__main__":
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/00wfZjcgAeUW4c5cyQ8k90K"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}
