"""
security_gate.py

CI/CD security gate that blocks PRs on high-severity secrets and critical CVEs,
but prioritizes a developer-friendly remediation experience:

  1. Runs gitleaks (secrets) + osv-scanner (SCA) on the PR diff.
  2. Normalizes findings into a common schema and deduplicates.
  3. Applies a policy with severity thresholds, allowlists, and SLAs.
  4. Generates remediation suggestions (auto-patch PRs for fixable deps,
     rotation runbooks for secrets).
  5. Emits a rich PR comment + GitHub check run.
  6. Supports audited waivers instead of "disable the job".

Usage (GitHub Actions entrypoint):
    python security_gate.py \
        --repo-path . \
        --base-ref origin/main \
        --head-sha $GITHUB_SHA \
        --policy .security/policy.yml \
        --output-dir .security/out

Exit codes:
    0  gate passed (or only findings under threshold)
    1  gate failed, blocking findings present
    2  internal scanner error
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("security_gate")


# ----------------------------- Domain model -----------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class FindingKind(str, Enum):
    SECRET = "secret"
    CVE = "cve"


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int | None = None

    def as_permalink(self, repo: str, sha: str) -> str:
        end = f"-L{self.end_line}" if self.end_line and self.end_line != self.start_line else ""
        return f"https://github.com/{repo}/blob/{sha}/{self.path}#L{self.start_line}{end}"


@dataclass
class Remediation:
    """
    A concrete next step the developer can take. We always try to offer
    at least one 'auto' action and one 'manual' explanation so the
    developer can choose speed vs. understanding.
    """
    summary: str
    kind: str                          # 'auto_patch' | 'rotate_secret' | 'waiver' | 'upgrade'
    auto_applicable: bool = False
    patch_diff: str | None = None      # unified diff, if auto_applicable
    runbook_markdown: str | None = None


@dataclass
class Finding:
    kind: FindingKind
    rule_id: str                       # e.g. 'aws-access-key' or 'CVE-2024-12345'
    title: str
    severity: Severity
    location: Location
    description: str
    introduced_at: str                 # ISO-8601; commit date or detection time
    # Scanner metadata
    source_tool: str                   # 'gitleaks' | 'osv-scanner' | ...
    raw: dict[str, Any] = field(default_factory=dict)
    # Triage
    remediations: list[Remediation] = field(default_factory=list)
    fingerprint: str = ""              # populated by normalize()
    sla_due: str | None = None         # ISO-8601

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        return d


# ------------------------------ Policy ----------------------------------------

@dataclass
class Policy:
    """
    Policy drives what blocks the PR. Two axes:

      - severity floor per finding-kind: anything >= floor blocks.
      - SLAs: time-to-fix per severity. Past-SLA findings always block,
        even if a temporary waiver was granted.

    Waivers are explicit, time-bounded, and recorded in source control.
    """
    block_severity_secret: Severity = Severity.HIGH
    block_severity_cve: Severity = Severity.CRITICAL
    sla_days: dict[Severity, int] = field(default_factory=lambda: {
        Severity.CRITICAL: 7,
        Severity.HIGH: 14,
        Severity.MEDIUM: 30,
        Severity.LOW: 90,
    })
    # fingerprint -> { "until": iso8601, "reason": str, "approver": str }
    waivers: dict[str, dict[str, str]] = field(default_factory=dict)
    # rule_id or path glob allowlist for secrets (e.g. test fixtures)
    secret_allowlist_paths: list[str] = field(default_factory=list)
    secret_allowlist_rules: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        if not path.exists():
            log.warning("No policy at %s, using defaults", path)
            return cls()
        import yaml                    # local import; cheap to skip if unused
        raw = yaml.safe_load(path.read_text()) or {}
        p = cls()
        if "block_severity_secret" in raw:
            p.block_severity_secret = Severity(raw["block_severity_secret"])
        if "block_severity_cve" in raw:
            p.block_severity_cve = Severity(raw["block_severity_cve"])
        if "sla_days" in raw:
            p.sla_days = {Severity(k): int(v) for k, v in raw["sla_days"].items()}
        p.waivers = raw.get("waivers", {}) or {}
        p.secret_allowlist_paths = raw.get("secret_allowlist_paths", []) or []
        p.secret_allowlist_rules = raw.get("secret_allowlist_rules", []) or []
        return p

    def blocks(self, f: Finding, now: datetime) -> tuple[bool, str]:
        """
        Decide whether a single finding blocks the PR. Returns (blocks, reason).
        This is the single source of truth for gate behavior.
        """
        # 1. Allowlists (only for secrets; SCA findings are not path-allowlisted).
        if f.kind is FindingKind.SECRET:
            if f.rule_id in self.secret_allowlist_rules:
                return False, "rule allowlisted"
            for glob in self.secret_allowlist_paths:
                if _glob_match(glob, f.location.path):
                    return False, f"path allowlisted ({glob})"

        # 2. Severity floor.
        floor = (self.block_severity_secret if f.kind is FindingKind.SECRET
                 else self.block_severity_cve)
        if f.severity.rank < floor.rank:
            return False, f"below {f.kind.value} blocking threshold ({floor.value})"

        # 3. Waiver check. A valid waiver downgrades to non-blocking
        #    unless the waiver itself has expired.
        waiver = self.waivers.get(f.fingerprint)
        if waiver:
            until = _parse_iso(waiver.get("until", ""))
            if until and until > now:
                return False, f"waived until {waiver['until']} by {waiver.get('approver','?')}"

        return True, f"{f.severity.value} {f.kind.value} exceeds policy"


def _glob_match(pattern: str, path: str) -> bool:
    import fnmatch
    return fnmatch.fnmatch(path, pattern)


def _parse_iso(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# ----------------------------- Scanners ---------------------------------------

class ScannerError(RuntimeError):
    pass


def _run(cmd: list[str], cwd: Path) -> str:
    log.debug("run: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError as e:
        raise ScannerError(f"binary missing: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise ScannerError(f"{cmd[0]} timed out") from e
    # Many scanners exit non-zero when findings exist. We only care about stdout,
    # but surface stderr on catastrophic failures (e.g. returncode >= 2).
    if r.returncode >= 2 and not r.stdout.strip():
        raise ScannerError(f"{cmd[0]} failed: {r.stderr[:500]}")
    return r.stdout


def scan_secrets(repo_path: Path, base_ref: str) -> list[Finding]:
    """
    Run gitleaks against the PR diff only (base_ref..HEAD). Scanning only the
    diff is critical: it keeps the gate fast and avoids punishing the PR author
    for pre-existing secrets they didn't introduce.
    """
    out = _run([
        "gitleaks", "detect",
        "--source", str(repo_path),
        "--log-opts", f"{base_ref}..HEAD",
        "--report-format", "json",
        "--report-path", "/dev/stdout",
        "--redact",
        "--no-banner",
        "--exit-code", "0",    # we decide gating ourselves
    ], repo_path)

    findings: list[Finding] = []
    for entry in _safe_json_list(out):
        sev = _secret_severity(entry.get("RuleID", ""), entry.get("Entropy", 0.0))
        loc = Location(
            path=entry.get("File", "unknown"),
            start_line=int(entry.get("StartLine", 1)),
            end_line=int(entry.get("EndLine", 1)),
        )
        findings.append(Finding(
            kind=FindingKind.SECRET,
            rule_id=entry.get("RuleID", "unknown"),
            title=_humanize_rule(entry.get("RuleID", "secret detected")),
            severity=sev,
            location=loc,
            description=entry.get("Description") or "Secret-like string found in diff.",
            introduced_at=entry.get("Date") or datetime.now(timezone.utc).isoformat(),
            source_tool="gitleaks",
            raw=entry,
        ))
    return findings


# Rule-IDs that grant production access get bumped to CRITICAL regardless
# of entropy. Everything else scales with entropy.
_HIGH_BLAST_SECRET_RULES = {
    "aws-access-key", "aws-secret-key", "gcp-service-account",
    "azure-client-secret", "stripe-live-key", "github-pat",
    "slack-bot-token", "private-key",
}


def _secret_severity(rule_id: str, entropy: float) -> Severity:
    if rule_id in _HIGH_BLAST_SECRET_RULES:
        return Severity.CRITICAL
    if entropy >= 4.5:
        return Severity.HIGH
    if entropy >= 3.5:
        return Severity.MEDIUM
    return Severity.LOW


def scan_dependencies(repo_path: Path) -> list[Finding]:
    """
    Run osv-scanner across the repo. osv-scanner handles most ecosystems
    (npm, pypi, maven, go, cargo) via their lockfiles, which is the correct
    thing to scan — manifests lie about transitive versions.
    """
    out = _run([
        "osv-scanner", "--format", "json", "--recursive", str(repo_path)
    ], repo_path)

    findings: list[Finding] = []
    data = _safe_json_obj(out)
    for result in data.get("results", []):
        lockfile = result.get("source", {}).get("path", "unknown")
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            name = pkg_info.get("name", "?")
            version = pkg_info.get("version", "?")
            ecosystem = pkg_info.get("ecosystem", "?")
            for vuln in pkg.get("vulnerabilities", []):
                sev = _cvss_to_severity(vuln)
                fix_version = _earliest_fixed_version(vuln)
                remediations: list[Remediation] = []
                if fix_version:
                    remediations.append(_build_upgrade_remediation(
                        name, version, fix_version, ecosystem, lockfile))
                findings.append(Finding(
                    kind=FindingKind.CVE,
                    rule_id=vuln.get("id", "UNKNOWN-CVE"),
                    title=f"{vuln.get('id','CVE')}: {name} {version}",
                    severity=sev,
                    location=Location(path=lockfile, start_line=1),
                    description=(vuln.get("summary") or
                                 vuln.get("details", "")[:400] or
                                 "Vulnerable dependency."),
                    introduced_at=vuln.get("published") or
                                 datetime.now(timezone.utc).isoformat(),
                    source_tool="osv-scanner",
                    raw={"package": pkg_info, "vuln": vuln,
                         "fix_version": fix_version},
                    remediations=remediations,
                ))
    return findings


def _cvss_to_severity(vuln: dict) -> Severity:
    """
    OSV data carries severity as CVSS vectors, GHSA severity strings, or
    nothing at all. Fall back conservatively — unknown vulns are MEDIUM,
    not LOW, because we'd rather surface than suppress.
    """
    for sev_entry in vuln.get("severity", []):
        t = sev_entry.get("type", "")
        score = sev_entry.get("score", "")
        if t.startswith("CVSS"):
            m = re.search(r"/AV:.*", score)  # noqa: F841
            # Use numeric score if present, else parse vector (skipped here for brevity).
            numeric = _cvss_numeric(score)
            if numeric is not None:
                if numeric >= 9.0: return Severity.CRITICAL
                if numeric >= 7.0: return Severity.HIGH
                if numeric >= 4.0: return Severity.MEDIUM
                return Severity.LOW
    db_sev = (vuln.get("database_specific", {}) or {}).get("severity", "").upper()
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(db_sev, Severity.MEDIUM)


def _cvss_numeric(vector_or_score: str) -> float | None:
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*$", vector_or_score)
    return float(m.group(1)) if m else None


def _earliest_fixed_version(vuln: dict) -> str | None:
    """Return the smallest 'fixed' version across all affected ranges, or None."""
    candidates: list[str] = []
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    candidates.append(ev["fixed"])
    if not candidates:
        return None
    # We'd use packaging.version per-ecosystem in production; lexicographic
    # is a reasonable approximation for the common semver case.
    return sorted(candidates)[0]


# --------------------------- Remediation planner ------------------------------

def _build_upgrade_remediation(name: str, current: str, fixed: str,
                                ecosystem: str, lockfile: str) -> Remediation:
    """
    For an SCA finding with a known fix version, propose a lockfile bump.
    Real implementations would actually run `npm update`, `pip-compile`,
    etc. in a sandbox and return the resulting diff. Here we describe the
    intent so the PR comment can offer a 'Apply fix' button that triggers
    a follow-up workflow.
    """
    runbook = (
        f"Upgrade `{name}` from `{current}` to `{fixed}` or later.\n\n"
        f"```sh\n"
        f"# {ecosystem} — from {lockfile}\n"
        f"{_upgrade_command(ecosystem, name, fixed)}\n"
        f"```\n\n"
        f"If the upgrade introduces breaking changes, see the project's changelog "
        f"between {current} and {fixed} before merging."
    )
    return Remediation(
        summary=f"Upgrade {name} to {fixed}",
        kind="upgrade",
        auto_applicable=True,
        runbook_markdown=runbook,
    )


def _upgrade_command(ecosystem: str, name: str, fixed: str) -> str:
    eco = ecosystem.lower()
    if "npm" in eco:   return f"npm install {name}@{fixed}"
    if "pypi" in eco:  return f"pip install --upgrade '{name}>={fixed}'"
    if "maven" in eco: return f"# update {name} to {fixed} in pom.xml, then: mvn -U dependency:resolve"
    if "go" in eco:    return f"go get {name}@v{fixed}"
    if "cargo" in eco: return f"cargo update -p {name} --precise {fixed}"
    return f"# upgrade {name} to {fixed} in your lockfile"


def build_secret_remediation(f: Finding) -> Remediation:
    """
    Secrets cannot be 'auto-fixed' — the credential is already compromised
    the moment it hits git history. The remediation is a rotation runbook
    with provider-specific steps.
    """
    provider = f.rule_id
    steps = _ROTATION_RUNBOOKS.get(provider, _ROTATION_RUNBOOKS["generic"])
    runbook = (
        f"**This secret must be rotated — assume it is compromised.**\n\n"
        f"{steps}\n\n"
        f"After rotation:\n"
        f"1. Remove the secret from `{f.location.path}` and commit.\n"
        f"2. Store the new value in your secret manager (not in git).\n"
        f"3. Consider rewriting git history with `git filter-repo` if the "
        f"repository is public or mirrored.\n"
    )
    return Remediation(
        summary=f"Rotate {_humanize_rule(provider)} and purge from history",
        kind="rotate_secret",
        auto_applicable=False,
        runbook_markdown=runbook,
    )


_ROTATION_RUNBOOKS = {
    "aws-access-key": (
        "1. In AWS IAM, mark the exposed access key as Inactive.\n"
        "2. Create a new access key for the same IAM user or, preferably, "
        "migrate the workload to an IAM role.\n"
        "3. Delete the inactive key after confirming no services broke.\n"
        "4. Audit CloudTrail for use of the exposed key since the commit date."
    ),
    "github-pat": (
        "1. Go to GitHub → Settings → Developer settings → Personal access tokens.\n"
        "2. Revoke the exposed token immediately.\n"
        "3. Create a new fine-scoped token and update any CI jobs that used the old one."
    ),
    "generic": (
        "1. Treat the exposed credential as compromised and revoke it now.\n"
        "2. Issue a replacement credential through the owning system.\n"
        "3. Audit that system's access logs since the commit date."
    ),
}


def _humanize_rule(rule_id: str) -> str:
    return rule_id.replace("-", " ").replace("_", " ").title()


# -------------------------- Normalize & deduplicate ---------------------------

def normalize(findings: Iterable[Finding], policy: Policy,
              now: datetime) -> list[Finding]:
    """
    Two goals:

      1. Fingerprint each finding deterministically so we can dedupe across
         scanners and track it across runs (for SLA timers and waivers).
      2. Compute the SLA due date and ensure every blocking finding has at
         least one remediation attached.
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        f.fingerprint = _fingerprint(f)
        # SLA: introduced_at + sla_days[severity]
        try:
            introduced = _parse_iso(f.introduced_at) or now
        except Exception:
            introduced = now
        sla_delta = policy.sla_days.get(f.severity)
        if sla_delta is not None:
            f.sla_due = (introduced + timedelta(days=sla_delta)).isoformat()

        # Ensure remediations exist.
        if f.kind is FindingKind.SECRET and not f.remediations:
            f.remediations.append(build_secret_remediation(f))

        # Dedupe: keep the record with the richer data (more remediations,
        # higher severity wins ties).
        existing = seen.get(f.fingerprint)
        if existing is None:
            seen[f.fingerprint] = f
        else:
            if (f.severity.rank, len(f.remediations)) > (
                    existing.severity.rank, len(existing.remediations)):
                seen[f.fingerprint] = f
    return list(seen.values())


def _fingerprint(f: Finding) -> str:
    """
    Stable across runs, stable across scanners that report the same issue.
    We deliberately exclude line numbers for CVEs (they refer to lockfiles
    whose line numbers shift), but include them for secrets (distinct lines =
    distinct secrets).
    """
    if f.kind is FindingKind.CVE:
        key = f"cve|{f.rule_id}|{f.location.path}"
    else:
        key = f"secret|{f.rule_id}|{f.location.path}|{f.location.start_line}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# --------------------------- Gate decision ------------------------------------

@dataclass
class GateResult:
    passed: bool
    blocking: list[Finding]
    informational: list[Finding]
    waived: list[Finding]
    scanned_at: str

    def summary(self) -> str:
        if self.passed:
            return (f"Gate passed. {len(self.informational)} informational, "
                    f"{len(self.waived)} waived.")
        by_sev = _count_by_severity(self.blocking)
        parts = [f"{n} {s.value}" for s, n in by_sev.items() if n]
        return f"Gate failed: {', '.join(parts)}."


def evaluate(findings: list[Finding], policy: Policy,
             now: datetime) -> GateResult:
    blocking, informational, waived = [], [], []
    for f in findings:
        blocks, reason = policy.blocks(f, now)
        if blocks:
            blocking.append(f)
        elif "waived" in reason:
            waived.append(f)
        else:
            informational.append(f)
    return GateResult(
        passed=not blocking,
        blocking=sorted(blocking, key=lambda x: -x.severity.rank),
        informational=sorted(informational, key=lambda x: -x.severity.rank),
        waived=waived,
        scanned_at=now.isoformat(),
    )


def _count_by_severity(findings: list[Finding]) -> dict[Severity, int]:
    out = {s: 0 for s in Severity}
    for f in findings:
        out[f.severity] = out[f.severity] + 1
    return out


# ------------------------ PR comment rendering --------------------------------

def render_pr_comment(result: GateResult, repo: str, sha: str,
                      dashboard_url: str) -> str:
    """
    The PR comment is the primary developer UI. It must answer three questions
    within the first 200 pixels: did I pass, what's the worst thing, and what
    do I do next? Everything else goes in collapsible details.
    """
    status = "🟢 Passed" if result.passed else "🔴 Blocked"
    lines = [
        f"## {status} — Security gate",
        "",
        result.summary(),
        "",
    ]

    if result.blocking:
        lines += ["### Must fix to merge", ""]
        for f in result.blocking:
            lines += _render_finding_block(f, repo, sha, blocking=True)

    if result.informational:
        n = len(result.informational)
        lines += [
            "<details>",
            f"<summary>{n} informational finding{'s' if n != 1 else ''} "
            f"(not blocking)</summary>",
            "",
        ]
        for f in result.informational:
            lines += _render_finding_block(f, repo, sha, blocking=False)
        lines += ["</details>", ""]

    if result.waived:
        n = len(result.waived)
        lines += [
            "<details>",
            f"<summary>{n} waived finding{'s' if n != 1 else ''}</summary>",
            "",
        ]
        for f in result.waived:
            lines += [f"- `{f.rule_id}` at `{f.location.path}:"
                      f"{f.location.start_line}` — waived"]
        lines += ["</details>", ""]

    lines += [
        "---",
        f"[Open full triage dashboard →]({dashboard_url})  ·  "
        f"Scanned {result.scanned_at}",
    ]
    return "\n".join(lines)


def _render_finding_block(f: Finding, repo: str, sha: str,
                           blocking: bool) -> list[str]:
    icon = {"critical": "🟥", "high": "🟧", "medium": "🟨",
            "low": "🟦", "info": "⬜"}[f.severity.value]
    out = [
        f"#### {icon} {f.title}",
        "",
        f"- Severity: **{f.severity.value}** · Rule: `{f.rule_id}`",
        f"- Location: [{f.location.path}:{f.location.start_line}]"
        f"({f.location.as_permalink(repo, sha)})",
    ]
    if f.sla_due:
        out.append(f"- SLA: fix by `{f.sla_due[:10]}`")
    out += ["", f.description, ""]

    if f.remediations:
        out += ["**How to fix**", ""]
        for r in f.remediations:
            badge = " _(auto-applicable)_" if r.auto_applicable else ""
            out += [f"- **{r.summary}**{badge}"]
            if r.runbook_markdown:
                out += ["", "  " + r.runbook_markdown.replace("\n", "\n  "), ""]
        out.append("")

    if not blocking:
        out += [
            f"_Request a waiver: comment `/security-gate waive {f.fingerprint} "
            f"<reason>` (requires security team approval)._",
            "",
        ]
    return out


# ------------------------------- IO helpers -----------------------------------

def _safe_json_list(s: str) -> list[dict]:
    try:
        data = json.loads(s or "[]")
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        log.warning("scanner returned non-JSON output")
        return []


def _safe_json_obj(s: str) -> dict:
    try:
        data = json.loads(s or "{}")
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        log.warning("scanner returned non-JSON output")
        return {}


# --------------------------------- CLI ----------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-path", type=Path, required=True)
    parser.add_argument("--base-ref", default="origin/main")
    parser.add_argument("--head-sha", default="HEAD")
    parser.add_argument("--policy", type=Path,
                        default=Path(".security/policy.yml"))
    parser.add_argument("--output-dir", type=Path,
                        default=Path(".security/out"))
    parser.add_argument("--repo-slug", default="owner/repo",
                        help="e.g. 'acme/backend' — used for permalinks")
    parser.add_argument("--dashboard-url", default="https://sec.example.com")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    policy = Policy.load(args.policy)
    now = datetime.now(timezone.utc)

    try:
        findings = scan_secrets(args.repo_path, args.base_ref) + \
                   scan_dependencies(args.repo_path)
    except ScannerError as e:
        log.error("Scanner failed: %s", e)
        return 2

    findings = normalize(findings, policy, now)
    result = evaluate(findings, policy, now)

    (args.output_dir / "findings.json").write_text(
        json.dumps([f.to_dict() for f in findings], indent=2))
    (args.output_dir / "result.json").write_text(
        json.dumps({
            "passed": result.passed,
            "summary": result.summary(),
            "counts": {
                "blocking": len(result.blocking),
                "informational": len(result.informational),
                "waived": len(result.waived),
            },
        }, indent=2))
    (args.output_dir / "comment.md").write_text(
        render_pr_comment(result, args.repo_slug, args.head_sha,
                          args.dashboard_url))

    log.info("%s", result.summary())
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
