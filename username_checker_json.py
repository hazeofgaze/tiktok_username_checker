import csv
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

INPUT_FILE = "usernames.txt"
RESULTS_FILE = "candidate_usernames_json.txt"
PROGRESS_FILE = "checked_usernames_json.txt"
LOG_FILE = "username_status_log_json.csv"
JSON_SAMPLES_FILE = "json_response_samples.jsonl"

MIN_DELAY = 1.1
RETRY_DELAY = 5.0
MAX_RETRIES = 3
TIMEOUT = 15

# These codes are community-reported, not official proof of availability.
NOT_FOUND_CODES = {10202, 10221}
SKIP_NUMERIC_ONLY = True
VALID_USERNAME = re.compile(r"^[a-z0-9._]{2,24}$", re.IGNORECASE)

REHYDRATION_RE = re.compile(
    r'<script\b(?=[^>]*\bid=["\']__UNIVERSAL_DATA_FOR_REHYDRATION__["\'])'
    r'[^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE,
)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

LOG_FIELDS = [
    "timestamp_utc",
    "username",
    "result",
    "attempts",
    "http_status",
    "embedded_status_code",
    "embedded_status_msg",
    "user_info_state",
    "returned_unique_id",
    "json_script_found",
    "scope_keys",
    "detail_path",
    "detail_keys",
    "json_signature",
    "final_url",
    "reason",
]


def new_diagnostic(name):
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "username": name,
        "result": "unknown",
        "attempts": 0,
        "http_status": "",
        "embedded_status_code": "",
        "embedded_status_msg": "",
        "user_info_state": "not parsed",
        "returned_unique_id": "",
        "json_script_found": "no",
        "scope_keys": "",
        "detail_path": "",
        "detail_keys": "",
        "_json_sample": None,
        "json_signature": "",
        "final_url": f"https://www.tiktok.com/@{name}",
        "reason": "No conclusive result",
    }


def load_usernames():
    """Load, validate, deduplicate, and skip completed usernames."""
    if not os.path.isfile(INPUT_FILE):
        print(f"ERROR: Can't find {INPUT_FILE}")
        print("Put the input text file in the same folder as this script.")
        sys.exit(1)

    names = []
    seen = set()
    invalid = 0
    numeric_skipped = 0

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        for line in file:
            name = line.strip().lstrip("@").lower()

            if not name or name in seen:
                continue

            seen.add(name)

            if not VALID_USERNAME.fullmatch(name):
                print(f"[INVALID] {name}")
                invalid += 1
                continue

            if SKIP_NUMERIC_ONLY and name.isdigit():
                print(f"[SKIP - NUMERIC ONLY] {name}")
                numeric_skipped += 1
                continue

            names.append(name)

    checked = set()

    if os.path.isfile(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r", encoding="utf-8") as file:
            checked = {
                line.strip().lower()
                for line in file
                if line.strip()
            }

    pending = [name for name in names if name not in checked]

    return pending, len(checked), invalid, numeric_skipped


def find_detail_object(scope):
    """Find a recognizable TikTok profile-detail object."""
    preferred_paths = (
        "webapp.user-detail",
        "webapp.reflow.profile.initial",
    )

    for path in preferred_paths:
        value = scope.get(path)

        if isinstance(value, dict):
            return value, path

    def walk(value, path="__DEFAULT_SCOPE__"):
        if isinstance(value, dict):
            path_lower = path.lower()

            if (
                "userInfo" in value
                and "statusCode" in value
                and (
                    "profile" in path_lower
                    or "user-detail" in path_lower
                )
            ):
                return value, path

            for key, child in value.items():
                found = walk(child, f"{path}.{key}")

                if found is not None:
                    return found

        elif isinstance(value, list):
            for index, child in enumerate(value):
                found = walk(child, f"{path}[{index}]")

                if found is not None:
                    return found

        return None

    return walk(scope) or (None, "")


def json_safe_summary(detail, scope, detail_path, user_info):
    """Summarize the JSON structure for diagnostics."""
    user = user_info.get("user") if isinstance(user_info, dict) else None

    return {
        "scope_keys": sorted(str(key) for key in scope.keys()),
        "detail_path": detail_path,
        "detail_keys": sorted(str(key) for key in detail.keys()),
        "statusCode": detail.get("statusCode"),
        "statusMsg": detail.get("statusMsg"),
        "userInfo_type": type(user_info).__name__,
        "userInfo_keys": (
            sorted(str(key) for key in user_info.keys())
            if isinstance(user_info, dict)
            else []
        ),
        "user_type": (
            type(user).__name__
            if user is not None
            else "null-or-missing"
        ),
        "user_keys": (
            sorted(str(key) for key in user.keys())
            if isinstance(user, dict)
            else []
        ),
    }


def parse_profile_page(html, requested_name, diagnostic):
    """Parse embedded JSON and classify recognizable responses."""
    match = REHYDRATION_RE.search(html)

    if not match:
        diagnostic["reason"] = "Embedded TikTok JSON script not found"
        diagnostic["user_info_state"] = "not parsed"
        return "unknown"

    diagnostic["json_script_found"] = "yes"

    try:
        data = json.loads(match.group(1))
    except (json.JSONDecodeError, TypeError) as error:
        diagnostic["reason"] = (
            f"Embedded JSON could not be parsed: {error}"
        )
        diagnostic["user_info_state"] = "invalid JSON"
        return "unknown"

    if not isinstance(data, dict):
        diagnostic["reason"] = "Embedded JSON root is not an object"
        return "unknown"

    scope = data.get("__DEFAULT_SCOPE__")

    if not isinstance(scope, dict):
        diagnostic["reason"] = "Expected __DEFAULT_SCOPE__ object missing"
        diagnostic["reason"] += (
            f"; root keys={','.join(sorted(map(str, data.keys()))[:20])}"
        )
        return "unknown"

    diagnostic["scope_keys"] = " | ".join(
        sorted(map(str, scope.keys()))
    )

    detail, detail_path = find_detail_object(scope)

    if not isinstance(detail, dict):
        diagnostic["reason"] = (
            "Profile detail object not found in embedded JSON"
        )
        return "unknown"

    diagnostic["detail_path"] = detail_path
    diagnostic["detail_keys"] = " | ".join(
        sorted(map(str, detail.keys()))
    )

    raw_status = detail.get("statusCode")
    diagnostic["embedded_status_code"] = (
        "" if raw_status is None else str(raw_status)
    )

    raw_message = detail.get("statusMsg")
    diagnostic["embedded_status_msg"] = (
        "" if raw_message is None else str(raw_message)
    )

    user_info = detail.get("userInfo")

    if "userInfo" not in detail or user_info is None:
        diagnostic["user_info_state"] = "absent or null"
    elif isinstance(user_info, dict):
        diagnostic["user_info_state"] = "present"
    else:
        diagnostic["user_info_state"] = (
            f"unexpected type: {type(user_info).__name__}"
        )

    summary = json_safe_summary(
        detail, scope, detail_path, user_info
    )

    signature_source = json.dumps(
        summary,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )

    signature = hashlib.sha256(
        signature_source.encode("utf-8")
    ).hexdigest()[:16]

    diagnostic["json_signature"] = signature
    diagnostic["_json_sample"] = {
        "signature": signature,
        "example_username": requested_name,
        "summary": summary,
        "userInfo": user_info,
    }

    try:
        status_code = int(raw_status)
    except (TypeError, ValueError):
        status_code = None

    if isinstance(user_info, dict) and "user" in user_info:
        user = user_info.get("user")

        if isinstance(user, dict):
            unique_id = str(user.get("uniqueId") or "").strip().lower()
            diagnostic["returned_unique_id"] = unique_id

            if unique_id and unique_id == requested_name.lower():
                diagnostic["reason"] = (
                    "Embedded profile uniqueId exactly matches "
                    "requested username"
                )
                return "taken"

            diagnostic["reason"] = (
                "User object present but uniqueId missing or does not match"
            )
            return "unknown"

        diagnostic["reason"] = (
            "userInfo contains a non-object user value"
        )
        return "unknown"

    if user_info is None and status_code in NOT_FOUND_CODES:
        diagnostic["reason"] = (
            f"No userInfo and statusCode {raw_status} is in the "
            "configured community-reported not-found set; "
            "claimability is unconfirmed"
        )
        return "candidate"

    diagnostic["reason"] = (
        "Embedded response did not match a known profile or "
        "configured not-found pattern"
    )
    return "unknown"


def check_username(session, name):
    """Check one profile and return its result, stop flag, and diagnostics."""
    url = f"https://www.tiktok.com/@{name}"
    diagnostic = new_diagnostic(name)

    for attempt in range(1, MAX_RETRIES + 1):
        diagnostic["attempts"] = attempt

        try:
            response = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
            )
        except requests.RequestException as error:
            diagnostic["reason"] = f"Request error: {error}"

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue

            return "unknown", False, diagnostic

        diagnostic["http_status"] = response.status_code
        diagnostic["final_url"] = response.url

        if response.status_code in (403, 429):
            diagnostic["reason"] = (
                f"TikTok restricted the request "
                f"(HTTP {response.status_code})"
            )
            return "unknown", True, diagnostic

        if response.status_code >= 500:
            diagnostic["reason"] = (
                f"TikTok/server returned HTTP {response.status_code}"
            )

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue

            return "unknown", False, diagnostic

        if response.status_code != 200:
            diagnostic["reason"] = (
                f"Unexpected HTTP status {response.status_code}; "
                "status alone is inconclusive"
            )
            return "unknown", False, diagnostic

        result = parse_profile_page(
            response.text, name, diagnostic
        )

        return result, False, diagnostic

    return "unknown", False, diagnostic


def append_line(path, value):
    with open(path, "a", encoding="utf-8") as file:
        file.write(value + "\n")


def log_diagnostic(diagnostic):
    """Write one diagnostic row per username to the CSV."""
    file_exists = (
        os.path.isfile(LOG_FILE)
        and os.path.getsize(LOG_FILE) > 0
    )

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=LOG_FIELDS,
            extrasaction="ignore",
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(diagnostic)


def load_json_sample_signatures():
    """Load signatures already saved to avoid duplicate samples."""
    signatures = set()

    if not os.path.isfile(JSON_SAMPLES_FILE):
        return signatures

    try:
        with open(JSON_SAMPLES_FILE, "r", encoding="utf-8") as file:
            for line in file:
                try:
                    row = json.loads(line)

                    if row.get("signature"):
                        signatures.add(row["signature"])

                except json.JSONDecodeError:
                    continue

    except OSError:
        pass

    return signatures


def log_json_sample(diagnostic, saved_signatures):
    """Save one compact sample for each distinct JSON response shape."""
    sample = diagnostic.get("_json_sample")

    if not isinstance(sample, dict):
        return

    signature = sample.get("signature")

    if not signature or signature in saved_signatures:
        return

    with open(
        JSON_SAMPLES_FILE,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                sample,
                ensure_ascii=False,
                default=str,
            ) + "\n"
        )

    saved_signatures.add(signature)


def main():
    names, skipped, invalid, numeric_skipped = load_usernames()

    if not names:
        print("No new valid usernames to check.")
        print(f"Previously completed entries skipped: {skipped}")
        print(f"Invalid entries ignored: {invalid}")
        print(f"Numeric-only usernames skipped: {numeric_skipped}")
        print(f"Diagnostic log: {LOG_FILE}")
        return

    print(f"Input: {INPUT_FILE}")
    print(
        f"Queued: {len(names)} | Previously completed: {skipped} | "
        f"Invalid: {invalid} | Numeric-only skipped: {numeric_skipped}"
    )
    print(
        f"Each result, including embedded statusCode, "
        f"will be logged to {LOG_FILE}."
    )
    print(
        "Results are provisional. "
        "The script stops if TikTok restricts access.\n"
    )

    stats = {
        "taken": 0,
        "candidate": 0,
        "unknown": 0,
    }

    saved_json_signatures = load_json_sample_signatures()
    session = requests.Session()
    session.headers.update(HEADERS)
    stop_run = False

    try:
        for index, name in enumerate(names, start=1):
            print(
                f"[{index}/{len(names)}] @{name}",
                end=" ",
                flush=True,
            )

            result, should_stop, diagnostic = check_username(
                session, name
            )

            diagnostic["result"] = result
            log_diagnostic(diagnostic)

            try:
                log_json_sample(
                    diagnostic,
                    saved_json_signatures,
                )
            except OSError as error:
                print(
                    f"\nWarning: couldn't save JSON sample: {error}"
                )

            embedded_code = (
                diagnostic.get("embedded_status_code") or "none"
            )
            http_code = diagnostic.get("http_status") or "none"

            if should_stop:
                print(
                    f"[BLOCKED / UNKNOWN] HTTP={http_code}; "
                    f"statusCode={embedded_code}; see {LOG_FILE}"
                )
                stop_run = True
                break

            stats[result] += 1

            if result == "taken":
                print(
                    f"[TAKEN] HTTP={http_code}; "
                    f"statusCode={embedded_code}"
                )
                append_line(PROGRESS_FILE, name)

            elif result == "candidate":
                print(
                    f"[CANDIDATE - VERIFY MANUALLY] "
                    f"HTTP={http_code}; statusCode={embedded_code}"
                )
                append_line(RESULTS_FILE, name)
                append_line(PROGRESS_FILE, name)

            else:
                print(
                    f"[UNKNOWN - NOT MARKED COMPLETE] "
                    f"HTTP={http_code}; statusCode={embedded_code}; "
                    f"reason={diagnostic['reason']}"
                )

            if index < len(names):
                time.sleep(MIN_DELAY)

    except KeyboardInterrupt:
        print(
            "\nStopped by keyboard. Completed results and "
            "diagnostic rows were saved."
        )

    finally:
        session.close()

    print("\nSummary")
    print(f"Taken: {stats['taken']}")
    print(
        f"Candidates to verify manually: {stats['candidate']}"
    )
    print(f"Unknown: {stats['unknown']}")
    print(f"Candidate file: {RESULTS_FILE}")
    print(f"Diagnostic CSV: {LOG_FILE}")
    print(f"JSON response-shape samples: {JSON_SAMPLES_FILE}")
    print(f"Progress file: {PROGRESS_FILE}")

    if stop_run:
        print("TikTok restricted the request; the run was stopped.")


if __name__ == "__main__":
    main()
