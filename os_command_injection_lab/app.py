from __future__ import annotations

import subprocess

from flask import Flask, render_template, request

app = Flask(__name__)

MAX_TARGET_LENGTH = 128
COMMAND_TIMEOUT_SECONDS = 5


def page(
    *,
    vulnerable_input: str = "127.0.0.1",
    vulnerable_output: str | None = None,
    vulnerable_status: int | None = None,
    secure_input: str = "127.0.0.1",
    secure_output: str | None = None,
    secure_status: int | None = None,
    error: str | None = None,
):
    return render_template(
        "index.html",
        vulnerable_input=vulnerable_input,
        vulnerable_output=vulnerable_output,
        vulnerable_status=vulnerable_status,
        secure_input=secure_input,
        secure_output=secure_output,
        secure_status=secure_status,
        error=error,
    )


def combine_output(result: subprocess.CompletedProcess[str]) -> str:
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    if output.strip():
        return output.strip()
    if result.returncode != 0:
        return f"(No output; command exited with status {result.returncode}.)"
    return "(The command produced no output.)"


def validate_length(target: str) -> str | None:
    if not target.strip():
        return "Enter a target first."
    if len(target) > MAX_TARGET_LENGTH:
        return f"Target must be {MAX_TARGET_LENGTH} characters or fewer."
    return None


@app.get("/")
def index():
    return page()


@app.post("/run/vulnerable")
def run_vulnerable():
    target = request.form.get("target", "")
    length_error = validate_length(target)
    if length_error:
        return page(vulnerable_input=target, error=length_error), 400

    # INTENTIONALLY VULNERABLE FOR THIS LOCAL COURSE LAB.
    # User input is interpolated into a shell command string. Shell metacharacters
    # such as ';' are interpreted by the shell, allowing an additional command.
    command = f"getent hosts {target}"
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        return page(
            vulnerable_input=target,
            vulnerable_output=combine_output(result),
            vulnerable_status=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return page(
            vulnerable_input=target,
            vulnerable_output=f"Command timed out after {COMMAND_TIMEOUT_SECONDS} seconds.",
        )
    except Exception as exc:  # Visible diagnostics help during the local lab.
        return page(vulnerable_input=target, error=f"Vulnerable demo error: {exc}"), 500


@app.post("/run/secure")
def run_secure():
    target = request.form.get("target", "")
    length_error = validate_length(target)
    if length_error:
        return page(secure_input=target, error=length_error), 400

    # MITIGATION: do not invoke a shell. Each list item becomes one argv element.
    # A value such as '127.0.0.1; id' is passed literally as the target argument;
    # the semicolon is not treated as a command separator by a shell.
    command = ["getent", "hosts", target]
    try:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        return page(
            secure_input=target,
            secure_output=combine_output(result),
            secure_status=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return page(
            secure_input=target,
            secure_output=f"Command timed out after {COMMAND_TIMEOUT_SECONDS} seconds.",
        )
    except FileNotFoundError:
        return page(
            secure_input=target,
            secure_output="The 'getent' utility was not found. This demo is intended for a glibc-based Linux system.",
        ), 500
    except Exception as exc:
        return page(secure_input=target, error=f"Secure demo error: {exc}"), 500


if __name__ == "__main__":
    # Deliberately bind to loopback only. Do not expose this vulnerable lab to a network.
    app.run(host="127.0.0.1", port=5000, debug=False)
