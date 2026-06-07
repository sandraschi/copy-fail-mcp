set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

# Open the interactive recipe dashboard in the browser
default:
    @just --list

# ── Quality ───────────────────────────────────────────────────────────────────

# Ruff linting
lint:
    Set-Location '{{justfile_directory()}}'
    uv run ruff check .

# Ruff + Biome fix
fix:
    Set-Location '{{justfile_directory()}}'
    uv run ruff check . --fix --unsafe-fixes
    uv run ruff format .
    Set-Location '{{justfile_directory()}}\webapp'
    npx @biomejs/biome check --write .

# ── Testing ──────────────────────────────────────────────────────────────────

# Run tests
test:
    Set-Location '{{justfile_directory()}}'
    uv run pytest -v

# ── Hardening ─────────────────────────────────────────────────────────────────

# Security audit
check-sec:
    Set-Location '{{justfile_directory()}}'
    uv run bandit -r src/

# Dependency audit
audit-deps:
    Set-Location '{{justfile_directory()}}'
    uv run safety check

