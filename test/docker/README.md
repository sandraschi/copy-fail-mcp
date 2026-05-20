# Copy Fail MCP — Test Infrastructure

Docker-based SSH target for validating the copy-fail-mcp pipeline
(SSH connection, script deployment, command execution, output parsing).

## Quick Start

```powershell
cd test\docker
docker compose up -d

# Test SSH with key
ssh -i ../keys/id_test_rsa -o StrictHostKeyChecking=no testuser@localhost -p 10966

# Or with password (password: test)
ssh -o StrictHostKeyChecking=no testuser@localhost -p 10966
```

## Test the Pipeline

```powershell
# Start the MCP server
uv run copy-fail serve --http --port 10955

# Check target (will show non-vulnerable - Docker shares host kernel)
uv run copy-fail check --host localhost --port 10966 --user testuser
```

## Limitations

The exploit (CVE-2026-31431) requires a host kernel with
`CONFIG_CRYPTO_USER_API_AEAD=y|m` and no Docker seccomp blocking
AF_ALG `accept()`. Neither are available on this machine.

The container validates the **pipeline only** (SSH, deploy, execute,
parse output) - not the exploit mechanics.

## For Full Exploit Testing

Provision a VM with an unpatched kernel (>= 4.14, AEAD enabled):

| Option | Method |
|--------|--------|
| VirtualBox VM | Use `virtualization-mcp` to create VM, install Ubuntu 22.04 (kernel 5.15, AEAD=y) |
| Dedicated Linux HW | Direct Linux install |
| Cloud VM | AWS EC2 / DO droplet with older Ubuntu AMI |

On the VM: install SSH server, add your public key, then use copy-fail-mcp tools:
```powershell
uv run copy-fail check --host <VM-IP> --port 22 --user ubuntu
```

## Troubleshooting

```powershell
docker logs cf-test
docker compose down
docker compose up -d
```
