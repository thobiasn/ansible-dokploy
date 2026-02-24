# Ansible Dokploy Deployment

A minimal Ansible playbook that provisions and hardens Debian/Ubuntu VPS servers for running [Dokploy](https://dokploy.com) (a self-hosted PaaS). Supports two modes: **control node** (installs Dokploy) and **external server node** (prepares a server to be added as a Dokploy worker).

---

## What This Playbook Does

When you run this playbook against a fresh VPS, it will:

- **Install system packages** — curl, vim, git, ufw, tmux, net-tools, and enable automatic security updates
- **Harden SSH** — change port to 2275, disable root and password login, restrict to pubkey-only with hardened ciphers
- **Set up Fail2ban** — SSH jail (aggressive mode) that bans after 3 failed attempts
- **Create a non-root user** — with your SSH key, a random system password, and passwordless sudo
- **Configure UFW firewall** — deny all incoming, allow outgoing, open ports 2275 (SSH), 80, and 443
- **Apply kernel hardening** — sysctl tweaks (SYN cookies, disable redirects, restrict ptrace/dmesg) and disable unused kernel modules (dccp, sctp, rds, tipc)
- **Install Dokploy** *(control node only)* — runs the official Dokploy install script
- **Deploy Traefik security headers** *(any node with Traefik)* — HSTS, content-type sniffing protection, frame denial, referrer policy, and more
- **Install CrowdSec intrusion prevention** *(any node with Traefik)* — community-driven IPS with Traefik bouncer plugin and shared blocklists

---

## Prerequisites

Before starting, make sure you have:

1. **A Debian or Ubuntu VPS** with root SSH access
2. **Ansible installed** on your local machine — follow the [official installation guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-and-upgrading-ansible-with-pip)
3. **The `community.general` and `community.docker` Ansible collections** installed:

```bash
ansible-galaxy collection install community.general community.docker
```

4. **An SSH key pair** — you'll need the path to your public key file

---

## Quick Start

### Step 1: Clone the repository

```bash
git clone <repo-url>
cd ansible-dokploy
```

### Step 2: Create and configure the inventory file

```bash
cp hosts.example hosts
```

Edit `hosts` and fill in your VPS details:

```ini
[servers]
vps ansible_host=YOUR_VPS_IP ansible_port=22 ansible_user=root ansible_ssh_private_key_file=~/.ssh/id_ed25519
```

- `ansible_host` — your VPS IP address
- `ansible_port` — `22` for the first run (the playbook will change it to `2275`)
- `ansible_user` — `root` for the first run
- `ansible_ssh_private_key_file` — path to your SSH **private** key

### Step 3: Configure playbook variables

Edit `playbook.yml` and update the `vars` section:

```yaml
vars:
  ssh_port: 2275        # SSH port (must match hosts file after first run)
  user_name: admin      # replace with your desired username
  user_ssh_key: "{{ lookup('file', '~/.ssh/id_ed25519.pub') }}"  # path to your public key
  is_control_node: true  # set to false for external worker nodes
  cloudflare_proxy: false # set to true if domain uses Cloudflare proxy (orange cloud)
  ufw_extra_ports: []     # additional UFW ports to open, e.g. [{port: 25, proto: tcp}]
```

- `ssh_port` — the SSH port used by sshd, UFW, and fail2ban (default: `2275`). If you change this, also update `ansible_port` in your `hosts` file
- `user_name` — the non-root user the playbook creates on the server
- `user_ssh_key` — a `file` lookup pointing to your SSH **public** key (this gets copied to the server)
- `is_control_node` — `true` by default (installs Dokploy), set to `false` for worker nodes. Traefik security headers and CrowdSec run automatically on any node where Traefik is installed
- `cloudflare_proxy` — set to `true` if your domain uses Cloudflare proxy (orange cloud). Configures Traefik to trust Cloudflare's forwarded headers so CrowdSec sees real visitor IPs
- `ufw_extra_ports` — list of additional ports to open in UFW beyond the defaults (SSH port, 80, 443). Each entry needs `port` and optionally `proto` (defaults to `tcp`)

### Step 4: Run the playbook (first run)

```bash
ansible-playbook -i hosts playbook.yml -l vps -u root --become
```

> Replace `root` with whichever user your VPS provider gives you for initial access.

**Important:** The playbook changes the SSH port from 22 to **2275** and disables root login. After it finishes, you can no longer connect on port 22 or as root.

### Step 5: Update inventory for subsequent runs

Edit your `hosts` file and change the port and user:

```ini
[servers]
vps ansible_host=YOUR_VPS_IP ansible_port=2275 ansible_user=admin ansible_ssh_private_key_file=~/.ssh/id_ed25519
```

- Change `ansible_port` from `22` to `2275`
- Change `ansible_user` from `root` to your `user_name` (e.g. `admin`)

### Step 6: Subsequent runs

```bash
ansible-playbook -i hosts playbook.yml -l vps -u admin
```

To do a dry run first:

```bash
ansible-playbook -i hosts playbook.yml -l vps -u admin --check
```

To run only the UFW rules:

```bash
ansible-playbook -i hosts playbook.yml -l vps -u admin --tags ufw_rules
```

---

## Setting Up the Dokploy Control Node

If you set `is_control_node: true`, the playbook installs Dokploy on the server.

After the playbook completes:

1. Create an SSH tunnel to access the Dokploy UI:

```bash
ssh -L 8080:localhost:8080 -p 2275 admin@YOUR_VPS_IP
```

2. Visit `http://localhost:8080` in your browser to complete the Dokploy setup.
3. Set up your domain in Dokploy and create an `A` record pointing to your VPS IP. Once configured, you can access Dokploy directly from your domain without the SSH tunnel.

---

## Setting Up External Server Nodes

For servers where `is_control_node: false` (the default), the playbook only provisions and hardens the server — it does **not** install Dokploy.

To add the server as a Dokploy worker node:

1. SSH into the server:

```bash
ssh -p 2275 admin@YOUR_VPS_IP
```

2. Run the node setup script **with sudo** (installs Docker, Swarm, Traefik, and other Dokploy requirements):

```bash
sudo ./node-setup.sh
```

> This script is copied from Dokploy's UI. If Dokploy updates their setup process, you may need to update `scripts/node-setup.sh` manually.

3. Run the user groups script **with sudo** (adds your user to docker and dokploy groups):

```bash
sudo ./node-setup-user-groups.sh
```

4. **Log out and back in** for the group membership to take effect.

5. **Re-run the playbook** to deploy Traefik security headers and CrowdSec (now that Traefik is installed):

```bash
ansible-playbook -i hosts playbook.yml -l vps -u admin
```

6. Back in Dokploy's UI on the control node, add this server as a remote server.

---

## Security Helpers

The playbook deploys `security.sh` to `/root/security.sh` and sources it in root's `.bashrc`. When logged in as root (or via `sudo -i`), you get these helper functions:

| Function | Description |
| --- | --- |
| `check_successful_ssh_logins` | Show successful SSH logins from auth.log |
| `check_failed_ssh_logins` | Show failed SSH login attempts |
| `block_ip <ip>` | Block an IP address via UFW |
| `unblock_ip <ip>` | Remove a UFW block on an IP |
| `check_blocked_ips` | List all IPs blocked by UFW |
| `monitor_bruteforce_attempts` | Summarize brute-force attempts from auth.log |
| `check_ufw_status` | Show current UFW firewall status |
| `show_last_logins` | Show last 20 login entries |
| `list_all_ssh_connections` | List current active SSH connections |
| `watch_ssh` | Tail auth.log in real-time |
| `restart_ssh_service` | Restart the SSH daemon |
| `restart_machine` | Reboot the server |

---

## Traefik Security Headers

The playbook deploys a Traefik dynamic config file at `/etc/dokploy/traefik/dynamic/security-headers.yml` that defines a `security-headers` middleware with the following headers:

| Header | Value | Purpose |
| --- | --- | --- |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` | Force HTTPS for 1 year |
| X-Content-Type-Options | `nosniff` | Prevent MIME-type sniffing |
| X-Frame-Options | `DENY` | Block iframe embedding |
| Referrer-Policy | `strict-origin-when-cross-origin` | Limit referrer leakage |
| Permissions-Policy | Deny camera, microphone, geolocation, payment, usb, interest-cohort | Restrict browser APIs |
| Server / X-Powered-By | *(empty)* | Hide server identity |

### Applying the Middleware

Add `security-headers@file` to your service's Traefik labels:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=security-headers@file"
```

Or in the Dokploy UI: go to your service's **Advanced** > **Traefik** settings and add `security-headers@file` to the middleware list.

### Chaining Multiple Middlewares

Combine middlewares with commas:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=security-headers@file,crowdsec-bouncer@file"
```

### Overriding frameDeny for Iframes

If a service needs to be embedded in an iframe, create a separate dynamic config file that overrides `frameDeny`:

```yaml
# /etc/dokploy/traefik/dynamic/allow-frames.yml
http:
  middlewares:
    allow-frames:
      headers:
        frameDeny: false
        customFrameOptionsValue: "SAMEORIGIN"
```

Then use `allow-frames@file` instead of (or in addition to) `security-headers@file` for that service.

---

## CrowdSec Intrusion Prevention

The playbook installs [CrowdSec](https://www.crowdsec.net/) on any node where Traefik is installed — a community-driven intrusion prevention system that detects and blocks malicious traffic using behavioral analysis and shared blocklists.

### What Gets Installed

- **CrowdSec agent** — monitors Traefik access logs for suspicious patterns
- **Traefik collection** (`crowdsecurity/traefik`) — detection scenarios for HTTP attacks (scanners, brute-force, etc.)
- **Traefik bouncer plugin** — a Traefik middleware that checks incoming requests against CrowdSec decisions and blocks banned IPs
- **Community blocklists** — automatically shared threat intelligence from the CrowdSec network

### LAPI Connectivity

The playbook automatically configures LAPI (CrowdSec's Local API) connectivity:

- Binds LAPI to `0.0.0.0:8080` so Docker containers can reach it (UFW still blocks external access since port 8080 is not opened)
- Detects the `docker_gwbridge` gateway IP and uses it in the bouncer middleware config so the Traefik Swarm container can reach the host's LAPI

### Traefik Static Config

The playbook appends two blocks to `/etc/dokploy/traefik/traefik.yml`:

1. **CrowdSec bouncer plugin** — registers the plugin under `experimental.plugins`
2. **Access log** — enables JSON access logs at `/etc/dokploy/traefik/dynamic/access.log`

> **Note:** Dokploy may overwrite `traefik.yml` during updates. If the CrowdSec plugin or access log config disappears, re-run the playbook to restore it.

### Applying the Bouncer Middleware

Add `crowdsec-bouncer@file` to your service's Traefik labels:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=crowdsec-bouncer@file"
```

Or combine with security headers:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=security-headers@file,crowdsec-bouncer@file"
```

### Useful CrowdSec Commands

| Command | Description |
| --- | --- |
| `cscli decisions list` | Show currently active bans |
| `cscli alerts list` | Show recent alerts |
| `cscli bouncers list` | List registered bouncers |
| `cscli collections list` | List installed detection collections |
| `cscli hub update` | Update the hub (scenarios, parsers, etc.) |
| `cscli hub upgrade` | Upgrade installed hub items |
| `cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual ban"` | Manually ban an IP |
| `cscli decisions delete --ip 1.2.3.4` | Unban an IP |
| `cscli metrics` | Show CrowdSec metrics |

### Cloudflare Users

If your domain uses Cloudflare with the orange cloud (proxy) enabled, Traefik will only see Cloudflare's IP addresses by default — not the real visitor IPs. To fix this, set `cloudflare_proxy: true` in your playbook variables. This configures Traefik to trust Cloudflare's forwarded headers (`CF-Connecting-IP` / `X-Forwarded-For`) so access logs contain real client IPs and CrowdSec can identify individual attackers.

The playbook adds Cloudflare's published IPv4 and IPv6 ranges to Traefik's `entryPoints.*.forwardedHeaders.trustedIPs`. If Cloudflare updates their IP ranges, update the list in `roles/crowdsec/tasks/main.yml` — the current ranges are from [cloudflare.com/ips](https://www.cloudflare.com/ips/).

> **Note:** If Dokploy overwrites `traefik.yml`, re-run the playbook to restore the trusted IPs configuration.

---

## System Hardening

This playbook includes a set of safe hardening measures that work well with Dokploy, Docker, Traefik, Cloudflare, and typical web apps. These settings are intentionally conservative and should not break normal workloads.

### Kernel / sysctl Hardening

A `/etc/sysctl.d/99-hardening.conf` file is installed with safe defaults:

- Keep IP forwarding on (required for Docker)
- Disable ICMP redirects
- Enable SYN cookies (basic DoS protection)
- Log suspicious packets ("martians")

Additional local protections:

- Disable SUID core dumps
- Restrict ptrace (one user can't inspect another's processes)
- Restrict access to kernel logs and pointers
- Restrict perf events to root
- Raise file watcher limits (useful for Node apps)

To temporarily disable:

```bash
mv /etc/sysctl.d/99-hardening.conf /etc/sysctl.d/99-hardening.conf.disabled
sysctl --system
```

### Disabled Kernel Modules

A `/etc/modprobe.d/hardening.conf` file disables unused protocols: dccp, sctp, rds, tipc. These are not needed on typical servers and disabling them is safe.

### Random Local Password for Admin User

The admin user receives a random system password (stored only in `/etc/shadow`). Password login over SSH is still disabled — this is just for local console safety.

### Fail2ban Protection

Fail2ban protects SSH with aggressive mode, banning IPs after 3 failed login attempts for 10 minutes.

### CrowdSec Protection

CrowdSec monitors Traefik access logs for malicious patterns (scanners, brute-force, exploits) and blocks offending IPs via the Traefik bouncer plugin. See the [CrowdSec Intrusion Prevention](#crowdsec-intrusion-prevention) section for details.

---

## Troubleshooting

### Locked out after first run

If you can't connect after the first run, the SSH port has changed to **2275**. Connect with:

```bash
ssh -p 2275 admin@YOUR_VPS_IP
```

If that doesn't work either, use your VPS provider's web console to access the server.

### Ansible fails with "could not find community.general"

Install the required collection:

```bash
ansible-galaxy collection install community.general
```

### VPS provider firewall blocking port 2275

Some VPS providers (e.g. Oracle Cloud, AWS) have an external firewall or security group in addition to the server's UFW. Make sure port **2275** is allowed in your provider's firewall/security group settings.
