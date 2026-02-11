# Ansible Dokploy Deployment

A minimal Ansible playbook that provisions and hardens Debian/Ubuntu VPS servers for running [Dokploy](https://dokploy.com) (a self-hosted PaaS). Supports two modes: **control node** (installs Dokploy) and **external server node** (prepares a server to be added as a Dokploy worker).

---

## What This Playbook Does

When you run this playbook against a fresh VPS, it will:

- **Install system packages** — curl, vim, git, ufw, tmux, net-tools, and enable automatic security updates
- **Harden SSH** — change port to 2275, disable root and password login, restrict to pubkey-only with hardened ciphers
- **Set up Fail2ban** — SSH jail (aggressive mode) and a Traefik HTTP jail for repeated 4xx abuse
- **Create a non-root user** — with your SSH key, a random system password, and passwordless sudo
- **Configure UFW firewall** — deny all incoming, allow outgoing, open ports 2275 (SSH), 80, and 443
- **Apply kernel hardening** — sysctl tweaks (SYN cookies, disable redirects, restrict ptrace/dmesg) and disable unused kernel modules (dccp, sctp, rds, tipc)
- **Install Dokploy** *(control node only)* — runs the official Dokploy install script

---

## Prerequisites

Before starting, make sure you have:

1. **A Debian or Ubuntu VPS** with root SSH access
2. **Ansible installed** on your local machine — follow the [official installation guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-and-upgrading-ansible-with-pip)
3. **The `community.general` Ansible collection** installed (required for the UFW module):

```bash
ansible-galaxy collection install community.general
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
  user_name: admin      # replace with your desired username
  user_ssh_key: "{{ lookup('file', '~/.ssh/id_ed25519.pub') }}"  # path to your public key
  is_control_node: false # set to true on the main Dokploy control VPS
```

- `user_name` — the non-root user the playbook creates on the server
- `user_ssh_key` — a `file` lookup pointing to your SSH **public** key (this gets copied to the server)
- `is_control_node` — set to `true` for your main Dokploy server, `false` for worker nodes

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

5. Back in Dokploy's UI on the control node, add this server as a remote server.

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

## Fail2Ban Traefik Configuration

A Fail2ban jail is included for Traefik that bans IPs making repeated 401, 403, 400, or 429 requests. For this to work reliably, you need to adjust the Traefik config so access logs are not buffered or filtered.

In the Dokploy UI (**Traefik File System** > `traefik.yml`) or directly at `/etc/dokploy/traefik/traefik.yml`, update the `accessLog` entry:

```yaml
accessLog:
  filePath: /etc/dokploy/traefik/dynamic/access.log
  format: json
  bufferingSize: 10
```

For **remote servers**, add the above block to each server's Traefik config. You can do this via the Dokploy UI (**Remote Servers** > **...** > **Show Traefik File System**) or directly on the server.

### Cloudflare Users

If your domain uses Cloudflare with the orange cloud (proxy) enabled, Traefik and Fail2ban will only see Cloudflare's IP addresses, not the real visitor IPs. This means the Traefik Fail2ban jail cannot reliably block individual attackers.

**If you use Cloudflare:** Consider the Traefik Fail2ban jail optional. Use Cloudflare's own Firewall Rules, WAF, or Rate Limiting for client-IP blocking. Fail2ban will still protect SSH and other non-proxied services normally.

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

Fail2ban protects:

- **SSH** — aggressive mode, bans after 3 failed attempts for 10 minutes
- **Traefik HTTP** — bans after 15 error responses (401/403/400/429) within 5 minutes for 1 hour

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

### Fail2ban Traefik jail not working

Make sure you've updated the Traefik config to include the `accessLog` block as described in the [Fail2Ban Traefik Configuration](#fail2ban-traefik-configuration) section. The jail needs JSON-formatted access logs at `/etc/dokploy/traefik/dynamic/access.log`.
