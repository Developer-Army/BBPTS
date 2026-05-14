# BBPTS Execution Isolation & Sandboxing Guide

## The Security Risk of Reconnaissance

Bug bounty reconnaissance inherently involves interacting with untrusted, potentially malicious infrastructure. By running 15+ external tools (e.g., headless browsers, HTTP clients, DNS resolvers) against arbitrary targets, you expose your host system to various risks:

1. **Malicious Payloads:** Tools that scrape websites or render JavaScript (like `katana` or `aquatone`) may execute browser exploits or encounter malicious HTML/JS.
2. **SSRF/OOB Exploits:** Network requests can be manipulated to attack your internal network.
3. **Command Injection in Upstream Tools:** If a bug exists in any of the wrapped binaries, a crafted target URL or response could lead to Remote Code Execution (RCE) on your host.

## Recommended Sandboxing Approaches

BBPTS is designed as an orchestrator, meaning it executes whatever tools are available in its `PATH`. **We strongly recommend running BBPTS within an isolated environment.**

### 1. Strict Containerization (Docker + Seccomp)

The safest way to run BBPTS is via its Docker container, rather than native OS execution.

```bash
docker run --rm \
  --network host \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/targets.txt:/app/targets.txt:ro \
  bbpts -input /app/targets.txt -summary /app/results/summary.csv
```

**Security Flags Explained:**
- `--security-opt no-new-privileges:true`: Prevents privilege escalation within the container.
- `--cap-drop ALL`: Drops all Linux kernel capabilities. You may need to selectively add back `--cap-add NET_RAW` if you are running custom raw-socket tools like `masscan` or `nmap`.

### 2. Virtual Machines (Qubes OS / Dedicated VMs)

For maximum security, provision a dedicated, ephemeral Virtual Machine (e.g., using DigitalOcean, Linode, or AWS EC2) strictly for running your recon pipeline. Tear down the VM after the scan completes.

*Note: BBPTS's Axiom integration (fleet deployment) inherently utilizes ephemeral VPS instances, which provides an excellent layer of isolation.*

### 3. gVisor (Advanced Sandboxing)

If you use Docker, consider using Google's **gVisor** (`runsc` runtime). gVisor intercepts application system calls and acts as a user-space kernel, providing a strong isolation boundary between the container and the host kernel.

```bash
docker run --runtime=runsc --rm -v $(pwd):/app bbpts -input targets.txt
```

---
*By adopting these isolation strategies, you protect your primary workstation from potential compromise while maintaining full operational capabilities.*
