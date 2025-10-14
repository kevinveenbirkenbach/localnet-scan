# localnet-scan — Lightweight local network scanner

A simple Python CLI tool that discovers hosts on your local network and reports IP, hostname, MAC, and vendor information.
It wraps tools like `arp-scan`, `nmap`, `avahi-resolve`, and `nbtscan`, and falls back to safe Python methods when unavailable.

---

## 🧭 Description

`localnet` scans your local network and lists active hosts with IP, hostname, MAC address, and hardware vendor — all in one command.

---

## ⚙️ Installation

### Using `pkgmgr` (recommended)

If you use [pkgmgr](https://github.com/kevinveenbirkenbach/package-manager), install `localnet` directly:

```bash
pkgmgr install localnet
```

After installation, run the tool as:

```bash
localnet --help
```

> This automatically makes the program available as the `localnet` command on your system.

---

## 🚀 Usage examples

Discover all devices in your local subnet:

```bash
sudo localnet --auto
```

Export results to CSV:

```bash
sudo localnet --subnet 192.168.0.0/24 --format csv --output hosts.csv
```

Export as JSON:

```bash
localnet --subnet 192.168.0.0/24 --format json > hosts.json
```

---

## 🧪 Testing

Run all unit tests:

```bash
make test
```

---

## 📜 License

MIT License — see `LICENSE`.

---

## 💬 Chat context

This project was developed collaboratively in a [ChatGPT session](https://chatgpt.com/share/68ee0afc-a5d8-800f-8138-d7eca19886c3).

## 👤 Author

Kevin Veen-Birkenbach
[https://www.veen.world](https://www.veen.world)
