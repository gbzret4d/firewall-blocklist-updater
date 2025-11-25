<p align="center">
    <img src="https://cdn-icons-png.flaticon.com/512/6295/6295417.png" align="center" width="30%">
</p>
<p align="center"><h1 align="center">FIREWALL-BLOCKLIST-UPDATER</h1></p>
<p align="center">
    <em>Securing Networks, One Update at a Time.</em>
</p>
<p align="center">
    <img src="https://img.shields.io/github/license/gbzret4d/firewall-blocklist-updater?style=default&logo=opensourceinitiative&logoColor=white&color=0080ff" alt="license">
    <img src="https://img.shields.io/github/last-commit/gbzret4d/firewall-blocklist-updater?style=default&logo=git&logoColor=white&color=0080ff" alt="last-commit">
    <img src="https://img.shields.io/github/languages/top/gbzret4d/firewall-blocklist-updater?style=default&color=0080ff" alt="repo-top-language">
    <img src="https://img.shields.io/github/languages/count/gbzret4d/firewall-blocklist-updater?style=default&color=0080ff" alt="repo-language-count">
</p>
<br>

## 🔗 Table of Contents

- [📍 Overview](#-overview)
- [👾 Features](#-features)
- [📁 Project Structure](#-project-structure)
  - [📂 Project Index](#-project-index)
- [🚀 Getting Started](#-getting-started)
  - [☑️ Prerequisites](#-prerequisites)
  - [⚙️ Installation](#-installation)
  - [🤖 Usage](#-usage)
- [🔰 Contributing](#-contributing)
- [🎗 License](#-license)
- [🙌 Acknowledgments](#-acknowledgments)

---

## 📍 Overview

The **Firewall Blocklist Updater** is a powerful automation tool designed to enhance network security by regularly updating firewall blocklists and whitelists. It automates the retrieval and management of IP address lists, efficiently blocking unauthorized or malicious sources while allowing trusted addresses. Supporting both IPv4 and IPv6, it includes parallel downloading for speed, dynamic handling of DynDNS whitelists, and secure management of API keys. Ideal for system administrators aiming for continuous and reliable protection, this script can run on diverse environments including containers without requiring elevated privileges.

---

## 👾 Features

|      | Feature           | Summary       |
| :--- | :---------------- | :------------ |
| ⚙️    | **Architecture**    | <ul><li>Script-based automation using shell scripting.</li><li>Supports IPv4 and IPv6 firewall rules with ipset and iptables.</li><li>Runs smoothly in containerized and host environments.</li></ul> |
| 🔩    | **Code Quality**    | <ul><li>Secure API key handling with strict file permissions.</li><li>Parallelized downloads optimize update speed.</li><li>Dynamic dynamic-DNS IP whitelisting with error safety.</li></ul> |
| 🔌    | **Integrations**    | <ul><li>Integrates with multiple external blocklist and whitelist sources.</li><li>Supports AbuseIPDB and HoneyDB APIs.</li><li>Utilizes GeoLite2 IP data for regional filtering.</li></ul> |
| ⚡️    | **Performance**     | <ul><li>Parallel downloads reduce total update times.</li><li>Efficient filtering and set management using Python and ipset.</li></ul> |
| 🛡️    | **Security**        | <ul><li>Keeps firewall rules and IP sets updated automatically.</li><li>Prevents accidental blocking of trusted IP ranges.</li><li>Secure API key environment loading.</li></ul> |
| 📦    | **Dependencies**    | <ul><li>curl, ipset, iptables, python3, jq, dig (with automatic installation if missing).</li></ul> |
| 🚀    | **Scalability**     | <ul><li>Designed to support growth in IP lists and network complexity.</li><li>Modular source list files enable easy customization.</li></ul> |

---

## 📁 Project Structure

```plaintext
firewall-blocklist-updater/
├── LICENSE
├── README.md
├── firewall-blocklists/
│   ├── blocklist.sources
│   ├── blocklists.sources
│   ├── whitelist.sources
│   └── whitelists.sources
└── update-firewall-blocklists.sh

📂 Project Index
<details open> <summary><b><code>firewall-blocklist-updater/</code></b></summary> <details> <summary><b>update-firewall-blocklists.sh</b></summary>
The main shell script automates the update process for firewall blocklists and whitelists. It supports both IPv4 and IPv6, securely handles API keys, downloads and merges various source lists, and manages ipset/iptables rules dynamically, including special handling of dynamic DNS whitelists.

</details> <details> <summary><b>firewall-blocklists/</b></summary>
blocklist.sources / blocklists.sources:
Lists of URLs where updated IP blocklists are downloaded from.

whitelist.sources / whitelists.sources:
Lists of URLs providing trusted IP ranges to exclude from blocking. Typically contain regional trusted IP ranges.

</details> </details>
🚀 Getting Started
☑️ Prerequisites
A Unix-like operating system (Linux, BSD, etc.) or a compatible container environment.
Bash shell environment.
Installed or installable dependencies:
curl
ipset
iptables
python3
jq
dig or bind-utils to resolve DNS
The script attempts to automatically install missing dependencies using your package manager if run with sufficient privileges.

⚙️ Installation
Clone the repository:
BASH
git clone https://github.com/gbzret4d/firewall-blocklist-updater.git
cd firewall-blocklist-updater
(Optional) Adjust source list files inside firewall-blocklists/ to your needs.

Make the updater script executable:

BASH
chmod +x update-firewall-blocklists.sh
🤖 Usage
Run the script with:

BASH
./update-firewall-blocklists.sh
It will:

Download blocklist and whitelist sources in parallel.
Download additional lists from AbuseIPDB and HoneyDB if API keys are provided.
Filter out private or reserved IPs.
Update your system's ipsets and iptables rules.
Dynamically add the IP resolved from a configured DynDNS hostname to your whitelist.
Send optional Telegram notifications on failure (requires valid tokens in env file).
⚙️ Configuration
Place your API keys for AbuseIPDB and HoneyDB in a file named firewall-blocklist-keys.env in the script folder or specify the path in the KEYFILE environment variable.
Customize sources by editing the .sources files inside firewall-blocklists/.
Configure your whitelist DynDNS host inside the script variable dnsname (bh645b654.asuscomm.com by default).
🔰 Contributing
Contributions are welcome! Please follow these steps:

Fork the repository.
Create a topic branch (git checkout -b feature-name).
Commit your changes with descriptive messages.
Push your branch and open a pull request.
Participate in code reviews.
For any issues, please open GitHub Issues or join the Discussions tab.

🎗 License
This project is licensed under the MIT License. See the LICENSE file for details.

🙌 Acknowledgments
Thanks to all open source projects and data providers that make network security enhancements like this possible, including AbuseIPDB, HoneyDB, GeoLite2, and the maintainers of ipset and iptables.

Maintained by gbzret4d – Feel free to reach out or contribute!