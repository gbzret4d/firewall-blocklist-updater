<p align="center">
    <img src="https://cdn-icons-png.flaticon.com/512/6295/6295417.png" align="center" width="30%" alt="Firewall Icon">
</p>
<h1 align="center">FIREWALL-BLOCKLIST-UPDATER</h1>
<p align="center">
    [![Ask DeepWiki](https://devin.ai/assets/askdeepwiki.png)](https://deepwiki.com/gbzret4d/firewall-blocklist-updater)
</p>
<p align="center">
    <em>Securing Networks, One Update at a Time.</em>
</p>
<br>

A powerful automation tool to enhance network security by regularly fetching and applying updated IP address blocklists and whitelists to your firewall.

## 🔗 Table of Contents

- [📍 Overview](#-overview)
- [👾 Features](#-features)
- [📁 Project Structure](#-project-structure)
- [🚀 Getting Started](#-getting-started)
  - [☑️ Prerequisites](#️-prerequisites)
  - [⚙️ Installation](#️-installation)
  - [🤖 Configuration](#-configuration)
  - [⚡ Usage](#-usage)
- [🤝 Contributing](#-contributing)
- [🎗 License](#-license)
- [🙌 Acknowledgments](#-acknowledgments)

---

## 📍 Overview

The **Firewall Blocklist Updater** is a robust Bash script designed to automate the maintenance of firewall security rules. It periodically downloads IP lists from various user-defined sources, including threat intelligence feeds like AbuseIPDB and HoneyDB, and applies them as `ipset` blocklists. The tool supports both IPv4 and IPv6, efficiently processes lists through parallel downloads, and ensures trusted IPs are never blocked by maintaining a separate whitelist. It also features dynamic whitelisting for hosts with dynamic DNS and provides resilience through local backups and optional failure notifications via Telegram. It's built to run in diverse environments, including containers, without requiring root privileges for most operations.

---

## 👾 Features

|      | Feature           | Summary       |
| :--- | :---------------- | :------------ |
| ⚙️    | **Automation**    | <ul><li>Automates fetching and applying IP blocklists and whitelists via a single script.</li><li>Handles both IPv4 and IPv6 addresses, creating separate `ipset` tables.</li><li>Can be scheduled to run regularly via cron for continuous protection.</li></ul> |
| ⚡️    | **Performance**     | <ul><li>Utilizes parallel downloads (`xargs -P`) to significantly speed up the fetching of source lists.</li><li>Leverages `ipset` for efficient management of large IP sets with minimal performance impact on the kernel.</li></ul> |
| 🛡️    | **Security**        | <ul><li>Securely loads API keys from a dedicated `.env` file with restricted permissions.</li><li>Filters out private, reserved, and loopback addresses to prevent accidental network lockouts.</li><li>Maintains a whitelist to ensure trusted IPs are never blocked.</li></ul> |
| 🔌    | **Integrations**    | <ul><li>Integrates with threat intelligence feeds like AbuseIPDB and HoneyDB (requires API keys).</li><li>Easily extensible with custom blocklist and whitelist URLs via simple text files.</li><li>Sends failure notifications to a Telegram chat for monitoring.</li></ul> |
| 🧱    | **Resilience**      | <ul><li>Creates local backups of downloaded lists and uses them as a fallback if fetching fails.</li><li>Includes an error handler to trap exits and send alerts.</li><li>Dynamically resolves and whitelists a configured DynDNS hostname to maintain access.</li></ul> |
| 📦    | **Compatibility**    | <ul><li>Checks for and attempts to install missing dependencies (`curl`, `ipset`, `jq`, `dig`, etc.) using common package managers.</li><li>Designed to run in standard Linux environments and container environments like Docker.</li></ul> |

---

## 📁 Project Structure

```plaintext
.
├── LICENSE
├── README.md
├── firewall-blocklists/
│   ├── blocklist.sources
│   ├── blocklists.sources
│   ├── whitelist.sources
│   └── whitelists.sources
└── update-firewall-blocklists.sh
```

-   `update-firewall-blocklists.sh`: The main executable script that orchestrates the entire update process.
-   `firewall-blocklists/`: A directory containing the lists of URLs for IP sources.
    -   `blocklist.sources`: A newline-separated list of URLs pointing to IP blocklists.
    -   `whitelist.sources`: A newline-separated list of URLs pointing to IP whitelists (e.g., trusted country IP ranges).
-   `LICENSE`: The MIT License file for the project.

---

## 🚀 Getting Started

### ☑️ Prerequisites

-   A Unix-like operating system (e.g., Linux).
-   `bash` shell.
-   The script will attempt to auto-install the following dependencies if they are missing:
    -   `curl`
    -   `ipset`
    -   `iptables`
    -   `python3`
    -   `jq`
    -   `dig` (from `dnsutils` or `bind-utils`)

### ⚙️ Installation

1.  Clone the repository to your local machine:
    ```sh
    git clone https://github.com/gbzret4d/firewall-blocklist-updater.git
    cd firewall-blocklist-updater
    ```
2.  Make the update script executable:
    ```sh
    chmod +x update-firewall-blocklists.sh
    ```

### 🤖 Configuration

1.  **Source Lists**: Edit the files in the `firewall-blocklists/` directory to add or remove URLs for your desired blocklists and whitelists. The script uses `blocklist.sources` and `whitelist.sources` by default.

2.  **API Keys & Notifications (Optional)**: For AbuseIPDB, HoneyDB, and Telegram integration, create a file named `firewall-blocklist-keys.env` in the same directory as the script:
    ```env
    # AbuseIPDB API Key (https://www.abuseipdb.com/account)
    ABUSEIPDB_API_KEY="YOUR_KEY_HERE"

    # HoneyDB API ID and Key (https://honeydb.io/settings)
    HONEYDB_API_ID="YOUR_ID_HERE"
    HONEYDB_API_KEY="YOUR_KEY_HERE"

    # Telegram Bot Token and Chat ID for failure notifications
    TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN"
    TELEGRAM_CHAT_ID="YOUR_CHAT_ID"
    ```
    The script will automatically restrict permissions for this file to `600`.

3.  **Dynamic DNS Whitelist**: To whitelist a dynamic IP address, edit the `dnsname` variable inside `update-firewall-blocklists.sh` to your DynDNS hostname.
    ```sh
    # Inside update-firewall-blocklists.sh
    local dnsname="your.dyndns.host.com"
    ```

### ⚡ Usage

Run the script manually. You may need `sudo` if the script needs to install dependencies or modify `ipset`/`iptables` rules and your user lacks permissions.

```sh
sudo ./update-firewall-blocklists.sh
```

For automated execution, set up a cron job. For example, to run the script every 6 hours:

```sh
# open crontab for editing
crontab -e

# add this line (adjust path as needed)
0 */6 * * * /path/to/firewall-blocklist-updater/update-firewall-blocklists.sh > /var/log/firewall-updater.log 2>&1
```

---

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements or find a bug, please feel free to fork the repository, make your changes, and submit a pull request.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

---

## 🎗 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

## 🙌 Acknowledgments

-   Thanks to the providers of the open-source blocklists from FireHOL, blocklist.de, and others.
-   AbuseIPDB and HoneyDB for their threat intelligence APIs.
-   The developers of `ipset` and `iptables`.