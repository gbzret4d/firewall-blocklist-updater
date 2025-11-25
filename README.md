<div align="left" style="position: relative;">
<img src="https://raw.githubusercontent.com/PKief/vscode-material-icon-theme/ec559a9f6bfd399b82bb44393651661b08aaf7ba/icons/folder-markdown-open.svg" align="right" width="30%" style="margin: -20px 0 0 20px;">
<h1>FIREWALL-BLOCKLIST-UPDATER</h1>
<p align="left">
	<em>Securing Networks, One Update at a Time!</em>
</p>
<p align="left">
	<img src="https://img.shields.io/github/license/gbzret4d/firewall-blocklist-updater?style=default&logo=opensourceinitiative&logoColor=white&color=0080ff" alt="license">
	<img src="https://img.shields.io/github/last-commit/gbzret4d/firewall-blocklist-updater?style=default&logo=git&logoColor=white&color=0080ff" alt="last-commit">
	<img src="https://img.shields.io/github/languages/top/gbzret4d/firewall-blocklist-updater?style=default&color=0080ff" alt="repo-top-language">
	<img src="https://img.shields.io/github/languages/count/gbzret4d/firewall-blocklist-updater?style=default&color=0080ff" alt="repo-language-count">
</p>
<p align="left"><!-- default option, no dependency badges. -->
</p>
<p align="left">
	<!-- default option, no dependency badges. -->
</p>
</div>
<br clear="right">

##  Table of Contents

- [ Overview](#-overview)
- [ Features](#-features)
- [ Project Structure](#-project-structure)
  - [ Project Index](#-project-index)
- [ Getting Started](#-getting-started)
  - [ Prerequisites](#-prerequisites)
  - [ Installation](#-installation)
  - [ Usage](#-usage)
  - [ Testing](#-testing)
- [ Project Roadmap](#-project-roadmap)
- [ Contributing](#-contributing)
- [ License](#-license)
- [ Acknowledgments](#-acknowledgments)

---

##  Overview

The Firewall-Blocklist-Updater is a robust open-source project designed to enhance network security. It efficiently updates firewall blocklists, managing both IPv4 and IPv6, and dynamically maintains a whitelist of trusted IP addresses. With a focus on secure and efficient operations, it's an essential tool for system administrators, cybersecurity professionals, and anyone looking to fortify their network against potential threats.

---

##  Features

|      | Feature         | Summary       |
| :--- | :---:           | :---          |
| ⚙️  | **Architecture**  | <ul><li>The project is structured around a main script `update-firewall-blocklists.sh` and two source files for whitelist and blocklist.</li><li>The architecture supports both IPv4 and IPv6.</li><li>The project is designed to work with containers, eliminating the need for sudo privileges.</li></ul> |
| 🔩 | **Code Quality**  | <ul><li>The main script is well-structured and modular, making it easy to understand and maintain.</li><li>The codebase uses shell scripting language, which is ideal for automation tasks like this project.</li></ul> |
| 📄 | **Documentation** | <ul><li>The primary language used in the project is shell scripting, with a total of 1 shell script and 4 source files.</li><li>There is no explicit documentation available in the codebase, which could be improved for better understanding and usage of the project.</li></ul> |
| 🔌 | **Integrations**  | <ul><li>The project integrates with external IP lists for both whitelist and blocklist sources.</li><li>The script is designed to work with containers, indicating potential for integration with container orchestration tools like Docker or Kubernetes.</li></ul> |
| 🧩 | **Modularity**    | <ul><li>The project is modular with separate source files for whitelist and blocklist.</li><li>The main script `update-firewall-blocklists.sh` is responsible for updating the firewall blocklists, managing the IP whitelist, and ensuring secure API key file permissions.</li></ul> |
| 🧪 | **Testing**       | <ul><li>There is no explicit testing framework or test cases provided in the codebase.</li></ul> |
| ⚡️  | **Performance**   | <ul><li>The script downloads source data in parallel for efficiency.</li><li>The dynamic DynDNS IP whitelist allows for automatic updating of IP addresses, improving performance.</li></ul> |
| 🛡️ | **Security**      | <ul><li>The project uses a comprehensive list of potential threats from various sources to enhance firewall security.</li><li>The script ensures secure API key file permissions.</li><li>The project uses a whitelist to allow traffic only from trusted sources, enhancing network security.</li></ul> |
| 📦 | **Dependencies**  | <ul><li>The project has dependencies on external IP lists for whitelist and blocklist sources.</li><li>The project does not seem to have any package manager dependencies.</li></ul> |

---

##  Project Structure

```sh
└── firewall-blocklist-updater/
    ├── LICENSE
    ├── README.md
    ├── firewall-blocklists
    │   ├── blocklist.sources
    │   ├── blocklists.sources
    │   ├── whitelist.sources
    │   └── whitelists.sources
    └── update-firewall-blocklists.sh
```


###  Project Index
<details open>
	<summary><b><code>FIREWALL-BLOCKLIST-UPDATER/</code></b></summary>
	<details> <!-- __root__ Submodule -->
		<summary><b>__root__</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b><a href='https://github.com/gbzret4d/firewall-blocklist-updater/blob/master/update-firewall-blocklists.sh'>update-firewall-blocklists.sh</a></b></td>
				<td>- The `update-firewall-blocklists.sh` file is a script that updates the firewall blocklists in the project<br>- It supports both IPv4 and IPv6, and it downloads source data in parallel for efficiency<br>- The script also ensures secure API key file permissions and is compatible with containers, eliminating the need for sudo privileges<br>- Additionally, it manages a dynamic DynDNS IP whitelist, which allows for the automatic updating of IP addresses in the whitelist<br>- The script uses a configuration directory and two source files, one for the whitelist and one for the blocklist, to manage these lists<br>- In the context of the entire codebase, this script plays a crucial role in maintaining the security of the system by regularly updating the firewall blocklists and managing the IP whitelist<br>- It is an essential part of the project's security infrastructure.</td>
			</tr>
			</table>
		</blockquote>
	</details>
	<details> <!-- firewall-blocklists Submodule -->
		<summary><b>firewall-blocklists</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b><a href='https://github.com/gbzret4d/firewall-blocklist-updater/blob/master/firewall-blocklists/whitelists.sources'>whitelists.sources</a></b></td>
				<td>- Whitelists.sources within the firewall-blocklists project serves as a reference to external resources, specifically country-based IP lists<br>- It contributes to the overall architecture by providing a mechanism to whitelist certain IP addresses from Germany, Austria, and Switzerland, enhancing the project's firewall configuration capabilities.</td>
			</tr>
			<tr>
				<td><b><a href='https://github.com/gbzret4d/firewall-blocklist-updater/blob/master/firewall-blocklists/blocklist.sources'>blocklist.sources</a></b></td>
				<td>- Blocklist.sources within the firewall-blocklists directory serves as a repository of URLs, each pointing to a different source of IP addresses deemed unsafe or malicious<br>- These sources are integral to the project's security measures, providing a comprehensive list of potential threats to be blocked by the firewall.</td>
			</tr>
			<tr>
				<td><b><a href='https://github.com/gbzret4d/firewall-blocklist-updater/blob/master/firewall-blocklists/whitelist.sources'>whitelist.sources</a></b></td>
				<td>- Whitelist.sources within the firewall-blocklists directory serves as a reference list for trusted IP addresses from Germany, Austria, and Switzerland<br>- It fetches data from the FireHOL's IP lists, specifically the GeoLite2 country datasets, to establish a secure network environment by allowing traffic only from these trusted sources.</td>
			</tr>
			<tr>
				<td><b><a href='https://github.com/gbzret4d/firewall-blocklist-updater/blob/master/firewall-blocklists/blocklists.sources'>blocklists.sources</a></b></td>
				<td>- Blocklists.sources in the firewall-blocklists directory serves as a repository of URLs that host various IP blocklists<br>- These blocklists are integral to the project's security measures, providing a comprehensive list of potentially harmful IP addresses associated with cyber threats, compromised systems, and malicious activities<br>- This aids in enhancing the project's firewall defenses.</td>
			</tr>
			</table>
		</blockquote>
	</details>
</details>

---
##  Getting Started

###  Prerequisites

Before getting started with firewall-blocklist-updater, ensure your runtime environment meets the following requirements:

- **Programming Language:** Error detecting primary_language: {'sh': 1, 'sources': 4}


###  Installation

Install firewall-blocklist-updater using one of the following methods:

**Build from source:**

1. Clone the firewall-blocklist-updater repository:
```sh
❯ git clone https://github.com/gbzret4d/firewall-blocklist-updater
```

2. Navigate to the project directory:
```sh
❯ cd firewall-blocklist-updater
```

3. Install the project dependencies:

echo 'INSERT-INSTALL-COMMAND-HERE'



###  Usage
Run firewall-blocklist-updater using the following command:
echo 'INSERT-RUN-COMMAND-HERE'

###  Testing
Run the test suite using the following command:
echo 'INSERT-TEST-COMMAND-HERE'

---
##  Project Roadmap

- [X] **`Task 1`**: <strike>Implement feature one.</strike>
- [ ] **`Task 2`**: Implement feature two.
- [ ] **`Task 3`**: Implement feature three.

---

##  Contributing

- **💬 [Join the Discussions](https://github.com/gbzret4d/firewall-blocklist-updater/discussions)**: Share your insights, provide feedback, or ask questions.
- **🐛 [Report Issues](https://github.com/gbzret4d/firewall-blocklist-updater/issues)**: Submit bugs found or log feature requests for the `firewall-blocklist-updater` project.
- **💡 [Submit Pull Requests](https://github.com/gbzret4d/firewall-blocklist-updater/blob/main/CONTRIBUTING.md)**: Review open PRs, and submit your own PRs.

<details closed>
<summary>Contributing Guidelines</summary>

1. **Fork the Repository**: Start by forking the project repository to your github account.
2. **Clone Locally**: Clone the forked repository to your local machine using a git client.
   ```sh
   git clone https://github.com/gbzret4d/firewall-blocklist-updater
   ```
3. **Create a New Branch**: Always work on a new branch, giving it a descriptive name.
   ```sh
   git checkout -b new-feature-x
   ```
4. **Make Your Changes**: Develop and test your changes locally.
5. **Commit Your Changes**: Commit with a clear message describing your updates.
   ```sh
   git commit -m 'Implemented new feature x.'
   ```
6. **Push to github**: Push the changes to your forked repository.
   ```sh
   git push origin new-feature-x
   ```
7. **Submit a Pull Request**: Create a PR against the original project repository. Clearly describe the changes and their motivations.
8. **Review**: Once your PR is reviewed and approved, it will be merged into the main branch. Congratulations on your contribution!
</details>

<details closed>
<summary>Contributor Graph</summary>
<br>
<p align="left">
   <a href="https://github.com{/gbzret4d/firewall-blocklist-updater/}graphs/contributors">
      <img src="https://contrib.rocks/image?repo=gbzret4d/firewall-blocklist-updater">
   </a>
</p>
</details>

---

##  License

This project is protected under the [SELECT-A-LICENSE](https://choosealicense.com/licenses) License. For more details, refer to the [LICENSE](https://choosealicense.com/licenses/) file.

---

##  Acknowledgments

- List any resources, contributors, inspiration, etc. here.

---
