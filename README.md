 # RULEZET  ![Release](https://img.shields.io/badge/release-v1.0.0-blue)

<p align="center">
  <img src="https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/logo_rulezet.png" width="300" alt="Rulezet logo">
</p>

---

## Community-Driven Detection Rules Platform

**Rulezet** is an open-source web platform for sharing, evaluating, improving, and managing cybersecurity detection rules (YARA, Sigma, Suricata, etc). It aims to foster collaboration among professionals and enthusiasts to improve the quality and reliability of detection rules.

---

## Technology Stack

This project is built with:

- **Flask** (Python)
- **Vue.js 3**
- **Flask Blueprints**
- **Flask-Login** (Authentication)
- **Flask-SQLAlchemy** (ORM)
- **PostgreSQL** (Database)

---

## Installation

> It is strongly recommended to use a **Python virtual environment**.

```bash
./install.sh
```

---

## First Connection

At the beginning, password and api Keys are generate to security reason


```bash
====================================================================================================
✅ Admin account created successfully!
🔑 API Key     : xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ( Unique secret key )
👤 Username    : admin@admin.admin
🔐 Password    : xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx   (⚠️ Change it after first login)
====================================================================================================

```

You should change the password after the first connection 

---

## Launching the Application

```bash
./launch.sh -l
```

---

## Features Overview

The platform includes a wide set of functionalities to manage and collaborate around detection rules:

### User Management
- Admin panel to **manage users**  
- **Favorite** rules for users

### Rule Lifecycle
- **Create**, **Edit**, and **Delete** rules  
- **Assign ownership** to rules  

### Search & Browse
- Powerful **search bar** and rule **filtering**  
- **View detailed rule** and download or copy it  

### Community Collaboration
- Propose **modifications** to existing rules via pull-request style edits 
- **Evaluate** rules to identify the most effective ones
- **Comment** and **discuss** arround the rules  

### GitHub Integration
- **Import detection rules directly** from public GitHub repositories  

### Rule Validity
- Automatic **validation of imported rules**
- Display and **manage invalid or malformed rules**  

### Light/Dark Mode

- The **most** important feature to enhance user comfort while working in different environments 😉.

---

## Rule's Formats

New rule formats may be added over time.  
If you want to propose a new format, feel free to open an **issue** on our [GitHub](https://github.com/ngsoti/rulezet-core.git).

Currently, the supported formats are:

- yara
- sigma
- zeek
- suricata
- crs
- nova
- elastic
- no format

---

## UI Previews

| Homepage | Rule Detail | Rule Management |
|---------|--------------|-----------------|
| ![Home](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_readme.png) | ![Detail](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_detail_readme.png) | ![Readme](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_invalid_rule.png) |

---

## API Access

RULEZET provides a RESTful API to allow seamless integration and automation of key processes such as rule creation, importation, account management, and more.

You can access the interactive API documentation using the following URL:


### Example Endpoints:
- `http://127.0.0.1:7009/api/rule/doc/` – Manage detection rules (create, update, delete, import, etc.)
- `http://127.0.0.1:7009/api/account/doc/` – Manage user accounts (registration, login, etc.)

### Why Use the API?

- Automate rule import/update from GitHub or local sources  
- Create and update rules programmatically  
- Manage user accounts and permissions via scripts or clients  
- Integrate RULEZET into your CI/CD or SOC pipeline  

With this API, developers and analysts can save time, reduce errors, and streamline workflows — all while ensuring full compatibility with RULEZET's internal engine.

> Tip: Use tools like [cURL](https://curl.se/) to interact with the API and test endpoints easily.

## Project Summary

This internship offers a unique opportunity to contribute to the development of a cutting-edge, open-source platform: a community-driven website designed for sharing, evaluating, and refining security detection rules. These rules, which are critical for identifying threats in cybersecurity, currently lack a central place for community validation. This project addresses that gap by creating a collaborative space where users can:

- **Share Rules**: Contribute detection rules in various formats (YARA, Sigma, Suricata, and others), allowing for broad community access.
- **Evaluate Rules**: Rate and comment on the effectiveness of rules, report false positives, and share practical experiences.
- **Refine Rules**: Participate in the collaborative improvement of rules through feedback and proposed changes, enhancing their accuracy and reliability.
- **Organize Rules**: Bundle rules into logical sets and classify them using tags and categories, improving searchability and usability.

Interns will play a key role in developing the website’s features and functionalities. This will involve implementing core features, exploring integrations with other security tools such as MISP and Suricata, and assisting in the development of a security rule data model for a standardized format to facilitate easy exchange. Interns will gain hands-on experience in open-source software development, web development, and practical cybersecurity applications. 

This project offers a chance to make a real-world impact by improving the way security professionals interact with essential threat detection information. You will gain exposure to web development, APIs, data modeling, and security knowledge.


---

## Original Inspiration

This project is inspired by [Ptit Crolle](https://github.com/DavidCruciani/ptit-crolle), and takes it further with a modern UI, collaborative features, and integration capabilities.

---

## Contributing

We welcome contributions from the community. You can:
- Submit pull requests for new features or bug fixes
- Suggest enhancements via GitHub Issues
- Help expand supported rule formats

---

