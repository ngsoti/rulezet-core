# RULEZET

<p align="center">
  <img src="https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet.png" width="300" alt="Rulezet logo">
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

```python
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

print("\n" + "=" * 100)
print(f"{GREEN}✅ Admin account created successfully!{RESET}")
print(f"🔑 {YELLOW}API Key     :{RESET} {admin.api_key} ( Unique secret key )")
print(f"👤 {YELLOW}Username    :{RESET} admin@admin.admin")
print(f"🔐 {YELLOW}Password    :{RESET} {raw_password}   (⚠️ Change it after first login)")
print("=" * 100 + "\n")
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

---

## UI Previews

| Homepage | Rule Detail | Rule Management |
|---------|--------------|-----------------|
| ![Home](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_readme.png) | ![Detail](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_detail_readme.png) | ![Readme](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_invalid_rule.png) |

---

## Project Summary

This internship offers a unique opportunity to contribute to the development of a cutting-edge, open-source platform: a community-driven website designed for sharing, evaluating, and refining security detection rules. These rules, which are critical for identifying threats in cybersecurity, currently lack a central place for community validation. This project addresses that gap by creating a collaborative space where users can:

- **Share Rules**: Contribute detection rules in various formats (YARA, Sigma, Suricata, and others), allowing for broad community access.
- **Evaluate Rules**: Rate and comment on the effectiveness of rules, report false positives, and share practical experiences.
- **Refine Rules**: Participate in the collaborative improvement of rules through feedback and proposed changes, enhancing their accuracy and reliability.
- **Organize Rules**: Bundle rules into logical sets and classify them using tags and categories, improving searchability and usability.

Interns will play a key role in developing the website’s features and functionalities. This will involve implementing core features, exploring integrations with other security tools such as MISP and Suricata, and assisting in the development of a security rule data model for a standardized format to facilitate easy exchange. Interns will gain hands-on experience in open-source software development, web development, and practical cybersecurity applications. 

This project offers a chance to make a real-world impact by improving the way security professionals interact with essential threat detection information. You will gain exposure to web development, APIs, data modeling, and security knowledge.

---

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

