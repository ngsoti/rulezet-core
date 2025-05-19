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
- **Flask-WTF** (Forms)
- **Flask-Session** (Session Handling)
- **PostgreSQL** (Database)

---

## Installation

> It is strongly recommended to use a **Python virtual environment**.

```bash
pip install -r requirements.txt
python3 app.py -i        # Initialize the database
```

---

## Configuration

Edit the `config.py` file:

- `SECRET_KEY`: Flask secret key
- `FLASK_URL`: Instance URL (default: localhost)
- `FLASK_PORT`: Port to run the app
- `MISP_MODULE`: Optional connection for MISP integration

You can also use a `.env` file to store sensitive variables.

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
| ![Home](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_readme.png) | ![Detail](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_detail_readme.png) | ![Readme](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_create.png) |

---

## Project Context

This project was initiated as part of a **cybersecurity internship**, aimed at building a collaborative and educational platform. The purpose is to centralize, validate, and improve community-driven detection rules, filling the gap left by the lack of public validation for such rules.

Participants (interns and contributors) are involved in:
- Building core features and interfaces
- Creating the detection rule model and standard
- Integrating with tools like MISP and Suricata
- Ensuring rule quality and validation

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

## License

MIT License — feel free to fork and build upon Rulezet for your own projects.

---