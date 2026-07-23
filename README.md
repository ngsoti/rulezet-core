<div align="center">
  <img width="524" height="524" alt="Rulezet Logo" src="https://github.com/user-attachments/assets/8f583c28-8138-40b4-b532-371bb45622f4" />
  
  <br>


  <p>
    <a href="https://github.com/ngsoti/rulezet-core/releases/tag/1.6.3">
      <img src="https://img.shields.io/badge/release-v1.6.3-blue?style=for-the-badge&logo=github" alt="Release" />
    </a>
    <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License" />
    <img src="https://img.shields.io/badge/platform-cybersecurity-red?style=for-the-badge" alt="Cybersecurity" />
  </p>

  <p>
    <img src="https://img.shields.io/badge/engine-YARA-informational?style=flat&logo=yara&logoColor=white" alt="YARA" />
    <img src="https://img.shields.io/badge/engine-Sigma-orange?style=flat&logo=sigma&logoColor=white" alt="Sigma" />
    <img src="https://img.shields.io/badge/engine-Suricata-yellow?style=flat&logo=suricata&logoColor=black" alt="Suricata" />
    <img src="https://img.shields.io/badge/integration-MISP-purple?style=flat&logo=misp&logoColor=white" alt="MISP" />
  </p>
</div>

## Community-Driven Detection Rules Platform

**Rulezet** is an open-source web platform for sharing, evaluating, improving, and managing cybersecurity detection rules (YARA, Sigma, Suricata, Zeek, CRS, Nova, NSE, Wazuh, Elastic). It fosters collaboration among security professionals and enthusiasts to improve the quality and reliability of detection rules.

Rulezet is available as an online service at [https://rulezet.org/](https://rulezet.org/)

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12 · Flask · Flask-Login · Flask-SQLAlchemy · Flask-RESTX |
| Frontend | Vue.js 3 · Bootstrap 5.3 · Font Awesome 6 |
| Database | PostgreSQL (production) · SQLite (testing) |
| Workers | Python `threading` — daemon background job queue |
| Similarity | TF-IDF + FAISS + rapidfuzz |

---Here is the updated documentation in English, harmonized with your `manage.py` structure.

---

## Installation

> A Python virtual environment is strongly recommended.

```bash
# 1. Create a virtual environment
python3 -m venv env
source env/bin/activate

# 2. Install dependencies and initialize the database
python3 manage.py init

```

---

## Quick Start

### 1. Initialize the Database

If you have already run `init`, this step is likely complete. If you need to initialize or re-initialize tables:

```bash
source env/bin/activate
python3 manage.py db-init

```

*Note: This will display your temporary administrator credentials.*

### 2. Launch the Application

For local development:

```bash
python3 manage.py start

```

The application runs on `http://127.0.0.1:7009` by default.

---

## Maintenance & Production

### Update after `git pull`

After pulling the latest code changes, use the following command to synchronize your dependencies and database:

```bash
python3 manage.py update

```

### Production Deployment

Use the dedicated command to automate the backup, update, and service restart process:

```bash
python3 manage.py deploy

```

---

## Help

To view all available options at any time:

```bash
python3 manage.py --help

```

---

## Configuration

`config.py` selects the environment via the `FLASKENV` variable:

| `FLASKENV` | Database | Notes |
|------------|----------|-------|
| `development` | `postgresql:///rulezet` | `DEBUG=True`, sessions in PostgreSQL |
| `testing` | `sqlite:///rulezet-test.sqlite` | CSRF disabled, sessions on filesystem |
| `production` | `postgresql:///rulezet` | `DEBUG=False` |

Secrets are stored in `.env`:

```env
SECRET_KEY=your-secret-key
MAIL_PASSWORD=your-mail-password
```

---

## Database Management

```bash
# Re-create from scratch (drop + reinit)
python3 app.py -r

# Run migrations after model changes
flask db migrate -m "description"
flask db upgrade

# Backup / restore
./backup/scripts/backup_rulezet.sh
./backup/scripts/restore_rulezet.sh
```

---

## Running Tests

```bash
# All tests
./launch.sh -t
# or:
FLASKENV=testing pytest tests

# Single file
FLASKENV=testing pytest tests/rules/test_rule.py
FLASKENV=testing pytest tests/rules/test_search_rules.py -k "test_name"
```

---

## Supported Rule Formats

New formats can be added at any time without modifying the import pipeline — see the Contributing section.

| Format | Description |
|--------|-------------|
| `yara` | YARA malware detection rules |
| `sigma` | Generic SIEM detection rules |
| `suricata` | Network IDS/IPS rules |
| `zeek` | Network traffic analysis scripts |
| `crs` | OWASP Core Rule Set (ModSecurity/Coraza) |
| `nova` | Nova hunting rules |
| `nse` | Nmap Scripting Engine scripts |
| `wazuh` | Wazuh SIEM detection rules |
| `elastic` | Elastic Security detection rules |

---

## Features

### Rule Lifecycle
- **Create**, **edit**, and **delete** detection rules
- **Parse** raw content to auto-extract metadata
- **Import** rules from GitHub repositories or ZIP archives
- Automatic **syntax validation** on import — invalid rules are quarantined and can be fixed
- Default **TLP:CLEAR** and **PAP:CLEAR** tags attached to every new rule automatically

### Search & Browse
- **Rules Explorer** with full-text search, format/tag/vulnerability filters, pagination
- **Bundles Explorer** — named collections of rules with a file-tree view
- **Tag taxonomy** — MISP-compatible tags with color, icon, and galaxy metadata
- Tag tooltips with description, visibility, and creation date

### Community Collaboration
- **Vote** (up/down) on rules
- **Favorite** rules for personal collections
- **Comment** and discuss on rules and bundles
- **Propose edits** via PR-style change proposals (pending / approved / rejected)

### GitHub Integration
- Import detection rules directly from public GitHub repositories
- Scheduled **update checks** to pull new rule versions
- Bulk GitHub source management with per-source rule listing
- Activity log links correctly strip `.git` suffixes when navigating to source details

### Activity Logs
- Full admin audit trail at `/admin/logs`
- Inline **Public/Private visibility toggle** per log entry (click the badge)
- **Bulk visibility change** (select rows → Set Public / Set Private)
- Bulk delete with background job
- Filters by action type, description search, and per-page count

### Administration
- **User management** — promote/demote, view profiles, delete accounts
- **Background jobs** monitor and control panel (`/jobs/list`) with zombie detection
- **Bulk tag** rules with fine-grained filters via background jobs
- **Manage rule formats** — enable/disable detection format support
- **Similarity engine** — compute TF-IDF + fuzzy similarity scores between rules
- **Reported rules** management

### UI / UX
- Consistent **page header banner** across all navigation pages (icon, title, accent bar)
- Full **light / dark mode** support with correct text contrast at all sizes
- Tag tooltips teleported to `<body>` — display correctly above carousels and overflow-hidden containers
- Smooth tooltip fade-in animation

---

## API Access

Swagger UI is available at `/api/`.

| Namespace | Auth | Description |
|-----------|------|-------------|
| `/api/rule/public` | None | Read rules publicly |
| `/api/rule/private` | `X-API-KEY` | Create / update / delete rules |
| `/api/bundle/public` | None | Read bundles publicly |
| `/api/bundle/private` | `X-API-KEY` | Manage bundles |
| `/api/account/public` | None | Public account info |
| `/api/account/private` | `X-API-KEY` | Account management |

Pass your API key in the `X-API-KEY` request header. Keys are generated on account creation and visible in your profile.

### Common use cases

```bash
# Import rules from a GitHub repo
curl -X POST http://127.0.0.1:7009/api/rule/private/import_github \
  -H "X-API-KEY: your-key" \
  -d '{"url": "https://github.com/org/repo"}'

# Create a rule
curl -X POST http://127.0.0.1:7009/api/rule/private/create \
  -H "X-API-KEY: your-key" \
  -H "Content-Type: application/json" \
  -d '{"format": "yara", "title": "My Rule", "to_string": "rule My_Rule { ... }"}'
```

---

## UI Previews

| Homepage | Rule Detail | Invalid Rules |
|----------|-------------|---------------|
| ![Home](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_home.png) | ![Detail](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_detail_readme.png) | ![Invalid](https://raw.githubusercontent.com/ngsoti/rulezet-core/main/doc/rulezet_invalid_rule.png) |

---

## Adding a New Rule Format

1. Create `app/features/rule/rule_format/available_format/myformat_format.py`
2. Subclass `RuleType` from `rule_type_abstract.py`
3. Implement all abstract methods: `format`, `validate()`, `parse_metadata()`, `get_rule_files()`, `extract_rules_from_file()`, `find_rule_in_repo()`
4. `load_all_rule_formats()` auto-discovers it via `pkgutil.iter_modules` — no further registration needed

---

## Contributing

We welcome contributions from the community:

- Submit pull requests for new features or bug fixes
- Report issues and suggest enhancements via [GitHub Issues](https://github.com/ngsoti/rulezet-core/issues)
- Help expand supported rule formats
- Improve documentation

---

## License

This software is licensed under the [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html).

```
Copyright (C) 2025-2026 CIRCL - Computer Incident Response Center Luxembourg
Copyright (C) 2025-2026 Theo Geffe
```

---

## Funding

Rulezet is co-funded by [CIRCL](https://www.circl.lu/) and by the European Union under the [FETTA](https://www.circl.lu/pub/press/20240131/) (Federated European Team for Threat Analysis) project.

![EU logo](https://www.vulnerability-lookup.org/images/eu-funded.jpg)

---

## Inspiration

This project is inspired by [Flask launchpad](https://github.com/ecrou-exact/flask-launchpad), extended with a modern UI, collaborative features, and full integration capabilities.
