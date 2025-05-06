# RULEZET


<img title="MarkText logo" src="https://github.com/ngsoti/rulezet-core/tree/main/doc/rulezet.png?raw=true"   data-align="center">

## Flask Application Template

### What's Included?

- Vue.js 3
- Blueprints
- Flask-Login for user authentication
- Flask-SQLAlchemy for database management
- Flask-WTF for form handling
- Flask-session for session management
- Predefined roles for users

### Installation

**It is strongly recommended to use a virtual environment**

To learn more about virtual environments, [Python's documentation](https://docs.python.org/3/tutorial/venv.html) will guide you through it.

```bash
pip install -r requirements.txt
python3 app.py -i                            ## Initialize the database
```

### Configuration

Edit the `config.py` file:

- `SECRET_KEY`: Secret key for the application
- `FLASK_URL`: URL for the instance
- `FLASK_PORT`: Port for the instance
- `MISP_MODULE`: URL and port where the MISP module is running

### Launching the Application

```bash
./launch.sh -l
```

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

**Website for Sharing, Commenting, and Rating Rules (Crowdsourced Rules Website)**

- Share rules and let the community vote and add comments (e.g., good, bad, generating false positives).
- Users can register and have the following permissions:
  - Add rules
  - Comment on rules
  - Bundle rules (like vulnerability lookup)
  - Rate rules (including false-positive rates and reviewing taxonomy for rule evaluation)

---

For the original website (Ptit Crolle), visit: [https://github.com/DavidCruciani/ptit-crolle](https://github.com/DavidCruciani/ptit-crolle)
