# P'tit Crolle

<img title="MarkText logo" src="https://github.com/DavidCruciani/ptit-crolle/blob/main/doc/crolle.png?raw=true" alt="Alt text" width="388" data-align="center">

Flask application template

## What's in ?

- Vuejs3

- Blueprints

- Flask-Login

- Flask-SQLAlchemy for databases

- Flask-WTF for forms

- Flask-session for sessions

- Some roles are already created

## Installation

**It is strongly recommended to use a virtual environment**

If you want to know more about virtual environments, [python has you covered](https://docs.python.org/3/tutorial/venv.html)

```bash
pip install -r requirements.txt
python3 app.py -i                            ## Initialize db
```

## Config

Edit `config.py`

- `SECRET_KEY`: Secret key for the app

- `FLASK_URL` : url for the instance

- `FLASK_PORT`: port for the instance

- `MISP_MODULE`: url and port where misp-module is running

## Launch

```bash
./launch.sh -l
```
