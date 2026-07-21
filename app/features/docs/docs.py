from flask import Blueprint, render_template

from app.core.utils.utils import get_version

docs_blueprint = Blueprint('docs', __name__)


@docs_blueprint.route('/')
def quick_start():
    return render_template('docs/quick_start.html', version=get_version())


@docs_blueprint.route('/full')
def full_documentation():
    return render_template('docs/full_documentation.html', version=get_version())
