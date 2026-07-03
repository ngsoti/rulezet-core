from flask import Blueprint, render_template
from flask_login import login_required

community_blueprint = Blueprint(
    'community',
    __name__,
    template_folder='templates',
)


@community_blueprint.route('/comments')
@login_required
def comments_hub():
    return render_template('community/comments_hub.html')
