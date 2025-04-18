from flask import Blueprint, redirect, request,render_template, flash, url_for
from flask_login import login_required

from .rule_form import AddNewRuleForm
from ..utils.utils import form_to_dict
from . import rule_core as RuleModel

rule_blueprint = Blueprint(
    'rule',
    __name__,
    template_folder='templates',    
    static_folder='static'
)


@rule_blueprint.route("/", methods=['GET', 'POST'])
@login_required
def rule():
    form = AddNewRuleForm()

    licenses = []
    with open("app/rule/import_licenses/licenses.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                licenses.append(line)

    form.license.choices = [(lic, lic) for lic in licenses]

    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        RuleModel.add_rule_core(form_dict)
        flash('Rule added !', 'success')
        
    return render_template("rule/rule.html", form=form)
