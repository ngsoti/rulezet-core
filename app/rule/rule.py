from flask import Blueprint, redirect, request,render_template, flash, url_for

from .rule_form import AddNewRuleForm
from ..utils.utils import form_to_dict
from . import rule_core as RuleModel

rule_blueprint = Blueprint(
    'rule',
    __name__,
    template_folder='templates',    
    static_folder='static'
)


@rule_blueprint.route("/" , methods=['GET', 'POST'])
def rule():
    form = AddNewRuleForm()
    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        RuleModel.add_rule_core(form_dict)
        flash('Rule added !', 'success')
    return render_template("rule/rule.html", form=form)

