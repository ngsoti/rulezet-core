from flask import Flask, Blueprint, redirect, request,render_template
from .account import account_core as AccountModel

test_blueprint = Blueprint(
    'test',
    __name__,
    template_folder='templates',    
    static_folder='static'
)


@test_blueprint.route("/")
def test():
    return render_template("test.html")


@test_blueprint.route("/get_users_page", methods=['GET'])
def get_users_page():
    page = request.args.get('page', 1, type=int)
    users = AccountModel.get_users_page(page)
    if users:
        users_list = list()
        for user in users:
            u = user.to_json()
            users_list.append(u)
        return {"users": users_list, "nb_pages": users.pages}
    return {"message": "No Users"}, 404
