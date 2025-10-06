from flask import Blueprint, Response, jsonify, render_template
import json
from flask_login import login_required
from ..rule import rule_core as RuleModel

misp_blueprint = Blueprint(
    'misp',
    __name__,
    template_folder='templates',
    static_folder='static'
)



@misp_blueprint.route("/", methods=['GET'])
@login_required
def misp():
    return render_template("misp/misp.html")


from flask import jsonify
import difflib

@misp_blueprint.route("/test", methods=['GET'])
@login_required
def compare():
    # Exemple : deux règles YARA légèrement différentes
    source_rule = """rule Adware_AndroidOS_Mobby_A_MTB{
	meta:
		description = "Adware:AndroidOS/Mobby.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 6f 2f 6d 6f 62 62 79 2f 6c 6f 61 64 65 72 2f 61 70 } //1 io/mobby/loader/ap
		$a_01_1 = {43 72 79 6f 6c 6f 61 64 65 72 } //2 Cryoloader
		$a_01_2 = {67 65 74 53 65 72 76 65 72 } //1 getServer
		$a_01_3 = {72 65 76 6f 6c 75 6d 62 75 73 2e 73 70 61 63 65 } //2 revolumbus.space
		$a_01_4 = {73 74 61 72 74 53 65 72 76 69 63 65 } //1 startService
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=6
 
}"""

    target_rule = """rule Adware_AndroidOS_Mobby_A_MTB{
	meta:
		description = "Asdware:AndroidOS/Mobby.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 6f 2f 6d 6f 62 62 79 2f 6c 6f 61 64 65 72 2f 61 70 } //1 io/mobby/loader/ap
		$a_01_1 = {43 72 79 6f 6c 6f 61 64 65 72 } //2 Cryoloader
		$a_01_3 = {72 65 76 6f 6c 75 6d 62 75 73 2e 73 70 61 63 65 } //2 revolumbus.space
		$a_01_4 = {73 74 61 72 74 53 65 72 76 69 63 65 } //1 startService
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=6
 
}"""

    diff = generate_diff_json(source_rule, target_rule)

    return jsonify({
        "message": "Comparaison effectuée",
        "success": True,
        "toast_class": "success",
        "diff": diff
    }), 200


def generate_diff_json(source, target):
    source_lines = source.splitlines()
    target_lines = target.splitlines()

    diff = list(difflib.ndiff(source_lines, target_lines))
    result = []

    for token in diff:
        if token.startswith("- "):
            result.append({"type": "remove", "source": token[2:], "target": ""})
        elif token.startswith("+ "):
            result.append({"type": "add", "source": "", "target": token[2:]})
        elif token.startswith("  "):
            line = token[2:]
            result.append({"type": "equal", "source": line, "target": line})

    return result


# from flask import jsonify
# import difflib

# @misp_blueprint.route("/test", methods=['GET'])
# @login_required
# def compare():
#     # Règle YARA originale
#     source_rule = """rule Adware_AndroidOS_Mobby_A_MTB{
# 	meta:
# 		description = "Adware:AndroidOS/Mobby.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
# 	strings :
# 		$a_00_0 = {69 6f 2f 6d 6f 62 62 79 2f 6c 6f 61 64 65 72 2f 61 70 } //1 io/mobby/loader/ap
# 		$a_01_1 = {43 72 79 6f 6c 6f 61 64 65 72 } //2 Cryoloader
# 		$a_01_2 = {67 65 74 53 65 72 76 65 72 } //1 getServer
# 		$a_01_3 = {72 65 76 6f 6c 75 6d 62 75 73 2e 73 70 61 63 65 } //2 revolumbus.space
# 		$a_01_4 = {73 74 61 72 74 53 65 72 76 69 63 65 } //1 startService
# 	condition:
# 		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=6
# }"""

#     # Règle YARA modifiée
#     target_rule = """rule Adware_AndroidOS_Mobby_A_MTB{
# 	meta:
# 		description = "Asdware:AndroidOS/Mobby.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
# 	strings :
# 		$a_00_0 = {69 6f 2f 6d 6f 62 62 79 2f 6c 6f 61 64 65 72 2f 61 70 } //1 io/mobby/loader/ap
# 		$a_01_1 = {43 72 79 6f 6c 6f 61 64 65 72 } //2 Cryoloader
# 		$a_01_3 = {72 65 76 6f 6c 75 6d 62 75 73 2e 73 70 61 63 65 } //2 revolumbus.space
# 		$a_01_4 = {73 74 61 72 74 53 65 72 76 69 63 65 } //1 startService
# 	condition:
# 		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=6
# }"""

#     diff_text = generate_inline_diff(source_rule, target_rule)

#     return jsonify({
#         "message": "Comparaison effectuée",
#         "success": True,
#         "toast_class": "success",
#         "diff": diff_text
#     }), 200


# def generate_inline_diff(source, target):
#     """
#     Retourne un texte unique avec les changements en inline :
#     - ajouts = vert
#     - suppressions = rouge
#     - inchangé = normal
#     """
#     source_lines = source.splitlines()
#     target_lines = target.splitlines()

#     diff = list(difflib.ndiff(source_lines, target_lines))
#     result_lines = []

#     for token in diff:
#         if token.startswith("- "):
#             result_lines.append(f"<span style='background:#f8d7da'>{token[2:]}</span>")
#         elif token.startswith("+ "):
#             result_lines.append(f"<span style='background:#d4fcd4'>{token[2:]}</span>")
#         elif token.startswith("  "):
#             result_lines.append(token[2:])

#     # Retourne tout en texte unique avec retours à la ligne
#     return "\n".join(result_lines)



# {% extends 'base.html' %}
# {% block content %}

# <button class="btn btn-primary me-2" @click="test">
#     <i class="fas fa-plug"></i> Test
# </button>

# <div class="diff-wrapper mt-3" style="overflow-x:auto; max-width:100%;">
#     <pre class="p-2" style="white-space:pre-wrap; font-family:monospace;" v-html="diff_result"></pre>
# </div>

# {% endblock %}

# {% block script %}
# <script type="module">
# const { createApp, ref } = Vue;
# import { display_toast, prepare_toast, message_list, display_prepared_toast } from '/static/js/toaster.js';

# createApp({
#     delimiters: ['[[', ']]'],
#     setup() {
#         const diff_result = ref("");

#         async function test() {
#             const res = await fetch('/misp/test');
#             const data = await res.json();
#             display_prepared_toast(data);
#             diff_result.value = data.diff; // texte HTML avec span colorés
#         }

#         return {
#             message_list,
#             test,
#             diff_result
#         }
#     }
# }).mount('#main-container');
# </script>
# {% endblock %}
