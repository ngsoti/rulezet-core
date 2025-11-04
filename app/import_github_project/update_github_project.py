# from app.rule_type.rule_formats.elastic_format import ElasticDetectionRule
from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType
from app.rule_type.rule_formats.yara_format import YaraRule
from app.rule_type.rule_formats.sigma_format import SigmaRule
from app.rule_type.rule_formats.suricata_format import SuricataRule
from app.rule_type.rule_formats.zeek_format import ZeekRule
from app.rule_type.rule_formats.crs_format import CRSRule
from app.rule_type.rule_formats.nova_format import NovaRule
from app.import_github_project.untils_import import clone_or_access_repo, git_pull_repo
from ..rule import rule_core as RuleModel

FORMAT_CLASSES = {
    "yara": YaraRule,
    "sigma": SigmaRule,
    "suricata": SuricataRule,
    "zeek": ZeekRule,
    "crs": CRSRule,
    "nova": NovaRule,
    # "elastic": ElasticDetectionRule
}

def Check_for_rule_updates(rule_id: int, repo_dir: str):
    """
    Check if a rule has been updated in its original GitHub repository
    using the RuleType classes.
    """
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return {"message": f"No rule found with the id {rule_id}", "success": False}, False, None

    fmt = rule.format.lower()
    if fmt not in FORMAT_CLASSES:
        return {"message": f"Unsupported rule format: {rule.format}", "success": False}, False, None

    rule_class = FORMAT_CLASSES[fmt]()
    found_rule , success = rule_class.find_rule_in_repo(repo_dir, rule_id)

    if not success:
        return {"message": found_rule, "success": False}, False, None

    if rule.to_string != found_rule.strip():
        return {
            "message": "Update found for this rule",
            "success": True,
            "new_content": found_rule.strip()
        }, True, found_rule.strip()
    else:
        return {
            "message": "No change detected for this rule",
            "success": True,
            "new_content": None
        }, True, None
