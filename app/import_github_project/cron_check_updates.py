from app.import_github_project.untils_import import clone_or_access_repo, git_pull_repo
from app.import_github_project.update_github_project import Check_for_rule_updates
from ..rule import rule_core as RuleModel



async def Check_for_rule_updates_async(schedule_id):
    """Asynchronous function to check if a rule has been updated in its original GitHub repository."""
    print(f"[🔄] Démarrage de la mise à jour pour le schedule ID: {schedule_id}")

    rule_items = RuleModel.get_rules_for_schedule(schedule_id)
    print(f"[📋] {len(rule_items)} règles liées à ce schedule.")

    results = []

    sources = RuleModel.get_sources_from_titles(rule_items)
    print(f"[📁] {len(sources)} sources GitHub détectées.")

    for source in sources:
        print(f"[⬇️] Traitement du dépôt: {source}")
        repo_dir, exists = clone_or_access_repo(source)
        if not exists:
            print(f"[📦] Dépôt cloné: {repo_dir}")
        else:
            print(f"[🔄] Dépôt déjà présent, mise à jour via git pull...")
            git_pull_repo(repo_dir)
        print(f"[✅] Dépôt prêt: {repo_dir}")

    for item in rule_items:
        rule_id = item.get("id")
        title = item.get("title", "Unknown Title")
        print(f"\n[🔍] Vérification de la règle ID {rule_id} – « {title} »")

        message_dict, success, new_rule_content = await Check_for_rule_updates(rule_id)
        rule = RuleModel.get_rule(rule_id)

        if success and new_rule_content:
            print(f"[✅] Règle mise à jour détectée pour « {title} ».")
            result = {
                "id": rule_id,
                "title": title,
                "success": success,
                "message": message_dict.get("message", "No message"),
                "new_content": new_rule_content,
                "old_content": rule.to_string if rule else "Error to charge the rule"
            }

            print(f"[💾] Enregistrement de l’historique pour la règle ID {rule_id}...")
            history_id = RuleModel.create_rule_history(result)

            if history_id is None:
                print(f"[⚠️] Échec de l’enregistrement de l’historique.")
                result["history_id"] = None
            else:
                print(f"[📜] Historique créé avec ID: {history_id}")
                result["history_id"] = history_id

            results.append(result)
        else:
            print(f"[❌] Pas de mise à jour détectée pour « {title} » ou erreur.")

    print(f"\n[✅] Fin du traitement du schedule ID: {schedule_id}. {len(results)} mise(s) à jour enregistrée(s).")
    return results


