from flask import request
from flask_restx import Namespace, Resource

from app.core.db_class.db import Rule, Tag
from app.core.utils.decorators import api_required
from app.core.utils.utils import get_user_from_api
from app.features.jobs.jobs_core import create_job

tags_private_ns = Namespace(
    'Tags — Private 🔑',
    description=(
        'Authenticated tag-management endpoints. Every route here requires an '
        'X-API-KEY header belonging to an admin, or to a user holding the '
        '"rule.tag_any" permission (Roles & Permissions admin page) — a plain '
        'valid API key alone is not enough.'
    ),
)


def _require_tag_manager(headers):
    """Shared gate for this namespace: a valid API key belonging to an admin,
    or to a user holding the rule.tag_any permission (see Roles &
    Permissions) — a plain valid key alone is not enough.

    Returns (actor, error_response_or_None).
    """
    actor = get_user_from_api(headers)
    if not actor:
        return None, ({'message': 'Invalid API key'}, 401)
    if not (actor.is_admin() or actor.has_permission('rule.tag_any')):
        return None, ({'message': 'Forbidden — requires the rule.tag_any permission'}, 403)
    return actor, None


@tags_private_ns.route('/lookup')
class LookupTag(Resource):
    @api_required
    @tags_private_ns.doc(
        params={
            'id':   {'description': 'Exact tag id.', 'type': 'integer', 'example': 1},
            'uuid': {'description': 'Exact tag uuid.', 'type': 'string',
                     'example': '3fa85f64-5717-4562-b3fc-2c963f66afa6'},
            'name': {'description': 'Case-insensitive substring match on the tag name — '
                                     'returns every match (up to 50).',
                     'type': 'string', 'example': 'tlp'},
        },
        description=(
            "Look up tag(s) by id, uuid, or name — at least one of the three is required.\n\n"
            "Use this before calling `bulk_add` to confirm a tag_id really is the tag you "
            "mean (not just a bare number you got from somewhere else), or to find a tag's "
            "id/uuid when you only know its name.\n\n"
            "**Examples**\n\n"
            "Look up by id:\n"
            "```\n"
            "curl -s \"http://127.0.0.1:7009/api/tags/private/lookup?id=1\" \\\n"
            "  -H \"X-API-KEY: <API_KEY>\" | python3 -m json.tool\n"
            "```\n\n"
            "Look up by uuid:\n"
            "```\n"
            "curl -s \"http://127.0.0.1:7009/api/tags/private/lookup?uuid=<TAG_UUID>\" \\\n"
            "  -H \"X-API-KEY: <API_KEY>\" | python3 -m json.tool\n"
            "```\n\n"
            "Look up by name (partial match, e.g. every `tlp:*` tag):\n"
            "```\n"
            "curl -s \"http://127.0.0.1:7009/api/tags/private/lookup?name=tlp\" \\\n"
            "  -H \"X-API-KEY: <API_KEY>\" | python3 -m json.tool\n"
            "```\n\n"
            "Returns `{\"tags\": [...]}`, each entry being a full Tag object "
            "(id, uuid, name, description, color, icon, rule_count, ...)."
        ),
    )
    @tags_private_ns.response(200, 'One or more tags matched — {"tags": [...]}.')
    @tags_private_ns.response(400, 'Missing id/uuid/name — at least one is required.')
    @tags_private_ns.response(403, 'Valid key, but caller is not an admin and lacks rule.tag_any.')
    @tags_private_ns.response(404, 'No tag matched the given id/uuid/name.')
    def get(self):
        """Look up tag(s) by id, uuid, or name."""
        actor, err = _require_tag_manager(request.headers)
        if err:
            return err

        tag_id = request.args.get('id', type=int)
        tag_uuid = request.args.get('uuid', type=str)
        name = request.args.get('name', type=str)

        if not tag_id and not tag_uuid and not name:
            return {'message': 'Provide at least one of: id, uuid, name'}, 400

        if tag_id or tag_uuid:
            query = Tag.query
            if tag_id:
                query = query.filter(Tag.id == tag_id)
            if tag_uuid:
                query = query.filter(Tag.uuid == tag_uuid)
            tag = query.first()
            if not tag:
                return {'message': 'No tag found matching id/uuid.'}, 404
            return {'tags': [tag.to_json()]}, 200

        matches = Tag.query.filter(Tag.name.ilike(f'%{name}%')).order_by(Tag.name).limit(50).all()
        if not matches:
            return {'message': f'No tag found matching name "{name}".'}, 404
        return {'tags': [t.to_json() for t in matches]}, 200


@tags_private_ns.route('/bulk_add')
class BulkAddTags(Resource):
    @api_required
    @tags_private_ns.doc(
        description=(
            "Bulk-tag a list of rules — two-step, confirm-before-you-commit.\n\n"
            "Rules and tags can each be identified by Rulezet's own numeric id, "
            "its own uuid, or both at once (not the GitHub-import `original_uuid` "
            "some rules also carry — only Rulezet's own `id`/`uuid`).\n\n"
            "**Step 1 — preview.** Call with rule + tag identifiers and no `confirm` "
            "(or `confirm: false`). Nothing is queued yet — the response is a plain-English "
            "summary of what *would* happen (which tag(s), how many of the given rules "
            "actually resolved) so you can check it before committing to a bulk change.\n\n"
            "**Step 2 — confirm.** Re-submit the exact same body with `confirm: true` to "
            "actually queue the `bulk_add_tag_to_rules` background job. The response includes "
            "`job_url` — open it in the browser (or poll `/jobs/detail/<uuid>`) to watch progress.\n\n"
            "Ids/uuids that don't resolve to anything, or rules that already carry the tag, "
            "are silently skipped — they never error the whole batch out. Each rule that is "
            "newly tagged gets an entry in its own edit history (visible on the rule's detail page).\n\n"
            "**Body**\n\n"
            "```\n"
            "{\n"
            "  \"rule_ids\":   [1, 2, 3],              // Rulezet rule id(s)\n"
            "  \"rule_uuids\": [\"<RULE_UUID>\"],        // Rulezet rule uuid(s)\n"
            "  \"tag_ids\":    [1],                    // Rulezet tag id(s)\n"
            "  \"tag_uuids\":  [\"<TAG_UUID>\"],         // Rulezet tag uuid(s)\n"
            "  \"confirm\":    true                    // omit/false = preview only\n"
            "}\n"
            "```\n"
            "At least one of `rule_ids`/`rule_uuids`, and at least one of `tag_ids`/`tag_uuids`, "
            "is required — mixing ids and uuids in the same call is fine.\n\n"
            "**Examples**\n\n"
            "Step 1 — preview, by id:\n"
            "```\n"
            "curl -s -X POST http://127.0.0.1:7009/api/tags/private/bulk_add \\\n"
            "  -H \"Content-Type: application/json\" -H \"X-API-KEY: <API_KEY>\" \\\n"
            "  -d '{\"rule_ids\": [1, 2], \"tag_ids\": [1]}' | python3 -m json.tool\n"
            "```\n\n"
            "Step 1 — preview, by uuid:\n"
            "```\n"
            "curl -s -X POST http://127.0.0.1:7009/api/tags/private/bulk_add \\\n"
            "  -H \"Content-Type: application/json\" -H \"X-API-KEY: <API_KEY>\" \\\n"
            "  -d '{\"rule_uuids\": [\"<RULE_UUID>\"], \"tag_uuids\": [\"<TAG_UUID>\"]}' "
            "| python3 -m json.tool\n"
            "```\n\n"
            "Step 2 — confirmed, queues the job:\n"
            "```\n"
            "curl -s -X POST http://127.0.0.1:7009/api/tags/private/bulk_add \\\n"
            "  -H \"Content-Type: application/json\" -H \"X-API-KEY: <API_KEY>\" \\\n"
            "  -d '{\"rule_ids\": [1, 2], \"tag_ids\": [1], \"confirm\": true}' | python3 -m json.tool\n"
            "```"
        ),
    )
    @tags_private_ns.response(200, 'Preview only — no job was created (confirm was not true).')
    @tags_private_ns.response(202, 'Confirmed — the tagging job was queued, response includes job_url.')
    @tags_private_ns.response(400, 'Missing rule/tag identifiers, or none of them resolved.')
    @tags_private_ns.response(403, 'Valid key, but caller is not an admin and lacks rule.tag_any.')
    def post(self):
        """Bulk-tag a list of rules (preview by default, confirm: true to run)."""
        actor, err = _require_tag_manager(request.headers)
        if err:
            return err

        data = request.get_json(force=True, silent=True) or {}
        rule_ids = data.get('rule_ids') or []
        rule_uuids = data.get('rule_uuids') or []
        tag_ids = data.get('tag_ids') or []
        tag_uuids = data.get('tag_uuids') or []
        confirm = bool(data.get('confirm', False))

        if not isinstance(rule_ids, list) or not isinstance(rule_uuids, list):
            return {'message': 'rule_ids and rule_uuids must be lists'}, 400
        if not isinstance(tag_ids, list) or not isinstance(tag_uuids, list):
            return {'message': 'tag_ids and tag_uuids must be lists'}, 400
        if not rule_ids and not rule_uuids:
            return {'message': 'Provide rule_ids and/or rule_uuids'}, 400
        if not tag_ids and not tag_uuids:
            return {'message': 'Provide tag_ids and/or tag_uuids'}, 400

        resolved_rule_ids = set(rule_ids)
        if rule_uuids:
            resolved_rule_ids.update(
                r.id for r in Rule.query.filter(Rule.uuid.in_(rule_uuids)).with_entities(Rule.id).all()
            )
        resolved_rule_ids = list(resolved_rule_ids)

        resolved_tag_ids = set(tag_ids)
        if tag_uuids:
            resolved_tag_ids.update(
                t.id for t in Tag.query.filter(Tag.uuid.in_(tag_uuids)).with_entities(Tag.id).all()
            )
        resolved_tag_ids = list(resolved_tag_ids)

        tags = Tag.query.filter(Tag.id.in_(resolved_tag_ids)).all()
        if not tags:
            return {'message': 'None of the provided tag_ids/tag_uuids resolved to a tag.'}, 400

        matched_rule_count = Rule.query.filter(Rule.id.in_(resolved_rule_ids)).count()
        if not resolved_rule_ids or matched_rule_count == 0:
            return {'message': 'None of the provided rule_ids/rule_uuids resolved to a rule.'}, 400
        tag_label = ', '.join(f'"{t.name}" (id={t.id})' for t in tags)

        if not confirm:
            return {
                'message': (
                    f'This will apply tag(s) {tag_label} to {matched_rule_count} of the '
                    f'{len(resolved_rule_ids)} rule(s) resolved from what was provided '
                    f'(some may not exist or may already carry the tag). Re-submit this '
                    f'same request with "confirm": true to proceed.'
                ),
                'confirmed': False,
                'preview': {
                    'tags': [{'id': t.id, 'name': t.name} for t in tags],
                    'requested_rule_count': len(resolved_rule_ids),
                    'matched_rule_count': matched_rule_count,
                },
            }, 200

        job = create_job(
            job_type='bulk_add_tag_to_rules',
            payload={'tag_ids': resolved_tag_ids, 'filters': {'rule_ids': resolved_rule_ids}, 'user_id': actor.id},
            label=f'API bulk tag — {len(resolved_rule_ids)} rule(s)',
            created_by=actor.id,
            total=len(resolved_rule_ids),
        )
        if not job:
            return {'message': 'Failed to create job'}, 500

        return {
            'message': f'Tagging job started — applying {tag_label} to {matched_rule_count} rule(s).',
            'confirmed': True,
            'job_uuid': job.uuid,
            'job_url': f'/jobs/detail/{job.uuid}',
            'status': 'pending',
        }, 202
