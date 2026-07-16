import json
import os
import uuid as _uuid_mod
from flask import Blueprint, abort, jsonify, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from . import blog_core as BlogModel
from app.core.utils.activity_log import log_activity
from app.features.notification.notification_core import notify_blog_published

# ── File upload security constants ───────────────────────────────────────────
_ALLOWED_MIME_TYPES = {
    'application/pdf',
    'text/plain', 'text/csv', 'text/markdown',
    'application/json', 'application/xml', 'text/xml',
    'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml',
    'application/zip', 'application/x-tar', 'application/gzip',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
}
_ALLOWED_EXTENSIONS = {
    'pdf', 'txt', 'csv', 'md', 'json', 'xml',
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg',
    'zip', 'tar', 'gz', 'docx', 'xlsx',
}
_ALLOWED_IMAGE_MIME = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}
_ALLOWED_IMAGE_EXT  = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
_MAX_FILE_SIZE      = 10 * 1024 * 1024   # 10 MB
_MAX_COVER_SIZE     =  5 * 1024 * 1024   #  5 MB

def _blog_upload_dir():
    from flask import current_app
    d = os.path.join(current_app.root_path, 'uploads', 'blog')
    os.makedirs(d, exist_ok=True)
    return d

def _cover_upload_dir():
    from flask import current_app
    d = os.path.join(current_app.root_path, 'static', 'uploads', 'blog')
    os.makedirs(d, exist_ok=True)
    return d

blog_blueprint = Blueprint(
    'blog',
    __name__,
    template_folder='templates',
    static_folder='static',
)


def _admin_required():
    """Return a 403 JSON response if the current user is not admin."""
    if not current_user.is_authenticated or not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin access required.'}), 403
    return None


# ── Public routes ──────────────────────────────────────────────────────────────

@blog_blueprint.route('/')
def list_posts():
    return render_template('blog/list_blog.html')


@blog_blueprint.route('/post/<string:post_uuid>')
def detail(post_uuid):
    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        abort(404)
    # Private post: only admin or share-key access
    if not post.is_public:
        if not (current_user.is_authenticated and (
                current_user.id == post.user_id or current_user.is_admin())):
            abort(403)
    BlogModel.add_view(post)
    return render_template('blog/detail_blog.html', post=post, shared=False)


@blog_blueprint.route('/share/<string:post_uuid>/<string:key>')
def detail_shared(post_uuid, key):
    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        abort(404)
    if post.share_key != key:
        abort(403)
    BlogModel.add_view(post)
    return render_template('blog/detail_blog.html', post=post, shared=True)


# ── Admin page routes ──────────────────────────────────────────────────────────

@blog_blueprint.route('/admin/')
@login_required
def admin_list():
    if not current_user.is_admin():
        abort(403)
    return render_template('blog/admin_list.html')


@blog_blueprint.route('/admin/create')
@login_required
def admin_create():
    if not current_user.is_admin():
        abort(403)
    return render_template('blog/create_edit.html', is_edit=False, post=None, files_json=[])


@blog_blueprint.route('/admin/edit/<string:post_uuid>')
@login_required
def admin_edit(post_uuid):
    if not current_user.is_admin():
        abort(403)
    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        abort(404)
    files_json = [f.to_json() for f in post.files]
    return render_template('blog/create_edit.html', is_edit=True, post=post, files_json=files_json)


# ── Admin JSON action routes ───────────────────────────────────────────────────

@blog_blueprint.route('/admin/save', methods=['POST'])
@login_required
def admin_save():
    err = _admin_required()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    post_uuid = data.get('uuid')

    try:
        if post_uuid:
            post = BlogModel.get_post_by_uuid(post_uuid)
            if not post:
                return jsonify({'success': False, 'message': 'Post not found.'}), 404
            was_public_published = post.is_public and not post.is_draft
            post = BlogModel.update_post(post, data)
            log_activity(
                'blog.edit', f"Edited blog post '{post.title}'",
                target_type='blog_post', target_id=post.id, target_uuid=post.uuid,
                is_public=False,
            )
            # This is the only save path the create/edit form actually uses (the
            # dedicated toggle endpoints below aren't wired to it), so this is
            # where a draft->published or private->public transition must be
            # caught to fire the "new blog post" notification exactly once.
            if not was_public_published and post.is_public and not post.is_draft:
                notify_blog_published(post)
            return jsonify({
                'success': True,
                'message': 'Post updated.',
                'toast_class': 'success-subtle',
                'uuid': post.uuid,
            })
        else:
            post = BlogModel.create_post(data, current_user.id)
            log_activity(
                'blog.create', f"Created blog post '{post.title}'",
                target_type='blog_post', target_id=post.id, target_uuid=post.uuid,
                is_public=post.is_public and not post.is_draft,
            )
            if post.is_public and not post.is_draft:
                notify_blog_published(post)
            return jsonify({
                'success': True,
                'message': 'Post created.',
                'toast_class': 'success-subtle',
                'uuid': post.uuid,
            }), 201
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    except Exception as exc:
        return jsonify({'success': False, 'message': 'Server error.'}), 500


@blog_blueprint.route('/admin/delete/<string:post_uuid>', methods=['POST'])
@login_required
def admin_delete(post_uuid):
    err = _admin_required()
    if err:
        return err

    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    title = post.title
    pid   = post.id
    ok    = BlogModel.delete_post(post.id)
    if ok:
        log_activity('blog.delete', f"Deleted blog post '{title}' (id={pid})",
                     target_type='blog_post', target_id=pid, target_uuid=post_uuid)
        return jsonify({'success': True, 'message': 'Post deleted.', 'toast_class': 'success-subtle'})
    return jsonify({'success': False, 'message': 'Delete failed.', 'toast_class': 'danger-subtle'}), 500


@blog_blueprint.route('/admin/toggle_access/<string:post_uuid>', methods=['POST'])
@login_required
def admin_toggle_access(post_uuid):
    err = _admin_required()
    if err:
        return err

    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    was_public = post.is_public
    is_public = BlogModel.toggle_public(post)
    log_activity(
        'blog.toggle_access',
        f"Toggled post '{post.title}' to {'public' if is_public else 'private'}",
        target_type='blog_post', target_id=post.id, target_uuid=post_uuid,
    )
    if is_public and not was_public and not post.is_draft:
        notify_blog_published(post)
    return jsonify({'success': True, 'is_public': is_public})


@blog_blueprint.route('/admin/toggle_draft/<string:post_uuid>', methods=['POST'])
@login_required
def admin_toggle_draft(post_uuid):
    err = _admin_required()
    if err:
        return err

    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    was_draft = post.is_draft
    was_public = post.is_public
    is_draft, is_public = BlogModel.toggle_draft(post)
    log_activity(
        'blog.toggle_draft',
        f"Toggled post '{post.title}' to {'draft' if is_draft else 'published'}",
        target_type='blog_post', target_id=post.id, target_uuid=post_uuid,
    )
    if was_draft and not is_draft and is_public:
        notify_blog_published(post)
    elif not was_public and is_public and not is_draft:
        notify_blog_published(post)
    return jsonify({'success': True, 'is_draft': is_draft, 'is_public': is_public})


@blog_blueprint.route('/admin/regenerate_key/<string:post_uuid>', methods=['POST'])
@login_required
def admin_regenerate_key(post_uuid):
    err = _admin_required()
    if err:
        return err

    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    new_key = BlogModel.regenerate_share_key(post)
    share_url = url_for('blog.detail_shared', post_uuid=post_uuid, key=new_key, _external=True)
    return jsonify({'success': True, 'share_key': new_key, 'share_url': share_url})


# ── JSON API ───────────────────────────────────────────────────────────────────

@blog_blueprint.route('/api/posts')
def api_posts():
    page     = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search   = request.args.get('search', type=str) or None
    tags_raw = request.args.get('tags', type=str) or ''
    tag_names = [t.strip() for t in tags_raw.split(',') if t.strip()] if tags_raw else []
    status   = request.args.get('status', type=str) or None

    is_admin = current_user.is_authenticated and current_user.is_admin()
    pagination = BlogModel.get_posts_paginated(page, per_page, search, tag_names, is_admin, status)

    return jsonify({
        'items':       [p.to_json() for p in pagination.items],
        'total':       pagination.total,
        'total_pages': pagination.pages,
        'page':        page,
    })


# ── Post downloads (public posts only) ────────────────────────────────────────

def _get_public_post_or_404(post_uuid):
    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post or post.is_draft or not post.is_public:
        abort(404)
    return post

def _safe_filename(title: str, uuid_prefix: str, ext: str) -> str:
    import re as _re
    slug = _re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')[:40]
    return f'blog-{slug}-{uuid_prefix}.{ext}'

def _build_render_context(post, base_url: str) -> dict:
    """Shared context for both PDF and Markdown renderers."""
    import datetime as _dt
    from app.core.db_class.db import Rule, Bundle

    cover = post.cover_image_url or ''
    if cover.startswith('/'):
        cover = base_url + cover

    rule_refs = []
    for assoc in post.rules:
        rule = Rule.query.get(assoc.rule_id)
        if rule and not rule.is_deleted:
            rule_refs.append({'uuid': rule.uuid, 'title': rule.title,
                              'format': rule.format, 'rule_id': rule.id})

    bundle_refs = []
    for assoc in post.bundles:
        bundle = Bundle.query.get(assoc.bundle_id)
        if bundle:
            bundle_refs.append({'uuid': bundle.uuid, 'name': bundle.name})

    return {
        'post':            post,
        'source_url':      base_url,
        'cover_image_abs': cover,
        'tags':            [a.tag.name for a in post.tags if a.tag],
        'cve_ids':         post.cve_ids or [],
        'technique_ids':   [a.technique_id for a in post.attacks],
        'external_links':  post.external_links or [],
        'files':           list(post.files),
        'rule_refs':       rule_refs,
        'bundle_refs':     bundle_refs,
        'generated_at':    _dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
    }


@blog_blueprint.route('/post/<string:post_uuid>/download/pdf')
def download_post_pdf(post_uuid):
    """Generate a full PDF of the blog post. Public + published posts only."""
    import markdown as _md
    from weasyprint import HTML as WeasyprintHTML
    from flask import current_app

    post = _get_public_post_or_404(post_uuid)
    base_url = request.url_root.rstrip('/')
    ctx = _build_render_context(post, base_url)

    content_html = _md.markdown(
        post.content or '',
        extensions=['extra', 'codehilite', 'toc', 'nl2br'],
    )
    ctx['content_html'] = content_html

    html_str = render_template('blog/post_print.html', **ctx)

    pdf_bytes = WeasyprintHTML(
        string=html_str,
        base_url=base_url,
    ).write_pdf()

    filename = _safe_filename(post.title, post.uuid[:8], 'pdf')
    response = current_app.response_class(
        response=pdf_bytes,
        status=200,
        mimetype='application/pdf',
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    short_title = post.title[:80] + ('…' if len(post.title) > 80 else '')
    log_activity('blog.download_pdf', f'Downloaded PDF of "{short_title}"',
                 target_type='blog_post', target_id=post.id, is_public=False)
    return response


@blog_blueprint.route('/post/<string:post_uuid>/download/markdown')
def download_post_markdown(post_uuid):
    """Download the blog post as a Markdown file with YAML front-matter."""
    import datetime as _dt
    from flask import current_app

    post = _get_public_post_or_404(post_uuid)
    base_url = request.url_root.rstrip('/')
    ctx = _build_render_context(post, base_url)

    lines = ['---']
    lines.append(f'title: "{post.title}"')
    if post.excerpt:
        lines.append(f'excerpt: "{post.excerpt}"')
    if post.published_at:
        lines.append(f'date: {post.published_at.strftime("%Y-%m-%d")}')
    if ctx["tags"]:
        lines.append('tags:')
        for t in ctx["tags"]:
            lines.append(f'  - {t}')
    if ctx["cve_ids"]:
        lines.append('cve_ids:')
        for c in ctx["cve_ids"]:
            lines.append(f'  - {c}')
    if ctx["technique_ids"]:
        lines.append('attack_techniques:')
        for a in ctx["technique_ids"]:
            lines.append(f'  - {a}')
    if post.cover_image_url:
        lines.append(f'cover_image: "{ctx["cover_image_abs"]}"')
    lines.append(f'source: "{base_url}/blog/post/{post.uuid}"')
    lines.append(f'exported_at: {_dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}')
    lines.append('---')
    lines.append('')
    lines.append(post.content or '')

    if ctx["external_links"]:
        lines += ['', '---', '', '## External Links', '']
        for lnk in ctx["external_links"]:
            lines.append(f'- [{lnk.get("label") or lnk["url"]}]({lnk["url"]})')

    if ctx["files"]:
        lines += ['', '## Attachments', '']
        for f in ctx["files"]:
            size_kb = round(f.size_bytes / 1024, 1)
            lines.append(f'- [{f.original_name}]({base_url}/blog/file/{f.uuid}?download=1) ({size_kb} KB, {f.mime_type})')

    if ctx["rule_refs"]:
        lines += ['', '## Referenced Detection Rules', '']
        for r in ctx["rule_refs"]:
            lines.append(f'- **{r["title"]}** ({r["format"]}) — [{base_url}/rule/detail_rule/{r["rule_id"]}]({base_url}/rule/detail_rule/{r["rule_id"]})')

    if ctx["bundle_refs"]:
        lines += ['', '## Referenced Bundles', '']
        for b in ctx["bundle_refs"]:
            lines.append(f'- **{b["name"]}**')

    content = '\n'.join(lines)
    filename = _safe_filename(post.title, post.uuid[:8], 'md')
    response = current_app.response_class(
        response=content.encode('utf-8'),
        status=200,
        mimetype='text/markdown; charset=utf-8',
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    short_title = post.title[:80] + ('…' if len(post.title) > 80 else '')
    log_activity('blog.download_md', f'Downloaded Markdown of "{short_title}"',
                 target_type='blog_post', target_id=post.id, is_public=False)
    return response


# ── JSON export ────────────────────────────────────────────────────────────────

@blog_blueprint.route('/post/<string:post_uuid>/export')
def export_post(post_uuid):
    """Download a blog post as a portable JSON file. Public + published posts only."""
    import re as _re
    from flask import current_app
    post = _get_public_post_or_404(post_uuid)

    base_url = request.url_root.rstrip('/')
    data = BlogModel.export_post_json(post, base_url)

    safe_title = _re.sub(r'[^a-z0-9]+', '-', post.title.lower()).strip('-')[:40]
    filename = f'blog-{safe_title}-{post.uuid[:8]}.json'

    response = current_app.response_class(
        response=json.dumps(data, ensure_ascii=False, indent=2),
        status=200,
        mimetype='application/json',
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    short_title = post.title[:80] + ('…' if len(post.title) > 80 else '')
    log_activity('blog.export', f'Exported blog post "{short_title}"',
                 target_type='blog_post', target_id=post.id, is_public=False)
    return response


@blog_blueprint.route('/api/post/<string:post_uuid>')
def api_post(post_uuid):
    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        return jsonify({'error': 'Not found.'}), 404

    if not post.is_public:
        share_key = request.args.get('key')
        if share_key and post.share_key == share_key:
            pass  # valid share-key access
        elif current_user.is_authenticated and (
                current_user.id == post.user_id or current_user.is_admin()):
            pass  # admin / owner
        else:
            return jsonify({'error': 'Forbidden.'}), 403

    if post.is_public and not post.is_draft:
        log_activity('blog.view', f'Viewed blog post "{post.title}"',
                     target_type='blog_post', target_id=post.id,
                     target_uuid=post_uuid, is_public=False)
    data = post.to_json()
    if current_user.is_authenticated and current_user.is_admin():
        data['share_key'] = post.share_key
    return jsonify(data)


# ── CVE-to-post: CIRCL proxy, rule search, and create-from-cve ───────────────


@blog_blueprint.route('/admin/circl_proxy/<path:cve_id>')
@login_required
def circl_proxy(cve_id):
    """Proxy CVE data from vulnerability.circl.lu to avoid browser CORS issues."""
    err = _admin_required()
    if err:
        return err
    import requests
    try:
        resp = requests.get(
            f'https://vulnerability.circl.lu/api/cve/{cve_id.lower()}',
            timeout=10,
            headers={'Accept': 'application/json', 'User-Agent': 'Rulezet/1.0'},
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502


@blog_blueprint.route('/admin/cve_rule_search')
@login_required
def cve_rule_search():
    """Return rules and bundles matching the given CVE IDs and optional format filter."""
    err = _admin_required()
    if err:
        return err
    from app.core.db_class.db import Rule, Bundle

    cve_ids = [c.strip() for c in request.args.get('cve_ids', '').split(',') if c.strip()][:10]
    formats = [f.strip() for f in request.args.get('formats', '').split(',') if f.strip()]

    seen_rule_ids, matched_rules = set(), []
    seen_bnd_ids,  matched_bnds = set(), []

    for cve_id in cve_ids:
        q = Rule.query.filter(Rule.is_deleted == False, Rule.cve_id.ilike(f'%{cve_id}%'))
        if formats:
            q = q.filter(Rule.format.in_(formats))
        for r in q.limit(50).all():
            if r.id not in seen_rule_ids:
                seen_rule_ids.add(r.id)
                matched_rules.append({'id': r.id, 'uuid': r.uuid, 'title': r.title, 'format': r.format})

        for b in Bundle.query.filter(Bundle.vulnerability_identifiers.ilike(f'%{cve_id}%')).limit(20).all():
            if b.id not in seen_bnd_ids:
                seen_bnd_ids.add(b.id)
                matched_bnds.append({'id': b.id, 'uuid': b.uuid, 'name': b.name})

    return jsonify({'rules': matched_rules, 'bundles': matched_bnds})


@blog_blueprint.route('/admin/create_from_cve', methods=['POST'])
@login_required
def create_from_cve():
    """Create an empty draft blog post and queue a background job to fill it from CVE data."""
    err = _admin_required()
    if err:
        return err
    from app.features.jobs.jobs_core import create_job

    data            = request.get_json(silent=True) or {}
    cve_ids         = [str(c).strip().upper() for c in (data.get('cve_ids') or []) if c][:20]
    formats         = [str(f).strip().lower() for f in (data.get('formats') or [])]
    include_rules   = bool(data.get('include_rules', True))
    include_bundles = bool(data.get('include_bundles', True))

    if not cve_ids:
        return jsonify({'success': False, 'message': 'At least one CVE ID is required.'}), 400

    # Create a placeholder draft immediately so we have a UUID to redirect to
    cve_label = ', '.join(cve_ids[:3]) + ('…' if len(cve_ids) > 3 else '')
    post = BlogModel.create_post({
        'title':     f'[Generating] {cve_label}',
        'content':   '',
        'is_draft':  True,
        'is_public': False,
    }, user_id=current_user.id)

    job = create_job(
        job_type='blog_from_cve',
        payload={
            'post_id':         post.id,
            'cve_ids':         cve_ids,
            'formats':         formats,
            'include_rules':   include_rules,
            'include_bundles': include_bundles,
        },
        label=f'Generate blog post from {cve_label}',
        created_by=current_user.id,
        total=len(cve_ids),
    )

    log_activity(
        action='blog.create_from_cve',
        description=f'Auto-generated blog post from {cve_label}',
        extra={'cve_ids': cve_ids, 'post_uuid': post.uuid, 'job_uuid': job.uuid},
    )

    return jsonify({'success': True, 'post_uuid': post.uuid, 'job_uuid': job.uuid})


# ── Cover image upload ────────────────────────────────────────────────────────

@blog_blueprint.route('/admin/resolve_import_refs', methods=['POST'])
@login_required
def resolve_import_refs():
    """Resolve rule/bundle UUIDs to their local integer IDs for JSON import."""
    err = _admin_required()
    if err:
        return err
    from app.core.db_class.db import Rule, Bundle
    data        = request.get_json(silent=True) or {}
    rule_uuids  = [str(u) for u in (data.get('rule_uuids')  or [])[:100]]
    bundle_uuids= [str(u) for u in (data.get('bundle_uuids') or [])[:50]]

    rules = []
    for uuid in rule_uuids:
        r = Rule.query.filter_by(uuid=uuid, is_deleted=False).first()
        if r:
            rules.append({'id': r.id, 'uuid': r.uuid, 'title': r.title, 'format': r.format})

    bundles = []
    for uuid in bundle_uuids:
        b = Bundle.query.filter_by(uuid=uuid).first()
        if b:
            bundles.append({'id': b.id, 'uuid': b.uuid, 'name': b.name})

    return jsonify({'rules': rules, 'bundles': bundles})


@blog_blueprint.route('/admin/upload_cover/<string:post_uuid>', methods=['POST'])
@login_required
def admin_upload_cover(post_uuid):
    err = _admin_required()
    if err:
        return err

    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'success': False, 'message': 'No file provided.'}), 400

    original_name = secure_filename(f.filename)
    ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
    if ext not in _ALLOWED_IMAGE_EXT:
        return jsonify({'success': False, 'message': f'.{ext} is not allowed. Use PNG, JPG, GIF or WEBP.'}), 400

    mime = f.mimetype or 'application/octet-stream'
    if mime not in _ALLOWED_IMAGE_MIME:
        return jsonify({'success': False, 'message': f'MIME type {mime} is not an accepted image type.'}), 400

    data = f.read(_MAX_COVER_SIZE + 1)
    if len(data) > _MAX_COVER_SIZE:
        return jsonify({'success': False, 'message': 'Image exceeds 5 MB limit.'}), 413

    # Delete old cover file if it was a local upload
    if post.cover_image_url and post.cover_image_url.startswith('/static/uploads/blog/'):
        old_filename = post.cover_image_url.split('/')[-1]
        old_path = os.path.join(_cover_upload_dir(), old_filename)
        if os.path.exists(old_path):
            os.remove(old_path)

    stored_name = f'{_uuid_mod.uuid4()}.{ext}'
    dest = os.path.join(_cover_upload_dir(), stored_name)
    with open(dest, 'wb') as fp:
        fp.write(data)

    url = f'/static/uploads/blog/{stored_name}'

    from app import db
    post.cover_image_url = url
    import datetime
    post.updated_at = datetime.datetime.utcnow()
    db.session.commit()

    return jsonify({'success': True, 'url': url})


# ── Public file download ───────────────────────────────────────────────────────

@blog_blueprint.route('/file/<string:file_uuid>')
def public_file_download(file_uuid):
    """Download a file attached to a blog post. Respects post visibility."""
    from app.core.db_class.db import BlogPostFile
    bf = BlogPostFile.query.filter_by(uuid=file_uuid).first()
    if not bf:
        abort(404)

    post = BlogModel.get_post_by_uuid_by_id(bf.post_id)
    if not post:
        abort(404)

    if not post.is_public:
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)

    path = os.path.join(_blog_upload_dir(), bf.stored_name)
    if not os.path.exists(path):
        abort(404)

    as_attachment = request.args.get('download', '0') == '1'
    return send_file(path, as_attachment=as_attachment, download_name=bf.original_name, mimetype=bf.mime_type)


# ── File attachment routes ─────────────────────────────────────────────────────

@blog_blueprint.route('/admin/file/upload/<string:post_uuid>', methods=['POST'])
@login_required
def admin_file_upload(post_uuid):
    err = _admin_required()
    if err:
        return err

    post = BlogModel.get_post_by_uuid(post_uuid)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'success': False, 'message': 'No file provided.'}), 400

    original_name = secure_filename(f.filename)
    ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
    if ext not in _ALLOWED_EXTENSIONS:
        return jsonify({'success': False, 'message': f'File type .{ext} is not allowed.'}), 400

    mime = f.mimetype or 'application/octet-stream'
    if mime not in _ALLOWED_MIME_TYPES:
        return jsonify({'success': False, 'message': f'MIME type {mime} is not allowed.'}), 400

    # Read with size guard
    data = f.read(_MAX_FILE_SIZE + 1)
    if len(data) > _MAX_FILE_SIZE:
        return jsonify({'success': False, 'message': 'File exceeds 10 MB limit.'}), 413

    file_uuid = str(_uuid_mod.uuid4())
    stored_name = f'{file_uuid}.{ext}'
    dest = os.path.join(_blog_upload_dir(), stored_name)
    with open(dest, 'wb') as fp:
        fp.write(data)

    from app.core.db_class.db import BlogPostFile
    from app import db
    import datetime
    bf = BlogPostFile(
        uuid=file_uuid,
        post_id=post.id,
        original_name=original_name,
        stored_name=stored_name,
        mime_type=mime,
        size_bytes=len(data),
        uploaded_by=current_user.id,
        created_at=datetime.datetime.utcnow(),
    )
    db.session.add(bf)
    db.session.commit()

    log_activity('blog.file_upload', f"Uploaded file '{original_name}' to post id={post.id}",
                 target_type='blog_post', target_id=post.id)
    return jsonify({'success': True, 'file': bf.to_json()})


@blog_blueprint.route('/admin/file/<string:file_uuid>', methods=['GET'])
@login_required
def admin_file_download(file_uuid):
    err = _admin_required()
    if err:
        return err

    from app.core.db_class.db import BlogPostFile
    bf = BlogPostFile.query.filter_by(uuid=file_uuid).first()
    if not bf:
        abort(404)

    path = os.path.join(_blog_upload_dir(), bf.stored_name)
    if not os.path.exists(path):
        abort(404)

    return send_file(path, as_attachment=True, download_name=bf.original_name, mimetype=bf.mime_type)


@blog_blueprint.route('/admin/file/delete/<string:file_uuid>', methods=['POST'])
@login_required
def admin_file_delete(file_uuid):
    err = _admin_required()
    if err:
        return err

    from app.core.db_class.db import BlogPostFile
    from app import db
    bf = BlogPostFile.query.filter_by(uuid=file_uuid).first()
    if not bf:
        return jsonify({'success': False, 'message': 'File not found.'}), 404

    path = os.path.join(_blog_upload_dir(), bf.stored_name)
    if os.path.exists(path):
        os.remove(path)

    db.session.delete(bf)
    db.session.commit()
    return jsonify({'success': True})
