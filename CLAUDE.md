Flask + Vue.js 3 + PostgreSQL. Community platform for cybersecurity detection rules (YARA, Sigma, Suricata, Zeek, etc.). Live at rulezet.org.

Preferred entrypoint is `manage.py` (wraps everything below): `python3 manage.py start` (dev server), `python3 manage.py test`, `python3 manage.py update` (post-`git pull` deps+db sync), `python3 manage.py deploy` (prod backup+update+restart), `python3 manage.py db-init` / `db-reload`, `python3 manage.py backup` / `restore`. Full list: `python3 manage.py --help`.
Lower-level equivalents still used directly in dev: `source env/bin/activate && ./launch.sh -l` (run dev), `./launch.sh -t` or `FLASKENV=testing pytest tests` (run tests), `python3 app.py -i` (DB init) / `-r` (DB reset).
Single test: `FLASKENV=testing pytest tests/rules/test_rule.py -k "test_name"`
Migrations: `flask db migrate -m "desc" && flask db upgrade`
Environments via `FLASKENV`: `development` (pg, debug), `testing` (sqlite, no csrf), `production` (pg).
App runs on `127.0.0.1:7009` by default. Secrets in `.env` — see `.env_default` for the full set (includes `GITHUB_TOKEN` for GitHub rule import/issue filing, `MAIL_SERVER`/`MAIL_PORT`/etc., `INSTANCE_PUBLIC_URL`); chatbot feature also reads `OLLAMA_URL`/`OLLAMA_MODEL` from `config.py`.
CI: `.github/workflows/main.yml` runs `./launch.sh -t` on every push; `.github/workflows/codeql.yml` runs CodeQL security scanning.

All SQLAlchemy models in `app/core/db_class/db.py` (74 model classes, ~3500 lines — search, don't read linearly).
Feature logic split: blueprint in `app/features/<feature>/<feature>.py`, DB logic in `*_core.py`.
Feature folders under `app/features/`: `account`, `admin`, `attack`, `blog`, `bundle`, `chatbot` (Ollama-backed assistant), `community`, `config`, `connector`, `dashboard`, `docs`, `jobs`, `misp`, `notification`, `report`, `rule`, `rule_tester`, `tags`, `velociraptor`, `workspace`.
REST API (Flask-RESTX, CSRF exempt) under `/api/`, swagger at `/api/`. Public/private namespaces per feature: `rule`, `bundle`, `connector`, `account`, `comment`, `config`, `log`, `instance`, `rule_tester`, `utils`.
API key auth via `@api_required` decorator, key in `X-API-KEY` header.
Background jobs: `BackgroundJob` rows, handlers registered with `@register_handler('type')` in `app/features/jobs/job_handlers.py` (~20 types, e.g. `bulk_add_tag_to_rules`, `delete_github_rules`, `connector_pull`, `update_misp_data`, `bulk_parse_attack_rules`, `trash_restore_bulk`), worker in `job_worker.py` polls every 2s.
Activity log everywhere: `from app.core.utils.activity_log import log_activity` — action dot-namespaced e.g. `rule.create`.

CRITICAL: never use `Rule.query` directly — always use `_active()` from `rule_core.py` which filters `is_deleted == False`.
Rules are soft-deleted (fields: `is_deleted`, `deleted_at`, `deleted_by_id`, `delete_batch_uuid`). Trash admin at `/rule/trash`.
Default tags `tlp:clear` and `pap:clear` auto-attached to every new rule via `_attach_default_tags()`.

Vue.js 3 UMD (not build step), ES modules, delimiters `['[[', ']]']` in templates.
Toasts via `create_message(msg, class)` from `/static/js/toaster.js` — never inline alert divs.
Pagination: use `PaginationComponent` from `/static/js/rule/paginationComponent.js`.
`ChartViewer` needs `window.echarts` (ECharts CDN) loaded globally; data format: `{ categories: [...], series: [{ name, values: [...] }] }`.

Page layout pattern — breadcrumb inside the banner, then cards:
Breadcrumb goes inside `.explorer-banner`, above the icon+title row. Truncate page title at 40 chars in breadcrumb, 60 in `<h2>`.
```html
<nav aria-label="breadcrumb" class="mb-2">
  <ol class="breadcrumb mb-0" style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.03em;">
    <li class="breadcrumb-item"><a href="/" class="text-decoration-none text-muted">Home</a></li>
    <li class="breadcrumb-item"><a href="/section" class="text-decoration-none text-muted">Section</a></li>
    <li class="breadcrumb-item active text-muted" aria-current="page">{% if title|length > 40 %}{{ title[:40] }}…{% else %}{{ title }}{% endif %}</li>
  </ol>
</nav>
```

Main detail card (used on rule/bundle/user detail pages):
```html
<div class="card h-100 border-0 card_detail border-top shadow-lg position-relative mb-4" style="border-radius:12px;">
  <div class="card-watermark-detail"><i class="fa-solid fa-[icon]"></i></div>
  <div class="position-absolute top-0 end-0 mt-3 me-3 d-flex gap-2" style="z-index:2;">
    <!-- badges here -->
  </div>
  <div class="card-body p-4 p-md-5">
    <!-- content -->
  </div>
</div>
```
CSS for detail pages: always include `css/rule/base/detail_rule.css` — shared between rule, bundle, and any detail page.
`.card_detail` = deep shadow. `.card-watermark-detail` = decorative oversized icon (18rem, blue 3% opacity, top-right).
`.card-security-premium` = hover lift effect (translateY -12px). Add on cards in list views.
`.premium-accent-line` = thin blue gradient line at top of a card (absolute, top 0, 80% width).

Secondary content cards (panels/sections inside a detail page): `<div class="card border-0 shadow-sm rounded-3 mb-4">` with `<div class="card-body p-4">`.
Inline section separators inside a card: `<div class="rounded-3 border p-3 mb-4" style="background:var(--light-bg-color);">`.

Page banner structure (all nav pages use this):
```html
<div class="explorer-banner mb-4">
  <i class="fa-solid fa-[icon] banner-watermark"></i>
  <div class="d-flex align-items-center gap-3 mb-3">
    <div class="banner-icon"><i class="fa-solid fa-[icon]"></i></div>
    <div><h2 class="fw-bold mb-1">Title</h2><div class="banner-accent"></div></div>
  </div>
  <p class="text-muted mb-0" style="max-width:600px;font-size:.95rem;">Description.</p>
</div>
```
Banner gradient uses only blue tones: `#0d6efd → #0a58ca`.

Style reference for new pages: `app/templates/account/detail_user.html` + `app/static/css/account/user_detail.css`.
KPI cards: `.ud-kpi-card.ud-kpi-card--blue/teal/green/gold/purple/orange`
Info cells: `.ud-info-cell` in a `.ud-info-grid` container
Section headers: `.ud-section-header` with `.ud-section-icon`, `.ud-section-title`, `.ud-section-sub`
Chart cards: `.ud-chart-card.ud-chart-card--accent-blue/teal/purple/orange/green/gold`

Dark mode CSS vars: `--text-color`, `--subtle-text-color`, `--card-bg-color`, `--border-color`, `--light-bg-color`.
Use `var(--subtle-text-color)` for secondary text — `var(--color-text)` does not exist.

Shared components in `app/static/js/components/` (ES modules, each has matching CSS in `css/components/`):
`SmartEditor` — multi-mode editor (code/markdown/text), used on rule create/edit pages.
`CodeViewer` — read-only syntax-highlighted code display, props: `code`, `language`, `filename`. Used everywhere a rule is shown.
`DiffViewer` — side-by-side diff, props: `old_content`, `new_content`. Used on edit proposals and rule history.
`ChartViewer` — ECharts wrapper, chart types: line/area/bar/bar-h/pie/donut/scatter. Used on stats/analytics pages.
`Timeline` — vertical event list, prop: `events [{date, label, icon, color}]`. Used in connector history, activity feeds.
`AnsiTerminal` — renders ANSI color codes, prop: `content`. Used in job logs.
`FileTree` — recursive tree, prop: `node`, emits `select`. Used in bundle structure.
`UserChip` — user avatar + name badge, prop: `user`. Used almost everywhere a user is referenced.
`CommentThread` — full comment thread (reactions, replies), from `components/comments/comment-thread.js`. Used on rule and bundle detail pages.
`LoadingBar` — thin progress bar, from `components/loading-bar.js`. Used during async operations.
`KeyValue` — simple key/value display row, from `components/key-value.js`.
`DataTable` — generic sortable table, from `components/table/data-table.js`.
`LogTable` — log entry table, from `components/log-table.js`. Used on admin logs page.
`ReportModal` — user report/flag dialog, from `components/ReportModal.js`. Used on rule and bundle pages.
`JobTracker` — live background job progress, from `/static/js/jobs/JobTracker.js`. Used on job detail page.
`TagInput` — tag selector with autocomplete, from `/static/js/tags/tagInput.js`. Used on rule/bundle create+edit.
`AttackInput` — ATT&CK technique selector, from `/static/js/attack/attackInput.js`. Used on rule create/edit.
`BundleRuleSelector` — pick rules to add to a bundle, from `/static/js/bundle/BundleRuleSelector.js`.
`BundleStructureEditor` — drag-and-drop tree editor for bundle folders, from `/static/js/bundle/BundleStructureEditor.js`.
`AttackMatrix` — MITRE ATT&CK matrix heatmap, from `/static/js/components/attack-matrix.js`.
`AttackDisplay` — single technique badge/card, from `/static/js/components/AttackDisplay.js`.

RuleList component (`app/static/js/rule/ruleList.js`) — always register with TagsDisplaysList + VulnerabilityDisplaysList.
RuleList CSS deps: `dataTable.css`, `code-viewer.css`, `ruleList.css`.
RuleList modes: `read`, `select`, `manage`. Bulk actions `delete`/`download`/`bundle` are internal.
ATT&CK chips use `AttackDisplayList` from `/static/js/attack/attackDisplayList.js` — CSS is in `ruleList.css` (adl-* classes).
MultiAttackFilter `apiEndpoint` prop must return `{ id: technique_id_string, name, tactic_keys, count }` — id must be the string like "T1068", not the integer PK.

Roles & permissions — always enforce, never skip:
3 levels: anonymous (read-only public), authenticated user (create/vote/comment/favorite), admin (`user.admin=True`, checked via `current_user.is_admin()`).
Owner = the user whose `id` matches the resource's `user_id` field. Owner and admin can edit/delete; nobody else can.
Backend guard pattern: `@login_required` on the route, then `if current_user.id != resource.user_id and not current_user.is_admin(): return jsonify(...), 403`.
Never allow a user to act on another user's resource without `is_admin()` check.
Jinja: `{% if current_user.is_authenticated %}` — for logged-in only. `{% if current_user.id == rule.user_id %}` — owner only. `{% if current_user.is_authenticated and (current_user.id == rule.user_id or current_user.is_admin()) %}` — owner or admin.
Vue: pass auth state via Jinja into `const is_admin = {{ current_user.is_admin() | tojson }}` and `const currentUserId = {{ current_user.id if current_user.is_authenticated else 'null' }}`. Owner check in Vue: `parseInt('{{ current_user.id }}') === resource.user_id || is_admin`.
CommentThread props: `:can-create`, `:can-edit-own`, `:can-delete-own` (all = `is_authenticated`), `:can-moderate` (= `is_admin()`).
RuleList props: `:current-user-id`, `:current-user-is-admin`, `:current-user-is-authenticated` — edit/delete buttons appear automatically when owner or admin.
Admin-only pages: use `before_request` hook returning 403 for non-admins, not inline checks per route.

Tag tooltips use Vue `<teleport to="body">` with `position:fixed` to escape overflow:hidden parents.
Connectors (federation sync) admin-only. Pull modes: soft (skip existing) / hard (update in place). Match by uuid only.
Instance telemetry: phone-home to rulezet.org every 24h. `IS_OFFICIAL_INSTANCE=true` only on rulezet.org.
Tests: SQLite, no CSRF. `conftest.py` calls `create_user_test()`, `create_admin_test()`, `create_rule_test()` (defined in `app/core/utils/init_db.py`) inside the `app` fixture.

File organisation — never put files in the wrong place:
Python blueprints → `app/features/<feature>/`  |  DB logic → `app/features/<feature>/<feature>_core.py`  |  API → `app/api/<feature>/`
Templates → `app/templates/<feature>/`  — one subfolder per feature, mirrors the blueprint structure.
JS components (reusable across features) → `app/static/js/components/`  — their CSS goes in `app/static/css/components/`.
JS feature code (specific to one feature) → `app/static/js/<feature>/`  — their CSS goes in `app/static/css/<feature>/`.
Shared/global CSS → `app/static/css/core.css`  — only add here if truly global (new CSS var, banner class, card class, etc.).
Never put inline `<style>` blocks in templates unless it's a one-off animation that belongs nowhere else.
Never put feature JS in `components/` and never put reusable components in a feature folder.
New feature = new subfolder in templates + js + css, named identically (e.g. `attack/`, `connector/`).
