import os
import re
import uuid as uuid_mod
from datetime import datetime
from flask import current_app
from flask_login import current_user
from ... import db
from ...core.db_class.db import UserConfig, CustomTheme, THEME_CHOICES, _slugify, PivotickBackground


# CSS variable keys that admins can customise per-theme.
THEME_VAR_KEYS = [
    '--bg-color', '--card-bg-color', '--light-bg-color', '--code-bg-color',
    '--card-header-bg-color', '--navbar-bg-color', '--bar-bg-color',
    '--text-color', '--subtle-text-color', '--navbar-text-color',
    '--border-color', '--selected-color', '--page-selected-color',
    '--sidebar-color', '--rule-name-color',
]

BUILTIN_STATIC_THEMES = set(THEME_CHOICES)
BUILTIN_OVERRIDABLE   = {'dark'}
_BUILTIN_META = {
    'dark': ('Dark', 'fa-moon', True),
}

# Named themes shipped with the app (CSS defined in themes/theme.css).
# These are always available regardless of the DB.
_OCEAN_VARS = {
    '--bg-color': '#edf4fb', '--card-bg-color': '#f8fbff', '--light-bg-color': '#ddeaf7',
    '--code-bg-color': '#e4f0fa', '--card-header-bg-color': '#d0e5f5',
    '--navbar-bg-color': '#f8fbff', '--bar-bg-color': '#ddeaf7',
    '--text-color': '#0d2a40', '--subtle-text-color': '#4a7fa5', '--navbar-text-color': '#0d2a40',
    '--border-color': 'rgba(30, 120, 180, 0.18)', '--selected-color': 'rgba(30, 120, 180, 0.12)',
    '--page-selected-color': '#1878b4', '--sidebar-color': '#0a2c45', '--rule-name-color': '#1565c0',
}
_FOREST_VARS = {
    '--bg-color': '#eef5ee', '--card-bg-color': '#f7fbf7', '--light-bg-color': '#daeeda',
    '--code-bg-color': '#e5f2e5', '--card-header-bg-color': '#cce6cc',
    '--navbar-bg-color': '#f7fbf7', '--bar-bg-color': '#daeeda',
    '--text-color': '#102210', '--subtle-text-color': '#3d7040', '--navbar-text-color': '#102210',
    '--border-color': 'rgba(40, 130, 50, 0.18)', '--selected-color': 'rgba(40, 130, 50, 0.12)',
    '--page-selected-color': '#288232', '--sidebar-color': '#092b0b', '--rule-name-color': '#1b6e22',
}
_MIDNIGHT_VARS = {
    '--bg-color': '#080d18', '--card-bg-color': '#0f1729', '--light-bg-color': '#151f38',
    '--code-bg-color': '#050912', '--card-header-bg-color': '#151f38',
    '--navbar-bg-color': '#0a1122', '--bar-bg-color': '#0f1729',
    '--text-color': '#c8d8f0', '--subtle-text-color': '#6080b0', '--navbar-text-color': '#c8d8f0',
    '--border-color': 'rgba(80, 130, 220, 0.14)', '--selected-color': 'rgba(80, 130, 220, 0.18)',
    '--page-selected-color': '#5082dc', '--sidebar-color': '#040810', '--rule-name-color': '#6aa0f0',
}
_SUNSET_VARS = {
    '--bg-color': '#1c1008', '--card-bg-color': '#281808', '--light-bg-color': '#362010',
    '--code-bg-color': '#140c05', '--card-header-bg-color': '#362010',
    '--navbar-bg-color': '#201408', '--bar-bg-color': '#281808',
    '--text-color': '#f5dfc0', '--subtle-text-color': '#b87840', '--navbar-text-color': '#f5dfc0',
    '--border-color': 'rgba(220, 120, 30, 0.18)', '--selected-color': 'rgba(220, 120, 30, 0.20)',
    '--page-selected-color': '#e07820', '--sidebar-color': '#0e0804', '--rule-name-color': '#f09040',
}

BUILTIN_NAMED_THEMES = {
    'ocean':    {'label': 'Ocean',    'icon': 'fa-water',      'is_dark': False, 'css_vars': _OCEAN_VARS},
    'forest':   {'label': 'Forest',   'icon': 'fa-tree',       'is_dark': False, 'css_vars': _FOREST_VARS},
    'midnight': {'label': 'Midnight', 'icon': 'fa-moon',       'is_dark': True,  'css_vars': _MIDNIGHT_VARS},
    'sunset':   {'label': 'Sunset',   'icon': 'fa-fire',       'is_dark': True,  'css_vars': _SUNSET_VARS},
}


def seed_default_themes():
    """Create/backfill built-in named themes in the DB and regenerate CSS."""
    try:
        changed = False
        for css_key, meta in BUILTIN_NAMED_THEMES.items():
            theme = CustomTheme.query.filter_by(css_key=css_key).first()
            if not theme:
                theme = CustomTheme(
                    name=meta['label'], css_key=css_key,
                    icon=meta['icon'], is_dark=meta['is_dark'],
                    is_builtin=False, is_public=True,
                    css_vars=meta.get('css_vars'), created_by=None,
                )
                db.session.add(theme)
                changed = True
            else:
                if meta.get('css_vars') and theme.css_vars != meta['css_vars']:
                    theme.css_vars = meta['css_vars']
                    changed = True
                if theme.is_dark != meta['is_dark']:
                    theme.is_dark = meta['is_dark']
                    changed = True
        if changed:
            db.session.commit()
            regenerate_custom_themes_css()
    except Exception:
        db.session.rollback()


def get_valid_theme_keys(admin=False):
    """Return the set of theme identifiers a user may select."""
    q = CustomTheme.query.filter_by(is_active=True, is_builtin=False)
    if not admin:
        q = q.filter_by(is_public=True)
    custom_keys = {t.css_key for t in q.all()}
    return BUILTIN_STATIC_THEMES | set(BUILTIN_NAMED_THEMES.keys()) | custom_keys


def get_all_custom_themes(admin_view=True):
    q = CustomTheme.query.filter_by(is_active=True)
    if not admin_view:
        q = q.filter_by(is_public=True)
    return q.order_by(CustomTheme.id).all()


def regenerate_custom_themes_css():
    """Rewrite app/static/css/themes/custom-themes.css from the DB.

    Each theme uses dual selectors to beat body.dark-mode specificity:
      html[data-theme="X"]       (0,1,1) beats [data-bs-theme="dark"] (0,1,0)
      html[data-theme="X"] body  (0,1,2) beats body.dark-mode          (0,1,1)
    """
    themes = CustomTheme.query.filter_by(is_active=True).order_by(CustomTheme.id).all()
    lines = ['/* Auto-generated custom themes — do not edit manually */']
    for t in themes:
        if not t.css_vars:
            continue
        var_lines = [
            f'    {var}: {value};'
            for var, value in t.css_vars.items()
            if var in THEME_VAR_KEYS and value
        ]
        if not var_lines:
            continue
        lines.append(f'\nhtml[data-theme="{t.css_key}"],')
        lines.append(f'html[data-theme="{t.css_key}"] body {{')
        lines.extend(var_lines)
        lines.append('}')
    css = '\n'.join(lines) + '\n'
    path = os.path.join(current_app.root_path, 'static', 'css', 'themes', 'custom-themes.css')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(css)


# ── UserConfig CRUD ──────────────────────────────────────────────────────────

def get_user_config(user_id=None):
    uid = user_id or (current_user.id if current_user.is_authenticated else None)
    if not uid:
        return None
    return UserConfig.query.filter_by(user_id=uid, is_active=True).first()


def create_default_config_core(user_id) -> tuple:
    try:
        existing = UserConfig.query.filter_by(user_id=user_id).first()
        if existing:
            return existing, 'Config already exists'
        config = UserConfig(user_id=user_id, created_by=user_id)
        db.session.add(config)
        db.session.commit()
        return config, 'Config created'
    except Exception:
        db.session.rollback()
        return None, 'Error creating config'


def update_config_core(form_dict) -> tuple:
    try:
        uid = current_user.id if current_user.is_authenticated else None
        if not uid:
            return None, 'Not authenticated'
        config = get_user_config(uid)
        if not config:
            config, msg = create_default_config_core(uid)
            if not config:
                return None, msg

        if 'theme' in form_dict:
            is_admin = current_user.is_admin() if current_user.is_authenticated else False
            if form_dict['theme'] not in get_valid_theme_keys(admin=is_admin):
                return None, 'Invalid theme'
            config.theme = form_dict['theme']

        db.session.commit()
        return config, 'Settings saved'
    except Exception:
        db.session.rollback()
        return None, 'Error saving settings'


# ── CustomTheme CRUD ─────────────────────────────────────────────────────────

def create_custom_theme_core(data, user_id):
    try:
        name = (data.get('name') or '').strip()
        if not name or len(name) > 64:
            return None, 'Theme name is required (max 64 chars)'
        css_key = _slugify(name)
        if not css_key:
            return None, 'Invalid theme name'
        if css_key in BUILTIN_STATIC_THEMES:
            return None, 'Cannot use a built-in theme name'
        if CustomTheme.query.filter_by(css_key=css_key).first():
            return None, 'A theme with this name already exists'
        icon    = (data.get('icon') or 'fa-palette').strip()
        is_dark = bool(data.get('is_dark', False))
        css_vars = {k: v for k, v in (data.get('css_vars') or {}).items()
                    if k in THEME_VAR_KEYS and v}
        theme = CustomTheme(
            name=name, css_key=css_key, icon=icon,
            is_dark=is_dark, is_builtin=False,
            css_vars=css_vars or None, created_by=user_id,
        )
        db.session.add(theme)
        db.session.commit()
        regenerate_custom_themes_css()
        return theme, 'Theme created'
    except Exception as e:
        db.session.rollback()
        return None, f'Error creating theme: {e}'


def update_custom_theme_core(uuid, data, user_id):
    try:
        theme = CustomTheme.query.filter_by(uuid=uuid, is_active=True).first()
        if not theme:
            return None, 'Theme not found'
        if not theme.is_builtin:
            name = (data.get('name') or '').strip()
            if name and len(name) <= 64:
                theme.name = name
            icon = data.get('icon')
            if icon:
                theme.icon = icon.strip()
            if 'is_dark' in data:
                theme.is_dark = bool(data['is_dark'])
        if 'is_public' in data:
            theme.is_public = bool(data['is_public'])
        if 'css_vars' in data:
            css_vars = {k: v for k, v in (data['css_vars'] or {}).items()
                        if k in THEME_VAR_KEYS and v}
            theme.css_vars = css_vars or None
        db.session.commit()
        regenerate_custom_themes_css()
        return theme, 'Theme updated'
    except Exception as e:
        db.session.rollback()
        return None, f'Error updating theme: {e}'


def upsert_builtin_theme_override_core(css_key, data, user_id):
    if css_key not in BUILTIN_OVERRIDABLE:
        return None, 'Not a valid built-in theme'
    try:
        theme = CustomTheme.query.filter_by(css_key=css_key, is_builtin=True).first()
        bname, bicon, bdark = _BUILTIN_META[css_key]
        if not theme:
            theme = CustomTheme(
                name=bname, css_key=css_key, icon=bicon,
                is_dark=bdark, is_builtin=True, created_by=user_id,
            )
            db.session.add(theme)
        css_vars = {k: v for k, v in (data.get('css_vars') or {}).items()
                    if k in THEME_VAR_KEYS and v}
        theme.css_vars  = css_vars or None
        theme.is_active = bool(css_vars)
        db.session.commit()
        regenerate_custom_themes_css()
        return theme, 'Theme vars saved'
    except Exception as e:
        db.session.rollback()
        return None, f'Error saving theme: {e}'


def reset_builtin_theme_core(css_key, user_id):
    if css_key not in BUILTIN_OVERRIDABLE:
        return False, 'Not a valid built-in theme'
    try:
        theme = CustomTheme.query.filter_by(css_key=css_key, is_builtin=True).first()
        if theme:
            theme.is_active = False
            theme.css_vars  = None
            db.session.commit()
            regenerate_custom_themes_css()
        return True, 'Built-in theme reset to defaults'
    except Exception as e:
        db.session.rollback()
        return False, f'Error resetting theme: {e}'


def delete_custom_theme_core(uuid, user_id):
    try:
        theme = CustomTheme.query.filter_by(uuid=uuid, is_active=True).first()
        if not theme:
            return False, 'Theme not found'
        if theme.is_builtin:
            return False, 'Cannot delete a built-in theme override'
        theme.is_active  = False
        theme.deleted_at = datetime.utcnow()
        theme.deleted_by = user_id
        db.session.commit()
        regenerate_custom_themes_css()
        return True, 'Theme deleted'
    except Exception as e:
        db.session.rollback()
        return False, f'Error deleting theme: {e}'


# ── PivoTick background gallery (admin uploads, any user can select) ─────────

PIVOTICK_BG_UPLOAD_FOLDER = os.path.join("app", "static", "uploads", "pivotick_backgrounds")
ALLOWED_PIVOTICK_BG_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_PIVOTICK_BG_SIZE_MB = 25


def list_pivotick_backgrounds():
    return PivotickBackground.query.order_by(PivotickBackground.created_at.desc()).all()


def save_pivotick_background(image_file, name, user_id):
    if not image_file or not image_file.filename:
        return None, 'No file provided'

    ext = image_file.filename.rsplit('.', 1)[-1].lower() if '.' in image_file.filename else ''
    if ext not in ALLOWED_PIVOTICK_BG_EXTENSIONS:
        return None, f'Unsupported file type. Allowed: {", ".join(sorted(ALLOWED_PIVOTICK_BG_EXTENSIONS))}'

    image_file.seek(0, os.SEEK_END)
    size_mb = image_file.tell() / (1024 * 1024)
    image_file.seek(0)
    if size_mb > MAX_PIVOTICK_BG_SIZE_MB:
        return None, f'File too large (max {MAX_PIVOTICK_BG_SIZE_MB} MB)'

    try:
        os.makedirs(PIVOTICK_BG_UPLOAD_FOLDER, exist_ok=True)
        filename = f"{uuid_mod.uuid4().hex}.{ext}"
        image_file.save(os.path.join(PIVOTICK_BG_UPLOAD_FOLDER, filename))

        bg = PivotickBackground(
            uuid=str(uuid_mod.uuid4()),
            filename=filename,
            name=(name or '').strip()[:128] or None,
            uploaded_by=user_id,
        )
        db.session.add(bg)
        db.session.commit()
        return bg, 'Background uploaded'
    except Exception as e:
        db.session.rollback()
        return None, f'Error uploading background: {e}'


def delete_pivotick_background(bg_id):
    bg = PivotickBackground.query.get(bg_id)
    if not bg:
        return False, 'Background not found'
    try:
        path = os.path.join(PIVOTICK_BG_UPLOAD_FOLDER, bg.filename)
        if os.path.isfile(path):
            os.remove(path)
        db.session.delete(bg)
        db.session.commit()
        return True, 'Background deleted'
    except Exception as e:
        db.session.rollback()
        return False, f'Error deleting background: {e}'
