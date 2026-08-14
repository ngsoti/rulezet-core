import uuid as uuid_mod
import datetime

from sqlalchemy import or_

from app import db
from app.core.db_class.db import Permission, Role, RolePermission, UserRole, User


# ─── Permission catalog ──────────────────────────────────────────────────────
# Fixed vocabulary tied to what the app actually checks (see CLAUDE.md-style
# call sites like app/features/rule/rule.py's quick_meta). Admins can attach
# these to roles from the UI, but can't invent new keys — a permission only
# means something once code somewhere calls current_user.has_permission(key).

DEFAULT_PERMISSIONS = [
    {
        "key": "rule.tag_any",
        "label": "Tag any rule",
        "description": "Add tags to any rule, not just rules the user owns.",
    },
]

# System roles pre-seeded with a starter permission set, ready to assign
# users to. Admins can still edit their permission list — only deleting
# them from the UI is blocked (is_system).
DEFAULT_ROLES = [
    {
        "name": "Tag manager",
        "description": "Can tag any rule on the platform.",
        "permission_keys": ["rule.tag_any"],
    },
]


def seed_default_permissions_and_roles():
    """Idempotent — safe to call on every app startup (see app/__init__.py)."""
    for perm in DEFAULT_PERMISSIONS:
        existing = Permission.query.filter_by(key=perm["key"]).first()
        if not existing:
            db.session.add(Permission(
                uuid=str(uuid_mod.uuid4()),
                key=perm["key"],
                label=perm["label"],
                description=perm["description"],
            ))
    db.session.commit()

    for role_def in DEFAULT_ROLES:
        role = Role.query.filter_by(name=role_def["name"]).first()
        if not role:
            role = Role(
                uuid=str(uuid_mod.uuid4()),
                name=role_def["name"],
                description=role_def["description"],
                is_system=True,
            )
            db.session.add(role)
            db.session.commit()

        existing_perm_ids = {
            rp.permission_id for rp in RolePermission.query.filter_by(role_id=role.id).all()
        }
        for key in role_def["permission_keys"]:
            perm = Permission.query.filter_by(key=key).first()
            if perm and perm.id not in existing_perm_ids:
                db.session.add(RolePermission(
                    uuid=str(uuid_mod.uuid4()),
                    role_id=role.id,
                    permission_id=perm.id,
                ))
                existing_perm_ids.add(perm.id)
    db.session.commit()


def get_all_permissions():
    return Permission.query.order_by(Permission.key).all()


# ─── Roles ───────────────────────────────────────────────────────────────────

def get_all_roles():
    return Role.query.order_by(Role.name).all()


def get_user_roles(user_id):
    """Compact role list for a single user — used anywhere a user is
    referenced publicly (UserChip, profile pages), not just the admin UI."""
    rows = (
        db.session.query(Role.id, Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user_id)
        .order_by(Role.name)
        .all()
    )
    return [{"id": rid, "name": rname} for rid, rname in rows]


def list_roles_paginated(page=1, per_page=20, search="", sort="name", dir="asc"):
    """Matches the generic DataTable component's fetch contract
    ({ items, total, total_pages }) — the role catalog is expected to stay
    small, but paginating it the same way as every other admin table keeps
    the page consistent with the rest of the admin UI rather than a bespoke
    one-off list."""
    query = Role.query
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Role.name.ilike(like), Role.description.ilike(like)))

    sort_col = {"name": Role.name, "created_at": Role.created_at}.get(sort, Role.name)
    query = query.order_by(sort_col.desc() if dir == "desc" else sort_col.asc())

    total = query.count()
    per_page = max(1, min(per_page, 100))
    roles = query.offset((page - 1) * per_page).limit(per_page).all()
    total_pages = max(1, (total + per_page - 1) // per_page)

    return {
        "items": [r.to_json() for r in roles],
        "total": total,
        "total_pages": total_pages,
    }


def get_role(role_id):
    return Role.query.get(role_id)


def create_role(name, description=None):
    name = (name or "").strip()
    if not name:
        return None, "Role name is required."
    if Role.query.filter_by(name=name).first():
        return None, "A role with this name already exists."
    role = Role(uuid=str(uuid_mod.uuid4()), name=name, description=description, is_system=False)
    db.session.add(role)
    db.session.commit()
    return role, None


def update_role(role_id, name=None, description=None):
    role = Role.query.get(role_id)
    if not role:
        return None, "Role not found."
    if name is not None:
        name = name.strip()
        if not name:
            return None, "Role name is required."
        dup = Role.query.filter(Role.name == name, Role.id != role_id).first()
        if dup:
            return None, "A role with this name already exists."
        role.name = name
    if description is not None:
        role.description = description
    db.session.commit()
    return role, None


def delete_role(role_id):
    role = Role.query.get(role_id)
    if not role:
        return False, "Role not found."
    if role.is_system:
        return False, "System roles can't be deleted — edit their permissions instead."
    RolePermission.query.filter_by(role_id=role_id).delete()
    UserRole.query.filter_by(role_id=role_id).delete()
    db.session.delete(role)
    db.session.commit()
    return True, None


def bulk_delete_roles(role_ids=None):
    """Delete several roles at once. role_ids=None means "every role" (the
    DataTable's select-all-pages case) — system roles are silently skipped
    either way rather than erroring the whole batch out."""
    query = Role.query
    if role_ids is not None:
        query = query.filter(Role.id.in_(role_ids))
    roles = query.all()

    deleted, skipped = 0, 0
    for role in roles:
        if role.is_system:
            skipped += 1
            continue
        RolePermission.query.filter_by(role_id=role.id).delete()
        UserRole.query.filter_by(role_id=role.id).delete()
        db.session.delete(role)
        deleted += 1
    db.session.commit()
    return deleted, skipped


def set_role_permissions(role_id, permission_ids):
    """Replace a role's permission set wholesale — the admin UI submits the
    full checklist state each time, so a sync (not incremental add/remove)
    matches what the form actually represents."""
    role = Role.query.get(role_id)
    if not role:
        return False, "Role not found."
    permission_ids = {int(p) for p in (permission_ids or [])}
    current = {rp.permission_id: rp for rp in RolePermission.query.filter_by(role_id=role_id).all()}

    for perm_id, rp in current.items():
        if perm_id not in permission_ids:
            db.session.delete(rp)
    for perm_id in permission_ids:
        if perm_id not in current and Permission.query.get(perm_id):
            db.session.add(RolePermission(uuid=str(uuid_mod.uuid4()), role_id=role_id, permission_id=perm_id))
    db.session.commit()
    return True, None


# ─── User <-> Role assignment ────────────────────────────────────────────────

def get_role_users(role_id, page=1, per_page=20):
    """Matches the generic DataTable component's fetch contract
    ({ items, total, total_pages })."""
    query = (
        db.session.query(User, UserRole)
        .join(UserRole, UserRole.user_id == User.id)
        .filter(UserRole.role_id == role_id)
        .order_by(User.first_name)
    )
    total = query.count()
    per_page = max(1, min(per_page, 100))
    rows = query.offset((page - 1) * per_page).limit(per_page).all()
    total_pages = max(1, (total + per_page - 1) // per_page)

    granter_ids = {ur.granted_by for _, ur in rows if ur.granted_by}
    granters = {u.id: u for u in User.query.filter(User.id.in_(granter_ids)).all()} if granter_ids else {}

    items = [
        {
            "id": u.id,
            "username": u.get_username(),
            "profile_picture": u.get_avatar_url(),
            "granted_at": ur.granted_at.strftime('%Y-%m-%d %H:%M') if ur.granted_at else None,
            "granted_by": (
                {
                    "id": ur.granted_by,
                    "username": granters[ur.granted_by].get_username(),
                    "avatar": granters[ur.granted_by].get_avatar_url(),
                }
                if ur.granted_by in granters else None
            ),
        }
        for u, ur in rows
    ]
    return {"items": items, "total": total, "total_pages": total_pages}


def add_user_to_role(role_id, user_id, granted_by_id):
    role = Role.query.get(role_id)
    user = User.query.get(user_id)
    if not role or not user:
        return False, "Role or user not found."
    if UserRole.query.filter_by(role_id=role_id, user_id=user_id).first():
        return False, "This user already has this role."
    db.session.add(UserRole(
        uuid=str(uuid_mod.uuid4()),
        role_id=role_id,
        user_id=user_id,
        granted_by=granted_by_id,
        granted_at=datetime.datetime.now(tz=datetime.timezone.utc),
    ))
    db.session.commit()
    try:
        from app.features.notification.notification_core import notify_role_assignment
        notify_role_assignment(user_id, role.name, granted=True)
    except Exception:
        pass
    return True, None


def remove_user_from_role(role_id, user_id):
    ur = UserRole.query.filter_by(role_id=role_id, user_id=user_id).first()
    if not ur:
        return False, "This user doesn't have this role."
    role = Role.query.get(role_id)
    db.session.delete(ur)
    db.session.commit()
    try:
        from app.features.notification.notification_core import notify_role_assignment
        notify_role_assignment(user_id, role.name if role else "role", granted=False)
    except Exception:
        pass
    return True, None


def search_assignable_users(role_id, search="", limit=10):
    """Users not already holding this role, for the admin UI's add-user picker."""
    already = {ur.user_id for ur in UserRole.query.filter_by(role_id=role_id).all()}
    query = User.query
    if search:
        like = f"%{search}%"
        query = query.filter(or_(
            User.first_name.ilike(like), User.last_name.ilike(like),
            User.username.ilike(like), User.email.ilike(like),
        ))
    users = query.order_by(User.first_name).limit(200).all()
    results = [u for u in users if u.id not in already][:limit]
    return [
        {"id": u.id, "username": u.get_username(), "profile_picture": u.get_avatar_url()}
        for u in results
    ]
