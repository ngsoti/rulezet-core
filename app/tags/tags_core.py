import datetime
import json
import math
import uuid

from pathlib import Path
from app import db
from app.db_class.db import Tag


def create_tag(form_data, created_by):
    """Create a new tag in the database."""
    try: 
        existing_tag = Tag.query.filter_by(name=form_data['name']).first()
        if existing_tag:
            return False 
        if created_by.is_admin:
            _is_active = True
            _approved_by_admin = True
        else:
            _is_active = False
            _approved_by_admin = False

        tag = Tag(
            uuid=str(uuid.uuid4()),
            name=form_data['name'],
            description=form_data.get('description', ''),
            created_at=datetime.datetime.now(tz=datetime.timezone.utc),
            updated_at=datetime.datetime.now(tz=datetime.timezone.utc), 
            color=form_data.get('color', '#FFFFFF'),
            icon=form_data.get('icon', 'fa-tag'),
            created_by=created_by.id,
            is_active=_is_active,
            is_approved_by_admin=_approved_by_admin,
            visibility=form_data['visibility'],
            external_id=form_data.get('external_id', None)
        )
        db.session.add(tag)
        db.session.commit()
        return tag
    except Exception as e:
        print(f"Error creating tag: {e}")
        return None
    

def get_tags(args):
    query = Tag.query

    if args.get('search'):
        query = query.filter(Tag.name.ilike(f"%{args['search']}%"))

    sort_order = args.get('sort_order', 'asc')
    if sort_order == 'asc':
        query = query.order_by(Tag.created_at.desc())
    else:
        query = query.order_by(Tag.created_at.asc())

    if args.get('visibility'):
        if args['visibility'] != 'all':
            query = query.filter_by(visibility=args['visibility'])
    if args.get('is_active'):
        if args['is_active'] != 'all':
            is_active_value = True if args['is_active'] == 'active' else False
            query = query.filter_by(is_active=is_active_value)

    

    page = int(args.get('page', 1))
    return query.paginate(page=page, per_page=20, max_per_page=20)

def remove_tag(tag_id):
    try:
        tag = Tag.query.get(tag_id)
        if not tag:
            return False, "Tag not found."

        db.session.delete(tag)
        db.session.commit()
        return True, "Tag successfully deleted."
    except Exception as e:
        print(f"Error deleting tag: {e}")
        return False, "An error occurred while deleting the tag."

def toggle_tag_visibility(tag_uuid):
    try:
        tag = Tag.query.filter_by(uuid=tag_uuid).first()
        if not tag:
            return False, "Tag not found."

        if tag.visibility == "public":
            tag.visibility = "private"
        elif tag.visibility == "private":
            tag.visibility = "public"
        else:
            tag.visibility = "public"

        db.session.commit()
        return True, f"Tag visibility changed to {tag.visibility}."
    except Exception as e:
        return False, "An error occurred while toggling the tag visibility."

def toggle_tag_status(tag_uuid):
    try:
        tag = Tag.query.filter_by(uuid=tag_uuid).first()
        if not tag:
            return False, "Tag not found."

        tag.is_active = not tag.is_active

        db.session.commit()
        status = "active" if tag.is_active else "inactive"
        return True, f"Tag status changed to {status}."
    except Exception as e:
        return False, "An error occurred while toggling the tag status."
def edit_tag(form_data, tag_id):
    try:
        tag = Tag.query.get(tag_id)
        if not tag:
            return False, "Tag not found."

        if tag.name != form_data['name'] and Tag.query.filter_by(name=form_data['name']).first():
            return False, "A tag with this name already exists."
        #duplicate uuid check
        if tag.external_id != form_data['external_id'] and Tag.query.filter_by(external_id=form_data['external_id']).first():
            return False, "A tag with this uuid already exists."

        tag.name = form_data['name']
        tag.description = form_data.get('description', tag.description)
        tag.color = form_data.get('color', tag.color)
        tag.icon = form_data.get('icon', tag.icon)
        tag.external_id = form_data.get('external_id', tag.external_id)
        tag.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)

        db.session.commit()
        return True, "Tag successfully updated."
    except Exception as e:
        print(f"Error updating tag: {e}")
        return False, None

MISP_TAXONOMIES_PATH = "app/modules/misp-taxonomies"
def list_all_misp_taxonomies_meta(args):
    """
    List only the main metadata of each MISP taxonomy (no predicates/values),
    excluding taxonomies already present in DB (by namespace).
    """

    taxonomies = []
    base_path = Path(MISP_TAXONOMIES_PATH)

    # 🔥 Namespaces déjà en base
    existing_namespaces = get_all_taxonomies_in_db()

    for taxonomy_dir in sorted(base_path.iterdir()):
        if not taxonomy_dir.is_dir():
            continue

        json_files = list(taxonomy_dir.glob("*.json"))
        if not json_files:
            continue

        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                namespace = data.get("namespace")
                if not namespace:
                    continue

                if namespace in existing_namespaces:
                    continue

                taxonomies.append({
                    "version": data.get("version"),
                    "description": data.get("description"),
                    "expanded": data.get("expanded"),
                    "exclusive": data.get("exclusive", False),
                    "namespace": namespace,
                    "uuid": data.get("uuid")
                })

            except Exception as e:
                print(f"[ERROR] Failed to load taxonomy {json_file}: {e}")

    # 🔍 Recherche
    search_term = args.get("search", "").lower()
    if search_term:
        taxonomies = [
            t for t in taxonomies
            if search_term in (t["description"] or "").lower()
            or search_term in (t["expanded"] or "").lower()
            or search_term in (t["namespace"] or "").lower()
        ]

    # 📄 Pagination
    page = int(args.get("page", 1))
    per_page = 20
    total = len(taxonomies)
    total_pages = math.ceil(total / per_page)
    start = (page - 1) * per_page
    end = start + per_page

    return {
        "items": taxonomies[start:end],
        "page": page,
        "pages": total_pages,
        "total": total
    }


def add_tags_from_misp_taxonomy(uuid_from_misp, created_by):
    if not uuid_from_misp:
        return None , "Missing UUID"

    taxonomy_path = None
    base_path = Path(MISP_TAXONOMIES_PATH)


    for taxonomy_dir in base_path.iterdir():
        if not taxonomy_dir.is_dir():
            continue

        for json_file in taxonomy_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("uuid") ==  uuid_from_misp:
                    taxonomy_path = json_file
                    break
            except Exception as e:
                print(f"[ERROR] {json_file}: {e}")
        if taxonomy_path:
            break

    if not taxonomy_path:
        return None, "Taxonomy not found"

    with open(taxonomy_path, "r", encoding="utf-8") as f:
        taxonomy_data = json.load(f)

    namespace = taxonomy_data.get("namespace", "unknown")
    tags_added = 0

    # if already in the db we dont want to add it again
    existing_namespaces = get_all_taxonomies_in_db()
    if namespace in existing_namespaces:
        return True , "Tags already in DB"

    # ==========================================================
    # 🟢 CAS 1 : values → predicate → entry (CERT-XLM)
    # ==========================================================
    if "values" in taxonomy_data:
        for block in taxonomy_data.get("values", []):
            predicate = block.get("predicate")
            if not predicate:
                continue

            for entry in block.get("entry", []):
                value = entry.get("value")
                if not value:
                    continue

                tag_name = f'{namespace}:{predicate}="{value}"'
                description = (
                    entry.get("description")
                    or entry.get("expanded")
                )
                color = entry.get("colour") or "#FFFFFF"

                if Tag.query.filter_by(name=tag_name).first():
                    continue

                db.session.add(Tag(
                    name=tag_name,
                    description=description,
                    color=color,
                    icon="fa-tag",
                    uuid=str(uuid.uuid4()),
                    created_by=created_by.id,
                    is_active=True,
                    is_approved_by_admin=True,
                    visibility="public",
                    created_at=datetime.datetime.now(datetime.timezone.utc),
                    updated_at=datetime.datetime.now(datetime.timezone.utc),
                    external_id=entry.get("uuid"),
                ))
                tags_added += 1

    # ==========================================================
    # 🟢 CAS 2 & 3 : predicates simples (PAP, TLP, etc.)
    # ==========================================================
    elif "predicates" in taxonomy_data:
        for pred in taxonomy_data.get("predicates", []):
            value = pred.get("value")
            if not value:
                continue

            tag_name = f"{namespace}:{value}"
            description = (
                pred.get("description")
                or pred.get("expanded")
            )
            color = pred.get("colour") or "#FFFFFF"

            if Tag.query.filter_by(name=tag_name).first():
                continue

            db.session.add(Tag(
                name=tag_name,
                description=description,
                color=color,
                icon="fa-tag",
                uuid=str(uuid.uuid4()),
                external_id=pred.get("uuid"),
                created_by=created_by.id,
                is_active=True,
                is_approved_by_admin=True,
                visibility="public",
                created_at=datetime.datetime.now(datetime.timezone.utc),
                updated_at=datetime.datetime.now(datetime.timezone.utc),
            ))
            tags_added += 1

    if tags_added:
        db.session.commit()
        return True, f"Added {tags_added} tags."

    return None , "No tags were added."

def get_all_taxonomies_in_db():
    """
    Return a list of taxonomy namespaces already present in DB (unique).
    Example tag:
        tlp:green
        CERT-XLM:intrusion-attempts="login-attempts"

    ➜ returns: ["tlp", "CERT-XLM"]
    """
    namespaces = set()

    for tag in Tag.query.filter_by(is_active=True).all():
        if ":" in tag.name:
            namespaces.add(tag.name.split(":", 1)[0])

    return namespaces
