"""Tests for GET /rule/data_table — the generic endpoint consumed by the
rule-data-table component (page / per_page / search / sort / dir / source)."""


def test_data_table_returns_shape(client):
    res = client.get('/rule/data_table')
    assert res.status_code == 200
    data = res.get_json()
    assert {'items', 'total', 'total_pages'} <= set(data.keys())
    assert isinstance(data['items'], list)
    assert data['total'] >= 1


def test_data_table_item_fields(client):
    data = client.get('/rule/data_table').get_json()
    item = data['items'][0]
    for field in ('id', 'title', 'format', 'author', 'description',
                  'creation_date', 'vote_up', 'vote_down', 'to_string'):
        assert field in item


def test_data_table_per_page(client):
    data = client.get('/rule/data_table?per_page=1&page=1').get_json()
    assert len(data['items']) == 1
    assert data['total_pages'] == data['total']


def test_data_table_per_page_capped_at_100(client):
    res = client.get('/rule/data_table?per_page=99999')
    assert res.status_code == 200


def test_data_table_search_by_title(client):
    all_ = client.get('/rule/data_table?per_page=100').get_json()
    title = all_['items'][0]['title']
    data = client.get(f'/rule/data_table?search={title}').get_json()
    assert data['total'] >= 1
    assert any(r['title'] == title for r in data['items'])


def test_data_table_search_no_match(client):
    data = client.get('/rule/data_table?search=zzz-no-such-rule-zzz').get_json()
    assert data['total'] == 0
    assert data['items'] == []


def test_data_table_sort_title(client):
    asc  = client.get('/rule/data_table?sort=title&dir=asc&per_page=100').get_json()
    desc = client.get('/rule/data_table?sort=title&dir=desc&per_page=100').get_json()
    titles_asc  = [r['title'] for r in asc['items']]
    titles_desc = [r['title'] for r in desc['items']]
    assert titles_desc == titles_asc[::-1]


def test_data_table_invalid_sort_key_is_ignored(client):
    res = client.get('/rule/data_table?sort=evil_column&dir=asc')
    assert res.status_code == 200


def test_data_table_source_filter_no_match(client):
    data = client.get(
        '/rule/data_table?source=https://github.com/nobody/no-such-repo'
    ).get_json()
    assert data['total'] == 0


def test_data_table_includes_tags_and_cves(client):
    item = client.get('/rule/data_table').get_json()['items'][0]
    assert isinstance(item.get('tags'), list)
    assert isinstance(item.get('cves'), list)


def test_data_table_rule_type_filter(client):
    all_ = client.get('/rule/data_table?per_page=100').get_json()
    fmt = all_['items'][0]['format']
    data = client.get(f'/rule/data_table?rule_type={fmt}').get_json()
    assert data['total'] >= 1
    assert all(fmt.lower() in (r['format'] or '').lower() for r in data['items'])


def test_data_table_unknown_tag_filter_matches_nothing(client):
    data = client.get('/rule/data_table?tags=no-such-tag-xyz').get_json()
    assert data['total'] == 0


def test_github_source_stats_requires_url(client):
    assert client.get('/rule/github_source_stats').status_code == 400


def test_github_source_stats_shape(client):
    data = client.get(
        '/rule/github_source_stats?url=https://github.com/x/y'
    ).get_json()
    assert {'total_rules', 'formats', 'authors_count',
            'licenses_count', 'last_update'} <= set(data.keys())


def test_export_download_by_ids(client):
    item = client.get('/rule/data_table').get_json()['items'][0]
    res = client.get(f"/rule/export/download?ids={item['id']}&export_format=json_each")
    assert res.status_code == 200
    assert res.data[:2] == b'PK'  # zip magic bytes


def test_data_table_has_ai_analysis_filter(app, client):
    """The "Rulezy's picks" toggle on RuleList — rules with a real
    AIGeneration(agent_key='rule_analysis', rule_id=...) row match, a rule
    with no analysis at all is excluded."""
    import uuid as uuid_mod
    from app import db
    from app.core.db_class.db import AIGeneration, Rule, User

    with app.app_context():
        rule = Rule.query.first()
        user_id = User.query.first().id
        db.session.add(AIGeneration(
            uuid=str(uuid_mod.uuid4()), agent_key='rule_analysis', rule_id=rule.id,
            user_id=user_id, content='report', is_public=True,
        ))
        db.session.commit()
        analyzed_id = rule.id

    unfiltered = client.get('/rule/data_table?per_page=100').get_json()
    filtered = client.get('/rule/data_table?has_ai_analysis=true&per_page=100').get_json()

    assert filtered['total'] <= unfiltered['total']
    assert any(r['id'] == analyzed_id for r in filtered['items'])
    # A rule_fixer/rule_generator AIGeneration row (rule_id always null for
    # those) must never make an unrelated rule match this filter.
    with app.app_context():
        db.session.add(AIGeneration(
            uuid=str(uuid_mod.uuid4()), agent_key='rule_fixer', rule_id=None,
            user_id=user_id, content='x', is_public=True,
        ))
        db.session.commit()
    refiltered = client.get('/rule/data_table?has_ai_analysis=true&per_page=100').get_json()
    assert refiltered['total'] == filtered['total']
