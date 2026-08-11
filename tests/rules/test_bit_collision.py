"""
Integration tests for corpus-wide Suricata flowbit/xbit/hostbit
collision detection (app/features/rule/rule_core.py:
check_bit_collision_risk(), reusing corpus_resource_collision_risk();
extraction in
app/features/rule/rule_format/available_format/suricata_format.py:
extract_bit_entries()).

Internal ref A2 (corpus part): same shape as the ref A1 dataset-filename
check, generalized to flowbit/xbit/hostbit names — a shared bit name
across independently authored rules can be read or overwritten
cross-source, and this can't be detected by looking at one rule alone.
'isset'/'isnotset' are reads; 'set'/'unset'/'toggle' are writes. A new
write colliding with an existing read or write on the same bit name is
rejected; a new read colliding with an existing entry is only a
warning.
"""
from __future__ import annotations

API_KEY_USER = "user_api_key"


def _create(client, title, to_string):
    data = {
        "title": title,
        "format": "suricata",
        "version": "1.0",
        "license": "MIT",
        "to_string": to_string,
    }
    return client.post("/api/rule/private/create", json=data, headers={"X-API-KEY": API_KEY_USER})


def test_a2_read_read_overlap_warns(client):
    """Two rules both checking (reading) the same bit name both succeed, with a warning on the second."""
    first = _create(
        client, "A2 corpus first reader",
        'alert tcp any any -> any any (msg:"a2c t1"; flowbits:isset,a2c_shared; sid:900201; rev:1;)',
    )
    assert first.status_code == 200

    second = _create(
        client, "A2 corpus second reader",
        'alert tcp any any -> any any (msg:"a2c t2"; flowbits:isset,a2c_shared; sid:900202; rev:1;)',
    )
    assert second.status_code == 200
    message = second.get_json()["message"]
    assert "warning" in message.lower()
    assert "flowbits:a2c_shared" in message


def test_a2_write_over_read_is_rejected(client):
    """A rule setting (writing) a bit another rule already reads is rejected outright."""
    reader = _create(
        client, "A2 corpus reader for write-over-read",
        'alert tcp any any -> any any (msg:"a2c t3"; flowbits:isset,a2c_writeover; sid:900203; rev:1;)',
    )
    assert reader.status_code == 200

    writer = _create(
        client, "A2 corpus writer over read",
        'alert tcp any any -> any any (msg:"a2c t4"; flowbits:set,a2c_writeover; sid:900204; rev:1;)',
    )
    assert writer.status_code == 400
    json_data = writer.get_json()
    assert "flowbits:a2c_writeover" in json_data["message"]


def test_a2_unrelated_bit_names_are_unaffected(client):
    """Rules referencing distinct bit names (or none at all) are unaffected (regression check)."""
    first = _create(
        client, "A2 corpus unrelated one",
        'alert tcp any any -> any any (msg:"a2c t5"; flowbits:isset,a2c_alpha; sid:900205; rev:1;)',
    )
    assert first.status_code == 200

    second = _create(
        client, "A2 corpus unrelated two",
        'alert tcp any any -> any any (msg:"a2c t6"; flowbits:set,a2c_beta; sid:900206; rev:1;)',
    )
    assert second.status_code == 200
    assert "warning" not in second.get_json()["message"].lower()

    third = _create(
        client, "A2 corpus no bits at all",
        'alert tcp any any -> any any (msg:"a2c t7"; content:"x"; sid:900207; rev:1;)',
    )
    assert third.status_code == 200
    assert "warning" not in third.get_json()["message"].lower()


def test_a2_same_name_different_bit_type_is_unaffected(client):
    """A flowbit and a hostbit sharing the same bit name are distinct resources — no collision."""
    first = _create(
        client, "A2 corpus flowbit namer",
        'alert tcp any any -> any any (msg:"a2c t8"; flowbits:set,a2c_shared_name; sid:900208; rev:1;)',
    )
    assert first.status_code == 200

    second = _create(
        client, "A2 corpus hostbit namer",
        'alert tcp any any -> any any (msg:"a2c t9"; hostbits:set,a2c_shared_name; sid:900209; rev:1;)',
    )
    assert second.status_code == 200
    assert "warning" not in second.get_json()["message"].lower()
