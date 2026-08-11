"""
Integration tests for corpus-wide Suricata dataset filename collision
detection (app/features/rule/rule_core.py: check_dataset_collision_risk(),
corpus_resource_collision_risk(); extraction in
app/features/rule/rule_format/available_format/suricata_format.py:
extract_dataset_entries()).

Internal ref A1: a rule using dataset:...,save|state on a filename
another source already uses can wipe or replace that source's IOC list,
and this can't be detected by looking at one rule alone — it needs a
corpus-wide check at submission time. 'load' is a read; 'save'/'state'
are writes. A new write colliding with any existing read or write on the
same filename is rejected; a new read colliding with an existing read or
write is only a warning.
"""
from __future__ import annotations

import re

from app.features.rule.rule_format.available_format.suricata_format import extract_dataset_entries

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


def test_a1_read_read_overlap_warns(client):
    """Two rules both loading (reading) the same dataset filename both succeed, with a warning on the second."""
    first = _create(
        client, "A1 first reader",
        'alert tcp any any -> any any (msg:"a1 t1"; dataset:isset,d1,type string,load a1_shared.lst; sid:900101; rev:1;)',
    )
    assert first.status_code == 200

    second = _create(
        client, "A1 second reader",
        'alert tcp any any -> any any (msg:"a1 t2"; dataset:isset,d2,type string,load a1_shared.lst; sid:900102; rev:1;)',
    )
    assert second.status_code == 200
    message = second.get_json()["message"]
    assert "warning" in message.lower()
    assert "a1_shared.lst" in message


def test_a1_write_over_read_is_rejected(client):
    """A rule saving/writing to a filename another rule already reads is rejected outright."""
    reader = _create(
        client, "A1 reader for write-over-read",
        'alert tcp any any -> any any (msg:"a1 t3"; dataset:isset,d3,type string,load a1_writeover.lst; sid:900103; rev:1;)',
    )
    assert reader.status_code == 200

    writer = _create(
        client, "A1 writer over read",
        'alert tcp any any -> any any (msg:"a1 t4"; dataset:set,d3,type string,save a1_writeover.lst; sid:900104; rev:1;)',
    )
    assert writer.status_code == 400
    json_data = writer.get_json()
    assert "a1_writeover.lst" in json_data["message"]


def test_a1_write_over_write_is_rejected(client):
    """A second rule writing to a filename another rule already writes to is rejected too."""
    first_writer = _create(
        client, "A1 first writer",
        'alert tcp any any -> any any (msg:"a1 t5"; dataset:set,d5,type string,save a1_doublewrite.lst; sid:900105; rev:1;)',
    )
    assert first_writer.status_code == 200

    second_writer = _create(
        client, "A1 second writer",
        'alert tcp any any -> any any (msg:"a1 t6"; dataset:set,d6,type string,state a1_doublewrite.lst; sid:900106; rev:1;)',
    )
    assert second_writer.status_code == 400
    json_data = second_writer.get_json()
    assert "a1_doublewrite.lst" in json_data["message"]


def test_a1_dataset_option_with_both_load_and_save_extracts_both():
    """A single dataset option combining 'load X,save Y' must yield both entries, not just the first (regression check)."""
    rule = (
        'alert http any any -> any any (msg:"a1 poison"; http.user_agent; content:"benign-ua"; '
        'dataset:isset,parasite_poison,type string,load parasite.lst,save ioc.lst; sid:900110; rev:1;)'
    )
    entries = extract_dataset_entries(rule)
    assert ('parasite.lst', 'read') in entries
    assert ('ioc.lst', 'write') in entries
    assert len(entries) == 2


def test_a1_unrelated_filenames_are_unaffected(client):
    """Rules referencing distinct dataset filenames are unaffected by the collision check (regression check)."""
    first = _create(
        client, "A1 unrelated one",
        'alert tcp any any -> any any (msg:"a1 t7"; dataset:isset,d7,type string,load a1_alpha.lst; sid:900107; rev:1;)',
    )
    assert first.status_code == 200

    second = _create(
        client, "A1 unrelated two",
        'alert tcp any any -> any any (msg:"a1 t8"; dataset:set,d8,type string,save a1_beta.lst; sid:900108; rev:1;)',
    )
    assert second.status_code == 200
    assert "warning" not in second.get_json()["message"].lower()

    third = _create(
        client, "A1 no dataset at all",
        'alert tcp any any -> any any (msg:"a1 t9"; content:"x"; sid:900109; rev:1;)',
    )
    assert third.status_code == 200
    assert "warning" not in third.get_json()["message"].lower()
