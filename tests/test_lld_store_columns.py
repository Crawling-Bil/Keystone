"""The LLD store writes column names into UPDATE statements, so it checks them itself (not only the routes in front of it)."""
from __future__ import annotations

import pytest

from features.lld_generator import store


@pytest.fixture()
def template(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "nes.db"))
    store.init_db()
    return store.create_template("Master", "master.docx", "Penutup", [1, 2], 4, "Gambar", "Tabel")


def test_a_real_column_is_updated(template):
    updated = store.update_template(template["id"], name="Renamed")
    assert updated["name"] == "Renamed"


def test_a_key_that_is_not_a_column_is_refused_and_nothing_changes(template):
    with pytest.raises(ValueError, match="Not a column"):
        store.update_template(template["id"], not_a_column="x")
    assert store.get_template(template["id"])["name"] == "Master"


def test_a_key_that_carries_sql_is_refused_and_nothing_changes(template):
    with pytest.raises(ValueError):
        store.update_template(template["id"], **{"name = 'pwned', filename": "x"})
    row = store.get_template(template["id"])
    assert row["name"] == "Master" and row["filename"] == "master.docx"


def test_every_updater_checks_its_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "nes.db"))
    store.init_db()
    with pytest.raises(ValueError):
        store.update_project(1, **{"id = id, name": "x"})
    with pytest.raises(ValueError):
        store.update_chapter(1, **{"id = id, title": "x"})
