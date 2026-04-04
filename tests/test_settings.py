import os

from app.runtime.settings import env_bool, env_int, env_csv_set


def test_env_bool_uses_default_when_missing(monkeypatch):
    monkeypatch.delenv("FLAG_MISSING", raising=False)
    assert env_bool("FLAG_MISSING", default=True) is True


def test_env_bool_parses_truthy_and_falsy(monkeypatch):
    monkeypatch.setenv("FLAG", "true")
    assert env_bool("FLAG") is True
    monkeypatch.setenv("FLAG", "off")
    assert env_bool("FLAG") is False


def test_env_int_respects_min_value(monkeypatch):
    monkeypatch.setenv("VALUE", "0")
    assert env_int("VALUE", default=5, min_value=1) == 5


def test_env_int_parses_valid_integer(monkeypatch):
    monkeypatch.setenv("VALUE", "7")
    assert env_int("VALUE", default=5, min_value=1) == 7


def test_env_csv_set_trims_and_deduplicates(monkeypatch):
    monkeypatch.setenv("ORIGINS", " http://a, http://b/ ,http://a ")
    values = env_csv_set("ORIGINS")
    assert values == {"http://a", "http://b"}
