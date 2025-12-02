import pytest
from sigma_scheduler.app.sigma_rule_fetcher import fetch_sigma_rules_from_url

VALID_SIGMA_URL = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/win_security_log_clear.yml"

def test_fetch_sigma_rules_valid_url():
    rules = fetch_sigma_rules_from_url(VALID_SIGMA_URL)
    assert rules is not None
    assert isinstance(rules, list) or isinstance(rules, dict)
    assert len(rules) > 0

def test_fetch_sigma_rules_invalid_url():
    invalid_url = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/doesnotexist.yml"
    with pytest.raises(Exception):
        fetch_sigma_rules_from_url(invalid_url)

def test_fetch_sigma_rules_empty_url():
    with pytest.raises(ValueError):
        fetch_sigma_rules_from_url("")
