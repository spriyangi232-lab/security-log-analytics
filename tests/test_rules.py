from sla import config, mitre, rules


def test_config_uses_rules_single_source():
    c = config.DEFAULT
    assert c.w_volume == rules.RISK_WEIGHTS["volume"] and c.tier_high == rules.RISK_TIERS["high_from"]


def test_mitre_shim_reexports():
    assert mitre.RULES is rules.RULES and mitre.ITIL_PRIORITY is rules.ITIL_PRIORITY


def test_risk_weights_sum_to_one():
    assert abs(sum(rules.RISK_WEIGHTS.values()) - 1) < 1e-9
