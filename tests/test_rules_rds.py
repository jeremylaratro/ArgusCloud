from awshound.graph import Node
from awshound import rules


def test_rule_rds_public_snapshot():
    snap = Node(id="rds:snap1", type="RDSSnapshot", properties={"public": True})
    edges = rules.evaluate_rules([snap], [])
    assert any(e.properties.get("rule") == "rds-public-snapshot" for e in edges)
