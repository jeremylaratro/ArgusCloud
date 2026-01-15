import json
from pathlib import Path

from awshound.graph import Node, Edge
from awshound import rules


def test_rule_public_s3():
    policy_doc = json.loads(Path("tests/fixtures/sample_s3_policy.json").read_text())
    policy_node = Node(id="arn:aws:s3:::public-bucket:policy", type="ResourcePolicy", properties={"document": policy_doc})
    edges = []
    result_edges = rules.evaluate_rules([policy_node], edges)
    assert any(e.properties.get("rule") == "public-s3" for e in result_edges)


def test_rule_open_sg():
    sg_node = Node(
        id="sg-123",
        type="SecurityGroup",
        properties={"ingress": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
    )
    result_edges = rules.evaluate_rules([sg_node], [])
    assert any(e.properties.get("rule") == "open-sg" for e in result_edges)


def test_rule_missing_guardduty():
    acct = Node(id="account:123456789012", type="Account", properties={})
    result_edges = rules.evaluate_rules([acct], [])
    assert any(e.properties.get("rule") == "guardduty-missing" for e in result_edges)


def test_rule_assume_role_chain():
    # principal user -> role1 -> admin role2
    edges = [
        Edge(src="arn:aws:iam::123:role/role1", dst="arn:aws:iam::123:user/alice", type="Trusts", properties={}),
        Edge(src="arn:aws:iam::123:role/admin", dst="arn:aws:iam::123:role/role1", type="Trusts", properties={}),
    ]
    nodes = [
        Node(id="arn:aws:iam::123:user/alice", type="User", properties={}),
        Node(id="arn:aws:iam::123:role/role1", type="Role", properties={"is_admin": False}),
        Node(id="arn:aws:iam::123:role/admin", type="Role", properties={"is_admin": True}),
    ]
    result_edges = rules.evaluate_rules(nodes, edges)
    assert any(e.properties.get("rule") == "assume-role-chain" for e in result_edges)


def test_rule_codebuild_secret_exfil():
    proj = Node(
        id="cb:proj",
        type="CodeBuildProject",
        properties={"environment_vars": [{"name": "SECRET", "value": "x"}], "environment_privileged": True},
    )
    result_edges = rules.evaluate_rules([proj], [])
    assert any(e.properties.get("rule") == "codebuild-env-secrets" for e in result_edges)
    assert any(e.properties.get("rule") == "codebuild-privileged" for e in result_edges)


def test_rule_kms_external_access():
    pol_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }
        ]
    }
    pol_node = Node(id="arn:aws:kms:region:acct:key/123:policy", type="ResourcePolicy", properties={"document": pol_doc})
    result_edges = rules.evaluate_rules([pol_node], [])
    assert any(e.properties.get("rule") == "kms-cross-account" for e in result_edges)


def test_rule_public_snapshot_ami():
    snap = Node(id="snap-1", type="Snapshot", properties={"state": "completed", "encrypted": False})
    ami = Node(id="ami-1", type="AMI", properties={"public": True})
    result_edges = rules.evaluate_rules([snap, ami], [])
    assert any(e.properties.get("rule") == "snapshot-exfil" for e in result_edges)
    assert any(e.properties.get("rule") == "ami-public" for e in result_edges)


def test_rule_ecr_cross_account():
    pol_doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]}
    pol_node = Node(id="arn:aws:ecr:region:acct:repository/repo:policy", type="ResourcePolicy", properties={"document": pol_doc})
    result_edges = rules.evaluate_rules([pol_node], [])
    assert any(e.properties.get("rule") == "ecr-cross-account" for e in result_edges)
