from awshound import normalize


def test_normalize_dedup_and_edges():
    raw = {
        "iam-roles": [
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/test",
                    "RoleName": "test",
                    "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
                },
                "AttachedPolicies": [],
                "InlinePolicies": [],
            },
            {
                # duplicate role should be deduped
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/test",
                    "RoleName": "test",
                    "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
                },
                "AttachedPolicies": [],
                "InlinePolicies": [],
            },
        ],
        "s3": [
            {
                "Bucket": {"Name": "example-bucket", "CreationDate": "now"},
                "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]},
            }
        ],
        "vpc": [
            {
                "Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
                "Subnets": [
                    {"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "az-1"}
                ],
                "SecurityGroups": [
                    {
                        "GroupId": "sg-1",
                        "GroupName": "web",
                        "VpcId": "vpc-1",
                        "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                        "IpPermissionsEgress": [],
                    }
                ],
                "RouteTables": [],
                "VpcEndpoints": [],
            }
        ],
        "iam-users": [
            {
                "User": {"Arn": "arn:aws:iam::123456789012:user/bob", "UserName": "bob"},
                "Groups": [],
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ],
    }
    nodes, edges = normalize.normalize(raw)
    # Deduped role count should be 1
    role_nodes = [n for n in nodes if n.type == "Role"]
    assert len(role_nodes) == 1
    # Trust edge to wildcard exists
    assert any(e.type == "Trusts" and e.dst == "*" for e in edges)
    # S3 bucket node exists
    assert any(n.type == "S3Bucket" and n.properties["name"] == "example-bucket" for n in nodes)
    # SG open to internet recorded
    assert any(n.id == "sg-1" for n in nodes)
