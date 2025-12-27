#!/usr/bin/env python3
"""
AWS Account Enumeration Tool
Comprehensive enumeration of AWS resources with modular design
"""

import boto3
import json
import sys
import os
import argparse
import getpass
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from typing import Dict, List, Any, Optional

class AWSEnumerator:
    # Valid AWS regions
    VALID_REGIONS = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
        'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
        'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'sa-east-1',
        'af-south-1', 'ap-east-1', 'ap-southeast-3', 'eu-south-1',
        'me-south-1', 'us-gov-east-1', 'us-gov-west-1'
    ]
    
    # Services that are global (not region-specific)
    GLOBAL_SERVICES = ['iam', 'route53', 's3']
    
    def __init__(self, access_key: str, secret_key: str, session_token: Optional[str] = None, 
                 region: str = 'us-east-1', all_regions: bool = False, regions: Optional[List[str]] = None):
        """Initialize AWS session with provided credentials"""
        # Validate inputs
        if not self._validate_credentials(access_key, secret_key):
            raise ValueError("Invalid credential format")
        
        # Handle region configuration
        self.all_regions = all_regions
        if all_regions:
            self.regions = regions if regions else self.get_enabled_regions(access_key, secret_key, session_token)
            print(f"[*] Multi-region mode: Will enumerate {len(self.regions)} regions")
        else:
            self.regions = [region]
            if region not in self.VALID_REGIONS:
                print(f"[!] Warning: '{region}' may not be a valid region")
        
        # Store credentials for multi-region sessions
        self.access_key = access_key.strip()
        self.secret_key = secret_key.strip()
        self.session_token = session_token.strip() if session_token else None
        
        try:
            # Create primary session
            self.session = boto3.Session(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                aws_session_token=self.session_token,
                region_name=self.regions[0]
            )
            self.region = self.regions[0]
            
            # Test credentials immediately
            self._test_credentials()
            
        except (NoCredentialsError, ClientError) as e:
            raise ValueError(f"Failed to initialize AWS session: {str(e)}")
        
        self.results = {
            'timestamp': datetime.utcnow().isoformat(),
            'regions_enumerated': self.regions,
            'multi_region': all_regions,
            'account': {},
            'global_services': {},
            'regional_services': {}
        }
    
    def get_enabled_regions(self, access_key: str, secret_key: str, session_token: Optional[str]) -> List[str]:
        """Get all enabled regions for the account"""
        try:
            temp_session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name='us-east-1'
            )
            ec2 = temp_session.client('ec2', region_name='us-east-1')
            response = ec2.describe_regions(AllRegions=False)  # Only enabled regions
            regions = [r['RegionName'] for r in response['Regions']]
            print(f"[+] Found {len(regions)} enabled regions")
            return regions
        except Exception as e:
            print(f"[!] Could not fetch enabled regions, using default list: {e}")
            return self.VALID_REGIONS[:8]  # Return subset of common regions
    
    def get_session_for_region(self, region: str) -> boto3.Session:
        """Create a session for a specific region"""
        return boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_session_token=self.session_token,
            region_name=region
        )
    
    def _validate_credentials(self, access_key: str, secret_key: str) -> bool:
        """Validate credential format"""
        # AWS Access Key format: AKIA[0-9A-Z]{16} or ASIA[0-9A-Z]{16} (temp creds)
        access_key_pattern = r'^(AKIA|ASIA)[0-9A-Z]{16}$'
        # Secret key is 40 characters
        secret_key_pattern = r'^[A-Za-z0-9/+=]{40}$'
        
        if not access_key or not secret_key:
            return False
        
        if not re.match(access_key_pattern, access_key.strip()):
            print(f"[!] Warning: Access key doesn't match standard AWS format")
            return True  # Continue anyway, format might vary
        
        if len(secret_key.strip()) != 40:
            print(f"[!] Warning: Secret key length is {len(secret_key.strip())}, expected 40")
        
        return True
    
    def _test_credentials(self):
        """Test if credentials are valid by making a simple API call"""
        try:
            sts = self.session.client('sts')
            sts.get_caller_identity()
            print("[+] Credentials validated successfully")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidClientTokenId':
                raise ValueError("Invalid Access Key ID")
            elif error_code == 'SignatureDoesNotMatch':
                raise ValueError("Invalid Secret Access Key")
            elif error_code == 'ExpiredToken':
                raise ValueError("Session token has expired")
            else:
                raise ValueError(f"Credential validation failed: {error_code}")
        except EndpointConnectionError:
            raise ValueError("Cannot connect to AWS - check network connection")

    def safe_call(self, func, *args, **kwargs) -> Any:
        """Wrapper for safe API calls with error handling"""
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            return {'error': str(e)}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}

    def enumerate_iam(self) -> Dict:
        """Enumerate IAM users, roles, groups, and policies"""
        iam = self.session.client('iam')
        data = {}
        
        # Users
        users = self.safe_call(iam.list_users)
        if 'Users' in users:
            data['users'] = [{
                'username': u['UserName'],
                'user_id': u['UserId'],
                'arn': u['Arn'],
                'created': u['CreateDate'].isoformat()
            } for u in users['Users']]
            
            # Get policies for each user
            for user in data['users']:
                policies = self.safe_call(iam.list_attached_user_policies, UserName=user['username'])
                if 'AttachedPolicies' in policies:
                    user['attached_policies'] = [p['PolicyName'] for p in policies['AttachedPolicies']]
        
        # Roles
        roles = self.safe_call(iam.list_roles)
        if 'Roles' in roles:
            data['roles'] = [{
                'name': r['RoleName'],
                'arn': r['Arn'],
                'created': r['CreateDate'].isoformat()
            } for r in roles['Roles']]
        
        # Groups
        groups = self.safe_call(iam.list_groups)
        if 'Groups' in groups:
            data['groups'] = [g['GroupName'] for g in groups['Groups']]
        
        # Policies
        policies = self.safe_call(iam.list_policies, Scope='Local')
        if 'Policies' in policies:
            data['custom_policies'] = [{
                'name': p['PolicyName'],
                'arn': p['Arn']
            } for p in policies['Policies']]
        
        return data

    def enumerate_ec2(self, session: boto3.Session = None) -> Dict:
        """Enumerate EC2 instances, security groups, and network resources"""
        if session is None:
            session = self.session
        ec2 = session.client('ec2')
        data = {}
        
        # Instances
        instances = self.safe_call(ec2.describe_instances)
        if 'Reservations' in instances:
            data['instances'] = []
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    data['instances'].append({
                        'instance_id': instance['InstanceId'],
                        'type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'vpc_id': instance.get('VpcId'),
                        'subnet_id': instance.get('SubnetId')
                    })
        
        # Security Groups
        sgs = self.safe_call(ec2.describe_security_groups)
        if 'SecurityGroups' in sgs:
            data['security_groups'] = [{
                'id': sg['GroupId'],
                'name': sg['GroupName'],
                'vpc_id': sg.get('VpcId'),
                'ingress_rules': len(sg.get('IpPermissions', [])),
                'egress_rules': len(sg.get('IpPermissionsEgress', []))
            } for sg in sgs['SecurityGroups']]
        
        # VPCs
        vpcs = self.safe_call(ec2.describe_vpcs)
        if 'Vpcs' in vpcs:
            data['vpcs'] = [{
                'vpc_id': vpc['VpcId'],
                'cidr': vpc['CidrBlock'],
                'is_default': vpc['IsDefault']
            } for vpc in vpcs['Vpcs']]
        
        # Key Pairs
        keys = self.safe_call(ec2.describe_key_pairs)
        if 'KeyPairs' in keys:
            data['key_pairs'] = [k['KeyName'] for k in keys['KeyPairs']]
        
        return data

    def enumerate_s3(self) -> Dict:
        """Enumerate S3 buckets and their configurations"""
        s3 = self.session.client('s3')
        data = {}
        
        buckets = self.safe_call(s3.list_buckets)
        if 'Buckets' in buckets:
            data['buckets'] = []
            for bucket in buckets['Buckets']:
                bucket_info = {
                    'name': bucket['Name'],
                    'created': bucket['CreationDate'].isoformat()
                }
                
                # Check public access
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                    bucket_info['public'] = any(
                        g.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' 
                        for g in acl.get('Grants', [])
                    )
                except:
                    bucket_info['public'] = 'error_checking'
                
                # Check encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
                    bucket_info['encrypted'] = True
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        bucket_info['encrypted'] = False
                
                data['buckets'].append(bucket_info)
        
        return data

    def enumerate_rds(self, session: boto3.Session = None) -> Dict:
        """Enumerate RDS instances and clusters"""
        if session is None:
            session = self.session
        rds = session.client('rds')
        data = {}
        
        # DB Instances
        instances = self.safe_call(rds.describe_db_instances)
        if 'DBInstances' in instances:
            data['db_instances'] = [{
                'identifier': db['DBInstanceIdentifier'],
                'engine': db['Engine'],
                'engine_version': db['EngineVersion'],
                'class': db['DBInstanceClass'],
                'status': db['DBInstanceStatus'],
                'publicly_accessible': db.get('PubliclyAccessible', False)
            } for db in instances['DBInstances']]
        
        # DB Snapshots
        snapshots = self.safe_call(rds.describe_db_snapshots)
        if 'DBSnapshots' in snapshots:
            data['snapshots'] = [{
                'id': s['DBSnapshotIdentifier'],
                'instance': s['DBInstanceIdentifier'],
                'created': s['SnapshotCreateTime'].isoformat()
            } for s in snapshots['DBSnapshots']]
        
        return data

    def enumerate_lambda(self, session: boto3.Session = None) -> Dict:
        """Enumerate Lambda functions"""
        if session is None:
            session = self.session
        lambda_client = session.client('lambda')
        data = {}
        
        functions = self.safe_call(lambda_client.list_functions)
        if 'Functions' in functions:
            data['functions'] = [{
                'name': f['FunctionName'],
                'runtime': f['Runtime'],
                'role': f['Role'],
                'last_modified': f['LastModified']
            } for f in functions['Functions']]
        
        return data

    def enumerate_cloudtrail(self, session: boto3.Session = None) -> Dict:
        """Enumerate CloudTrail trails"""
        if session is None:
            session = self.session
        ct = session.client('cloudtrail')
        data = {}
        
        trails = self.safe_call(ct.describe_trails)
        if 'trailList' in trails:
            data['trails'] = [{
                'name': t['Name'],
                'bucket': t.get('S3BucketName'),
                'is_logging': self.safe_call(ct.get_trail_status, Name=t['Name']).get('IsLogging', False)
            } for t in trails['trailList']]
        
        return data

    def enumerate_secrets_manager(self, session: boto3.Session = None) -> Dict:
        """Enumerate Secrets Manager secrets"""
        if session is None:
            session = self.session
        sm = session.client('secretsmanager')
        data = {}
        
        secrets = self.safe_call(sm.list_secrets)
        if 'SecretList' in secrets:
            data['secrets'] = [{
                'name': s['Name'],
                'arn': s['ARN'],
                'last_accessed': s.get('LastAccessedDate', 'Never').isoformat() if isinstance(s.get('LastAccessedDate'), datetime) else 'Never'
            } for s in secrets['SecretList']]
        
        return data

    def enumerate_kms(self, session: boto3.Session = None) -> Dict:
        """Enumerate KMS keys"""
        if session is None:
            session = self.session
        kms = session.client('kms')
        data = {}
        
        keys = self.safe_call(kms.list_keys)
        if 'Keys' in keys:
            data['keys'] = []
            for key in keys['Keys'][:50]:  # Limit to avoid rate limiting
                key_info = self.safe_call(kms.describe_key, KeyId=key['KeyId'])
                if 'KeyMetadata' in key_info:
                    metadata = key_info['KeyMetadata']
                    data['keys'].append({
                        'key_id': metadata['KeyId'],
                        'state': metadata['KeyState'],
                        'enabled': metadata['Enabled']
                    })
        
        return data

    def enumerate_route53(self) -> Dict:
        """Enumerate Route53 hosted zones and records"""
        route53 = self.session.client('route53')
        data = {}
        
        # List hosted zones
        zones = self.safe_call(route53.list_hosted_zones)
        if 'HostedZones' in zones:
            data['hosted_zones'] = []
            for zone in zones['HostedZones']:
                zone_info = {
                    'id': zone['Id'].split('/')[-1],
                    'name': zone['Name'],
                    'private': zone.get('Config', {}).get('PrivateZone', False),
                    'record_count': zone.get('ResourceRecordSetCount', 0)
                }
                
                # Get record sets for each zone
                zone_id = zone['Id'].split('/')[-1]
                records = self.safe_call(route53.list_resource_record_sets, HostedZoneId=zone_id)
                if 'ResourceRecordSets' in records:
                    zone_info['records'] = [{
                        'name': r['Name'],
                        'type': r['Type'],
                        'ttl': r.get('TTL', 'alias')
                    } for r in records['ResourceRecordSets'][:20]]  # Limit to first 20 records
                    
                    if len(records['ResourceRecordSets']) > 20:
                        zone_info['total_records'] = len(records['ResourceRecordSets'])
                
                data['hosted_zones'].append(zone_info)
        
        return data

    def get_account_info(self) -> Dict:
        """Get account-level information"""
        sts = self.session.client('sts')
        data = {}
        
        identity = self.safe_call(sts.get_caller_identity)
        if 'Account' in identity:
            data['account_id'] = identity['Account']
            data['user_arn'] = identity['Arn']
            data['user_id'] = identity['UserId']
        
        return data

    def enumerate_region(self, region: str) -> Dict:
        """Enumerate all regional services for a specific region"""
        print(f"[*] Enumerating region: {region}")
        session = self.get_session_for_region(region)
        
        # Regional services
        regional_tasks = {
            'ec2': lambda: self.enumerate_ec2(session),
            'rds': lambda: self.enumerate_rds(session),
            'lambda': lambda: self.enumerate_lambda(session),
            'cloudtrail': lambda: self.enumerate_cloudtrail(session),
            'secrets_manager': lambda: self.enumerate_secrets_manager(session),
            'kms': lambda: self.enumerate_kms(session)
        }
        
        region_results = {}
        
        # Execute regional tasks concurrently
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_service = {executor.submit(func): service for service, func in regional_tasks.items()}
            
            for future in as_completed(future_to_service):
                service = future_to_service[future]
                try:
                    region_results[service] = future.result()
                except Exception as e:
                    region_results[service] = {'error': str(e)}
        
        return region_results
    
    def enumerate_all(self) -> Dict:
        """Enumerate all services - handles both single and multi-region modes"""
        print("[*] Starting AWS enumeration...")
        
        # Get account info first
        print("[*] Fetching account information...")
        self.results['account'] = self.get_account_info()
        
        # Enumerate global services (only once)
        print("[*] Enumerating global services...")
        global_tasks = {
            'iam': self.enumerate_iam,
            'route53': self.enumerate_route53,
            's3': self.enumerate_s3
        }
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_service = {executor.submit(func): service for service, func in global_tasks.items()}
            
            for future in as_completed(future_to_service):
                service = future_to_service[future]
                print(f"[*] Enumerating {service.upper()}...")
                try:
                    self.results['global_services'][service] = future.result()
                except Exception as e:
                    self.results['global_services'][service] = {'error': str(e)}
        
        # Enumerate regional services
        if self.all_regions:
            print(f"\n[*] Starting multi-region enumeration across {len(self.regions)} regions...")
            for region in self.regions:
                try:
                    self.results['regional_services'][region] = self.enumerate_region(region)
                except Exception as e:
                    print(f"[!] Error enumerating region {region}: {e}")
                    self.results['regional_services'][region] = {'error': str(e)}
        else:
            # Single region mode
            print(f"\n[*] Enumerating regional services in {self.regions[0]}...")
            self.results['regional_services'][self.regions[0]] = self.enumerate_region(self.regions[0])
        
        print("\n[+] Enumeration complete!")
        return self.results

    def generate_report(self, output_file: str = None) -> str:
        """Generate formatted report"""
        report = []
        report.append("=" * 80)
        report.append("AWS ACCOUNT ENUMERATION REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {self.results['timestamp']}")
        report.append(f"Multi-Region Mode: {self.results['multi_region']}")
        report.append(f"Regions Enumerated: {', '.join(self.results['regions_enumerated'])}\n")
        
        # Account Info
        if 'account' in self.results:
            report.append("-" * 80)
            report.append("ACCOUNT INFORMATION")
            report.append("-" * 80)
            for key, value in self.results['account'].items():
                report.append(f"{key}: {value}")
            report.append("")
        
        # Global Services
        if 'global_services' in self.results and self.results['global_services']:
            report.append("=" * 80)
            report.append("GLOBAL SERVICES (not region-specific)")
            report.append("=" * 80)
            
            for service, data in self.results['global_services'].items():
                report.append("-" * 80)
                report.append(f"{service.upper()} ENUMERATION")
                report.append("-" * 80)
                
                if isinstance(data, dict) and 'error' in data:
                    report.append(f"Error: {data['error']}\n")
                    continue
                
                self._format_service_data(report, data)
                report.append("")
        
        # Regional Services
        if 'regional_services' in self.results:
            for region, services in self.results['regional_services'].items():
                report.append("=" * 80)
                report.append(f"REGION: {region.upper()}")
                report.append("=" * 80)
                
                if isinstance(services, dict) and 'error' in services:
                    report.append(f"Region Error: {services['error']}\n")
                    continue
                
                for service, data in services.items():
                    report.append("-" * 40)
                    report.append(f"{service.upper()}")
                    report.append("-" * 40)
                    
                    if isinstance(data, dict) and 'error' in data:
                        report.append(f"Error: {data['error']}\n")
                        continue
                    
                    self._format_service_data(report, data)
                    report.append("")
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            # Also save JSON
            json_file = output_file.replace('.txt', '.json')
            with open(json_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"[+] Report saved to {output_file}")
            print(f"[+] JSON data saved to {json_file}")
        
        return report_text
    
    def _format_service_data(self, report: List[str], data: Dict):
        """Helper method to format service data consistently"""
        for category, items in data.items():
            if isinstance(items, list):
                report.append(f"\n{category.replace('_', ' ').title()}: {len(items)} found")
                for item in items[:10]:  # Show first 10
                    report.append(f"  - {json.dumps(item, default=str)}")
                if len(items) > 10:
                    report.append(f"  ... and {len(items) - 10} more")
            else:
                report.append(f"{category}: {items}")


def get_credentials_from_env() -> Dict[str, Optional[str]]:
    """Get credentials from environment variables"""
    return {
        'access_key': os.environ.get('AWS_ACCESS_KEY_ID'),
        'secret_key': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'session_token': os.environ.get('AWS_SESSION_TOKEN'),
        'region': os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
    }


def get_credentials_interactive() -> Dict[str, Any]:
    """Get credentials interactively with secure input"""
    print("\n[*] Enter AWS Credentials")
    print("[*] (Press Ctrl+C to cancel)\n")
    
    try:
        access_key = input("Access Key ID: ").strip()
        if not access_key:
            print("[!] Access Key ID cannot be empty")
            sys.exit(1)
        
        # Use getpass for secret key to hide input
        secret_key = getpass.getpass("Secret Access Key: ").strip()
        if not secret_key:
            print("[!] Secret Access Key cannot be empty")
            sys.exit(1)
        
        session_token = getpass.getpass("Session Token (optional, press Enter to skip): ").strip()
        session_token = session_token if session_token else None
        
        # Multi-region option
        multi_region = input("Enumerate all regions? (y/N): ").strip().lower()
        all_regions = multi_region == 'y'
        
        regions_list = None
        if not all_regions:
            region = input("Region [us-east-1]: ").strip() or 'us-east-1'
        else:
            custom_regions = input("Specific regions (comma-separated) or Enter for all enabled: ").strip()
            if custom_regions:
                regions_list = [r.strip() for r in custom_regions.split(',')]
            region = 'us-east-1'  # Default for session creation
        
        return {
            'access_key': access_key,
            'secret_key': secret_key,
            'session_token': session_token,
            'region': region,
            'all_regions': all_regions,
            'regions': regions_list
        }
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(0)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='AWS Account Enumeration Tool - Comprehensive resource discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (single region)
  python3 aws_enum.py
  
  # Enumerate all enabled regions
  python3 aws_enum.py --all-regions
  
  # Enumerate specific regions
  python3 aws_enum.py --regions us-east-1,us-west-2,eu-west-1
  
  # Use environment variables with all regions
  export AWS_ACCESS_KEY_ID=AKIA...
  export AWS_SECRET_ACCESS_KEY=...
  python3 aws_enum.py --env --all-regions
  
  # Specify credentials via arguments (not recommended for production)
  python3 aws_enum.py --access-key AKIA... --secret-key ... --region us-west-2
  
  # Custom output file
  python3 aws_enum.py --output my_report.txt --all-regions
        """
    )
    
    parser.add_argument('--access-key', '-a', help='AWS Access Key ID')
    parser.add_argument('--secret-key', '-s', help='AWS Secret Access Key')
    parser.add_argument('--session-token', '-t', help='AWS Session Token (optional)')
    parser.add_argument('--region', '-r', default='us-east-1', 
                       help='AWS Region for single-region mode (default: us-east-1)')
    parser.add_argument('--all-regions', action='store_true', 
                       help='Enumerate all enabled regions (overrides --region)')
    parser.add_argument('--regions', help='Comma-separated list of specific regions to enumerate (e.g., us-east-1,eu-west-1)')
    parser.add_argument('--env', '-e', action='store_true', 
                       help='Use credentials from environment variables')
    parser.add_argument('--output', '-o', help='Output file path (default: auto-generated)')
    parser.add_argument('--json-only', action='store_true', 
                       help='Only output JSON, skip text report')
    
    return parser.parse_args()


def main():
    print("""
    ╔═══════════════════════════════════════╗
    ║   AWS Account Enumerator v2.0         ║
    ║   Comprehensive Resource Discovery    ║
    ╚═══════════════════════════════════════╝
    """)
    
    args = parse_arguments()
    
    # Determine credential source
    creds = None
    
    # Handle region configuration
    all_regions = args.all_regions
    regions_list = None
    
    if args.regions:
        regions_list = [r.strip() for r in args.regions.split(',')]
        all_regions = True  # Implies multi-region mode
        print(f"[*] Using specified regions: {', '.join(regions_list)}")
    
    if args.env:
        print("[*] Using credentials from environment variables...")
        creds = get_credentials_from_env()
        if not creds['access_key'] or not creds['secret_key']:
            print("[!] AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in environment")
            sys.exit(1)
        creds['all_regions'] = all_regions
        creds['regions'] = regions_list
    elif args.access_key and args.secret_key:
        print("[!] Warning: Passing credentials via command line arguments is insecure")
        print("[!] They may be visible in process lists and shell history")
        creds = {
            'access_key': args.access_key,
            'secret_key': args.secret_key,
            'session_token': args.session_token,
            'region': args.region,
            'all_regions': all_regions,
            'regions': regions_list
        }
    else:
        # Interactive mode
        creds = get_credentials_interactive()
        # Override if command line args specify all-regions
        if args.all_regions:
            creds['all_regions'] = True
    
    # Validate we have credentials
    if not creds or not creds.get('access_key') or not creds.get('secret_key'):
        print("[!] Missing required credentials")
        sys.exit(1)
    
    # Initialize and run enumeration
    try:
        print("\n[*] Initializing AWS session...")
        enumerator = AWSEnumerator(
            access_key=creds['access_key'],
            secret_key=creds['secret_key'],
            session_token=creds.get('session_token'),
            region=creds.get('region', 'us-east-1'),
            all_regions=creds.get('all_regions', False),
            regions=creds.get('regions')
        )
        
        print("[*] Starting enumeration...\n")
        results = enumerator.enumerate_all()
        
        # Generate report
        if args.output:
            output_file = args.output
        else:
            suffix = 'all_regions' if creds.get('all_regions') else creds.get('region', 'us-east-1')
            output_file = f"aws_enum_report_{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        if not args.json_only:
            report = enumerator.generate_report(output_file)
            print("\n" + "=" * 80)
            # Only print summary for multi-region to avoid overwhelming output
            if creds.get('all_regions'):
                summary_lines = report.split('\n')[:50]  # First 50 lines
                print('\n'.join(summary_lines))
                print("\n[...] Full report saved to file (too large to display) [...]")
            else:
                print(report)
        else:
            # JSON only mode
            json_file = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else f"{output_file}.json"
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"[+] JSON data saved to {json_file}")
        
        print("\n[+] Enumeration completed successfully!")
        
    except ValueError as e:
        print(f"[!] Validation Error: {str(e)}")
        sys.exit(1)
    except NoCredentialsError:
        print("[!] Invalid or expired credentials")
        sys.exit(1)
    except EndpointConnectionError as e:
        print(f"[!] Connection Error: Cannot reach AWS endpoints - check network connectivity")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Clear sensitive data from memory
        if creds:
            creds.clear()


if __name__ == "__main__":
    main()
