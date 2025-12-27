# AWS Account Enumerator

Automated enumeration tool for AWS accounts with secure credential handling and multi-region support. Generates comprehensive reports of all accessible resources.

## Features

- **Multi-Region Support**: Enumerate all enabled regions or select specific ones
- **Concurrent enumeration** of 9+ AWS services
- **Global Services** (enumerated once):
  - **IAM**: Users, roles, groups, policies
  - **Route53**: Hosted zones and DNS records
  - **S3**: Buckets, ACLs, encryption status
- **Regional Services** (enumerated per region):
  - **EC2**: Instances, security groups, VPCs, key pairs
  - **RDS**: Databases, snapshots
  - **Lambda**: Functions and configurations
  - **Secrets Manager**: Secret inventories
  - **KMS**: Key management
  - **CloudTrail**: Logging configurations
- Dual output: Human-readable TXT + structured JSON
- **Secure credential handling**: Masked input, env vars, validation
- **Input validation**: Credential format checking, region validation
- **Error handling**: Comprehensive error messages and recovery

## Installation

```bash
pip install -r requirements.txt
chmod +x aws_enum.py
```

## Usage

### Interactive Mode (Recommended)
```bash
python3 aws_enum.py
```
Credentials are masked during input using `getpass`. You'll be prompted to choose single or multi-region enumeration.

### Multi-Region Enumeration

**All Enabled Regions:**
```bash
# Interactive
python3 aws_enum.py
# Select 'y' when prompted "Enumerate all regions?"

# Command line
python3 aws_enum.py --all-regions

# With environment variables
python3 aws_enum.py --env --all-regions
```

**Specific Regions:**
```bash
# Interactive
python3 aws_enum.py
# Enter regions when prompted: us-east-1,us-west-2,eu-west-1

# Command line
python3 aws_enum.py --regions us-east-1,us-west-2,eu-west-1

# With credentials from environment
python3 aws_enum.py --env --regions us-east-1,eu-west-1,ap-southeast-1
```

### Environment Variables (Secure)
```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."  # Optional
export AWS_DEFAULT_REGION="us-east-1"

# Single region
python3 aws_enum.py --env

# All regions
python3 aws_enum.py --env --all-regions
```

### Command Line Arguments
```bash
# Single region
python3 aws_enum.py --access-key AKIA... --secret-key ... --region us-west-2

# All regions
python3 aws_enum.py --access-key AKIA... --secret-key ... --all-regions

# Specific regions
python3 aws_enum.py -a AKIA... -s ... --regions us-east-1,us-west-2

# With session token
python3 aws_enum.py -a AKIA... -s ... -t FwoGZXIv... --all-regions

# Custom output
python3 aws_enum.py --env --all-regions --output my_report.txt

# JSON only output
python3 aws_enum.py --env --all-regions --json-only
```

**Warning**: Command line arguments may expose credentials in process lists and shell history. Use environment variables or interactive mode for production.

### Programmatic Usage
```python
from aws_enum import AWSEnumerator

# Single region
enumerator = AWSEnumerator(
    access_key='AKIA...',
    secret_key='...',
    session_token='...',  # Optional
    region='us-east-1',
    all_regions=False
)

# All enabled regions
enumerator = AWSEnumerator(
    access_key='AKIA...',
    secret_key='...',
    all_regions=True
)

# Specific regions
enumerator = AWSEnumerator(
    access_key='AKIA...',
    secret_key='...',
    all_regions=True,
    regions=['us-east-1', 'us-west-2', 'eu-west-1']
)

results = enumerator.enumerate_all()
enumerator.generate_report('output.txt')
```

## Multi-Region Behavior

- **Global services** (IAM, Route53, S3) are enumerated **once** regardless of region count
- **Regional services** are enumerated **per region** in parallel
- Failed regions don't stop enumeration of other regions
- Report shows clear separation between global and regional resources
- Output file naming includes region info: `aws_enum_report_all_regions_TIMESTAMP.txt`

## Security Features

- **Credential validation**: Format checking before API calls
- **Immediate testing**: Validates credentials on initialization
- **Secure input**: Uses `getpass` to mask sensitive input
- **Memory cleanup**: Clears credentials from memory on exit
- **Input sanitization**: Strips whitespace, validates formats
- **Error specificity**: Clear error messages without exposing credentials

## Output

**Single Region:**
- `aws_enum_report_REGION_YYYYMMDD_HHMMSS.txt` - Formatted report
- `aws_enum_report_REGION_YYYYMMDD_HHMMSS.json` - Raw JSON data

**Multi-Region:**
- `aws_enum_report_all_regions_YYYYMMDD_HHMMSS.txt` - Formatted report
- `aws_enum_report_all_regions_YYYYMMDD_HHMMSS.json` - Raw JSON data

## Extension

Add new services by creating methods:
```python
def enumerate_<service>(self, session: boto3.Session = None) -> Dict:
    if session is None:
        session = self.session
    client = session.client('<service>')
    # Enumeration logic
    return data
```

Add to appropriate category:
- **Global services**: Add to `GLOBAL_SERVICES` list and `global_tasks` in `enumerate_all()`
- **Regional services**: Add to `regional_tasks` in `enumerate_region()`

## Credential Formats

- **Access Key**: `AKIA` or `ASIA` followed by 16 alphanumeric characters
- **Secret Key**: 40 characters (base64-like)
- **Session Token**: Variable length (for temporary credentials)

## Performance

- **Concurrent execution**: Regional services enumerated in parallel within each region
- **Rate limiting**: Built-in limits to avoid API throttling
- **Efficient region detection**: Auto-discovers only enabled regions
- **Progress indicators**: Real-time status updates during enumeration

## Notes

- Requires valid AWS credentials with appropriate read permissions
- Multi-region enumeration can take several minutes depending on region count
- Safe error handling prevents enumeration failures
- All timestamps in ISO format for parsing
- Validates regions against known AWS regions
- Route53 enumeration includes zones and first 20 DNS records per zone
