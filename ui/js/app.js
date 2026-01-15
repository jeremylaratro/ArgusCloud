    // State
    let cy = null;
    let nodes = [];
    let edges = [];
    let isFullscreen = false;
    let currentProfile = null;
    let profiles = [];

    // ============ Advanced Filter State ============
    const filterState = {
      searchText: '',
      resourceTypes: [],
      resourceCategories: [],
      severity: [],
      providers: [],
      regions: [],
      edgeTypes: [],
      attackRules: [],
      hasAttackPaths: false,
      publicExposure: false,
      misconfigured: false,
      // MITRE ATT&CK tactics
      mitreTactics: []
    };

    let savedFilters = JSON.parse(localStorage.getItem('arguscloud_saved_filters') || '[]');
    let availableTypes = [];
    let availableRegions = [];
    let availableEdgeTypes = [];
    let availableAttackRules = [];

    // AWS Resource Categories mapping
    const resourceCategories = {
      'Identity & Access': ['User', 'Role', 'Group', 'Principal', 'IAMSummary', 'IAMUser', 'IAMRole', 'IAMPolicy', 'InlinePolicy', 'ManagedPolicy', 'ResourcePolicy'],
      'Compute': ['EC2Instance', 'LambdaFunction', 'ECSCluster', 'ECSService', 'ECSTask', 'AutoScalingGroup'],
      'Storage': ['S3Bucket', 'EBSVolume', 'EFSFileSystem', 'Glacier'],
      'Network': ['VPC', 'Subnet', 'SecurityGroup', 'RouteTable', 'InternetGateway', 'NATGateway', 'LoadBalancer', 'TargetGroup'],
      'Security': ['KMSKey', 'SecretsManager', 'ACMCertificate', 'WAF', 'Shield'],
      'Database': ['RDSInstance', 'DynamoDBTable', 'ElastiCache', 'Redshift'],
      'Serverless': ['LambdaFunction', 'APIGateway', 'StepFunction', 'EventBridge'],
      'Logging': ['LogGroup', 'CloudTrail', 'CloudWatch'],
      'External': ['External']
    };

    // MITRE ATT&CK Cloud tactics
    const mitreTactics = {
      'initial-access': { name: 'Initial Access', description: 'Techniques used to gain initial foothold' },
      'execution': { name: 'Execution', description: 'Techniques for running malicious code' },
      'persistence': { name: 'Persistence', description: 'Techniques to maintain access' },
      'privilege-escalation': { name: 'Privilege Escalation', description: 'Techniques to gain higher privileges' },
      'defense-evasion': { name: 'Defense Evasion', description: 'Techniques to avoid detection' },
      'credential-access': { name: 'Credential Access', description: 'Techniques to steal credentials' },
      'discovery': { name: 'Discovery', description: 'Techniques to explore the environment' },
      'lateral-movement': { name: 'Lateral Movement', description: 'Techniques to move through network' },
      'collection': { name: 'Collection', description: 'Techniques to gather data' },
      'exfiltration': { name: 'Exfiltration', description: 'Techniques to steal data' },
      'impact': { name: 'Impact', description: 'Techniques to disrupt availability' }
    };

    // Attack rule to MITRE tactic mapping
    const attackRuleToTactic = {
      'imds-exposure': ['initial-access', 'credential-access'],
      'public-s3': ['initial-access', 'exfiltration'],
      'open-sg': ['initial-access', 'lateral-movement'],
      'kms-cross-account': ['privilege-escalation', 'lateral-movement'],
      'iam-privesc': ['privilege-escalation'],
      'ssrf-metadata': ['credential-access'],
      'unused-credentials': ['persistence'],
      'overpermissive-policy': ['privilege-escalation'],
      'cross-account-trust': ['lateral-movement'],
      'public-snapshot': ['exfiltration'],
      'unencrypted-storage': ['collection'],
      'logging-disabled': ['defense-evasion']
    };

    // Filter presets - expanded with AWS security scenarios
    const filterPresets = {
      'critical': {
        name: 'All Critical Findings',
        description: 'Resources with critical severity attack paths',
        filters: { severity: ['critical'], hasAttackPaths: true }
      },
      'high-risk': {
        name: 'High Risk',
        description: 'Critical and high severity findings',
        filters: { severity: ['critical', 'high'], hasAttackPaths: true }
      },
      'public': {
        name: 'Public Exposure',
        description: 'Publicly accessible resources',
        filters: { publicExposure: true }
      },
      'privesc': {
        name: 'Privilege Escalation',
        description: 'IAM privilege escalation paths',
        filters: { mitreTactics: ['privilege-escalation'], hasAttackPaths: true }
      },
      'lateral-movement': {
        name: 'Lateral Movement',
        description: 'Cross-account and role assumption paths',
        filters: { mitreTactics: ['lateral-movement'], hasAttackPaths: true }
      },
      'credential-theft': {
        name: 'Credential Access',
        description: 'IMDS exposure, secrets access paths',
        filters: { mitreTactics: ['credential-access'], hasAttackPaths: true }
      },
      'iam-audit': {
        name: 'IAM Audit',
        description: 'All IAM resources for security review',
        filters: { resourceCategories: ['Identity & Access'] }
      },
      'network-exposure': {
        name: 'Network Exposure',
        description: 'Security groups, VPCs, and network resources',
        filters: { resourceCategories: ['Network'] }
      },
      'data-at-risk': {
        name: 'Data at Risk',
        description: 'Storage resources with attack paths',
        filters: { resourceCategories: ['Storage'], hasAttackPaths: true }
      },
      'compute-threats': {
        name: 'Compute Threats',
        description: 'EC2, Lambda with security findings',
        filters: { resourceCategories: ['Compute'], hasAttackPaths: true }
      },
      'trust-relationships': {
        name: 'Trust Relationships',
        description: 'Role assumptions and trust policies',
        filters: { edgeTypes: ['Trusts', 'AssumesRole', 'CanAssume'] }
      },
      'attack-paths-only': {
        name: 'Attack Paths Only',
        description: 'Show only attack path edges',
        filters: { edgeTypes: ['AttackPath'] }
      }
    };

    // ============ AWS Attack Queries ============
    // BloodHound-style categorized attack queries
    const awsAttackQueries = {
      common: {
        name: 'Common',
        queries: [
          { id: 'all-attack-paths', name: 'All Attack Paths', severity: 'high', description: 'Show all discovered attack paths', action: 'filter', filters: { hasAttackPaths: true } },
          { id: 'critical-findings', name: 'Critical Severity Findings', severity: 'critical', description: 'Resources with critical severity issues', action: 'filter', filters: { severity: ['critical'], hasAttackPaths: true } },
          { id: 'high-risk', name: 'High Risk Resources', severity: 'high', description: 'Critical and high severity findings', action: 'filter', filters: { severity: ['critical', 'high'], hasAttackPaths: true } },
          { id: 'public-resources', name: 'Publicly Accessible Resources', severity: 'high', description: 'Resources exposed to the internet', action: 'filter', filters: { publicExposure: true } },
          { id: 'misconfigured', name: 'Misconfigured Resources', severity: 'medium', description: 'Resources with security misconfigurations', action: 'filter', filters: { misconfigured: true } }
        ]
      },
      admin: {
        name: 'Admin Access',
        queries: [
          { id: 'admin-users', name: 'Users with Admin Access', severity: 'critical', description: 'IAM users with administrative privileges', action: 'cypher', query: "MATCH (u:IAMUser)-[:HasPolicy|AttachedPolicy]->(p) WHERE p.name CONTAINS 'Admin' RETURN u, p" },
          { id: 'admin-roles', name: 'Roles with Admin Access', severity: 'critical', description: 'IAM roles with administrative privileges', action: 'cypher', query: "MATCH (r:IAMRole)-[:HasPolicy|AttachedPolicy]->(p) WHERE p.name CONTAINS 'Admin' RETURN r, p" },
          { id: 'poweruser-access', name: 'PowerUser Access', severity: 'high', description: 'Principals with PowerUser-level access', action: 'cypher', query: "MATCH (n)-[:HasPolicy|AttachedPolicy]->(p) WHERE p.name CONTAINS 'PowerUser' RETURN n, p" },
          { id: 'root-account', name: 'Root Account Usage', severity: 'critical', description: 'Detect root account access patterns', action: 'cypher', query: "MATCH (n) WHERE n.id CONTAINS ':root' RETURN n" },
          { id: 'iam-full-access', name: 'IAM Full Access', severity: 'critical', description: 'Principals with iam:* permissions', action: 'cypher', query: "MATCH (n)-[:HasPolicy|AttachedPolicy]->(p) WHERE p.name CONTAINS 'IAMFullAccess' RETURN n, p" }
        ]
      },
      privesc: {
        name: 'Privilege Escalation',
        queries: [
          { id: 'privesc-paths', name: 'All PrivEsc Paths', severity: 'critical', description: 'All privilege escalation attack paths', action: 'filter', filters: { mitreTactics: ['privilege-escalation'], hasAttackPaths: true } },
          { id: 'assumable-admin', name: 'Paths to Admin Roles', severity: 'critical', description: 'Paths from users to admin roles', action: 'cypher', query: "MATCH path=(u:IAMUser)-[:CanAssume*1..3]->(r:IAMRole)-[:HasPolicy]->(p) WHERE p.name CONTAINS 'Admin' RETURN path" },
          { id: 'create-user', name: 'Can Create Users', severity: 'high', description: 'Principals that can create new IAM users', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'iam:CreateUser' RETURN n, p" },
          { id: 'create-role', name: 'Can Create Roles', severity: 'high', description: 'Principals that can create new IAM roles', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'iam:CreateRole' RETURN n, p" },
          { id: 'attach-policy', name: 'Can Attach Policies', severity: 'high', description: 'Principals that can attach policies to any user/role', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'iam:AttachUserPolicy' OR p.document CONTAINS 'iam:AttachRolePolicy' RETURN n, p" },
          { id: 'passrole', name: 'PassRole Permissions', severity: 'high', description: 'Principals with iam:PassRole capability', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'iam:PassRole' RETURN n, p" },
          { id: 'update-assume', name: 'Can Modify Trust Policies', severity: 'critical', description: 'Principals that can update role trust policies', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'iam:UpdateAssumeRolePolicy' RETURN n, p" }
        ]
      },
      credential: {
        name: 'Credential Theft',
        queries: [
          { id: 'credential-paths', name: 'All Credential Access Paths', severity: 'high', description: 'Paths to credential access', action: 'filter', filters: { mitreTactics: ['credential-access'], hasAttackPaths: true } },
          { id: 'imds-access', name: 'IMDS Credential Exposure', severity: 'critical', description: 'EC2 instances with IMDSv1 enabled', action: 'cypher', query: "MATCH (e:EC2Instance) WHERE e.imds_v1_enabled = true RETURN e" },
          { id: 'secrets-access', name: 'Secrets Manager Access', severity: 'high', description: 'Principals with access to secrets', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'secretsmanager:GetSecretValue' RETURN n, p" },
          { id: 'ssm-params', name: 'SSM Parameter Access', severity: 'medium', description: 'Principals with access to SSM parameters', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'ssm:GetParameter' RETURN n, p" },
          { id: 'kms-decrypt', name: 'KMS Decrypt Access', severity: 'high', description: 'Principals that can decrypt with KMS keys', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'kms:Decrypt' RETURN n, p" },
          { id: 'access-keys', name: 'Users with Access Keys', severity: 'medium', description: 'IAM users with active access keys', action: 'cypher', query: "MATCH (u:IAMUser) WHERE u.has_access_keys = true RETURN u" }
        ]
      },
      exposure: {
        name: 'Public Exposure',
        queries: [
          { id: 'public-s3', name: 'Public S3 Buckets', severity: 'critical', description: 'S3 buckets with public access', action: 'cypher', query: "MATCH (s:S3Bucket) WHERE s.public_access = true RETURN s" },
          { id: 'public-ec2', name: 'Public EC2 Instances', severity: 'high', description: 'EC2 instances with public IPs', action: 'cypher', query: "MATCH (e:EC2Instance) WHERE e.public_ip IS NOT NULL RETURN e" },
          { id: 'open-sg', name: 'Open Security Groups', severity: 'high', description: 'Security groups allowing 0.0.0.0/0', action: 'cypher', query: "MATCH (sg:SecurityGroup) WHERE sg.ingress_open = true RETURN sg" },
          { id: 'public-rds', name: 'Public RDS Instances', severity: 'critical', description: 'RDS instances publicly accessible', action: 'cypher', query: "MATCH (r:RDSInstance) WHERE r.publicly_accessible = true RETURN r" },
          { id: 'public-snapshots', name: 'Public Snapshots', severity: 'high', description: 'EBS/RDS snapshots shared publicly', action: 'cypher', query: "MATCH (s:Snapshot) WHERE s.public = true RETURN s" },
          { id: 'public-lambda', name: 'Public Lambda URLs', severity: 'medium', description: 'Lambda functions with public URLs', action: 'cypher', query: "MATCH (l:LambdaFunction) WHERE l.public_url = true RETURN l" }
        ]
      },
      crossaccount: {
        name: 'Cross-Account',
        queries: [
          { id: 'cross-account-roles', name: 'Cross-Account Assumable Roles', severity: 'high', description: 'Roles assumable from other accounts', action: 'cypher', query: "MATCH (r:IAMRole) WHERE r.trust_policy CONTAINS 'arn:aws' AND NOT r.trust_policy CONTAINS r.account_id RETURN r" },
          { id: 'external-trusts', name: 'External Account Trusts', severity: 'high', description: 'Roles trusting external accounts', action: 'cypher', query: "MATCH (r:IAMRole)-[:TrustedBy]->(ext:External) RETURN r, ext" },
          { id: 'cross-account-s3', name: 'Cross-Account S3 Access', severity: 'medium', description: 'S3 buckets with cross-account policies', action: 'cypher', query: "MATCH (s:S3Bucket) WHERE s.cross_account_access = true RETURN s" },
          { id: 'cross-account-kms', name: 'Cross-Account KMS Access', severity: 'high', description: 'KMS keys accessible from other accounts', action: 'cypher', query: "MATCH (k:KMSKey) WHERE k.cross_account_access = true RETURN k" },
          { id: 'org-scp', name: 'Organization SCPs', severity: 'info', description: 'Service Control Policies in the organization', action: 'cypher', query: "MATCH (o:Organization)-[:HasSCP]->(scp) RETURN o, scp" }
        ]
      },
      lateral: {
        name: 'Lateral Movement',
        queries: [
          { id: 'lateral-paths', name: 'All Lateral Movement Paths', severity: 'high', description: 'All lateral movement attack paths', action: 'filter', filters: { mitreTactics: ['lateral-movement'], hasAttackPaths: true } },
          { id: 'role-chains', name: 'Role Assumption Chains', severity: 'high', description: 'Multi-hop role assumption paths', action: 'cypher', query: "MATCH path=(n)-[:CanAssume*2..5]->(r:IAMRole) RETURN path" },
          { id: 'ssm-access', name: 'SSM Session Access', severity: 'medium', description: 'Principals with SSM session access to instances', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'ssm:StartSession' RETURN n, p" },
          { id: 'ec2-connect', name: 'EC2 Instance Connect', severity: 'medium', description: 'Principals with EC2 Instance Connect access', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'ec2-instance-connect:SendSSHPublicKey' RETURN n, p" },
          { id: 'lambda-invoke', name: 'Lambda Invoke Access', severity: 'medium', description: 'Principals that can invoke Lambda functions', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'lambda:InvokeFunction' RETURN n, p" }
        ]
      },
      data: {
        name: 'Data Exfiltration',
        queries: [
          { id: 'exfil-paths', name: 'All Data Exfil Paths', severity: 'high', description: 'All data exfiltration paths', action: 'filter', filters: { mitreTactics: ['exfiltration'], hasAttackPaths: true } },
          { id: 's3-read', name: 'S3 Read Access', severity: 'medium', description: 'Principals with S3 read permissions', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 's3:GetObject' RETURN n, p" },
          { id: 'rds-snapshot', name: 'RDS Snapshot Access', severity: 'high', description: 'Principals that can create RDS snapshots', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'rds:CreateDBSnapshot' RETURN n, p" },
          { id: 'ebs-snapshot', name: 'EBS Snapshot Access', severity: 'high', description: 'Principals that can create/share EBS snapshots', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'ec2:CreateSnapshot' RETURN n, p" },
          { id: 'dynamodb-read', name: 'DynamoDB Read Access', severity: 'medium', description: 'Principals with DynamoDB read access', action: 'cypher', query: "MATCH (n)-[:HasPolicy]->(p) WHERE p.document CONTAINS 'dynamodb:GetItem' OR p.document CONTAINS 'dynamodb:Scan' RETURN n, p" },
          { id: 'unencrypted-data', name: 'Unencrypted Data Stores', severity: 'high', description: 'S3/EBS/RDS without encryption', action: 'cypher', query: "MATCH (n) WHERE n.encrypted = false AND (n:S3Bucket OR n:EBSVolume OR n:RDSInstance) RETURN n" }
        ]
      }
    };

    // ============ Query List Rendering ============
    // Render attack queries for selected category
    function renderQueryList(category) {
      const queryList = document.getElementById('queryList');
      if (!queryList) return;

      const categoryData = awsAttackQueries[category];
      if (!categoryData) {
        queryList.innerHTML = '<div class="empty-state" style="padding: 16px; color: var(--text-tertiary); font-size: 12px;">No queries available</div>';
        return;
      }

      queryList.innerHTML = categoryData.queries.map(q => `
        <div class="query-item" data-query-id="${q.id}" data-action="${q.action}" title="${q.description}">
          <span class="query-item-icon ${q.severity}"></span>
          <span class="query-item-name">${q.name}</span>
        </div>
      `).join('');

      // Add click handlers
      queryList.querySelectorAll('.query-item').forEach(item => {
        item.addEventListener('click', () => executeAttackQuery(item.dataset.queryId, category));
      });
    }

    // Execute an attack query
    function executeAttackQuery(queryId, category) {
      const categoryData = awsAttackQueries[category];
      if (!categoryData) return;

      const query = categoryData.queries.find(q => q.id === queryId);
      if (!query) return;

      // Remove active state from all items
      document.querySelectorAll('.query-item').forEach(item => item.classList.remove('active'));
      // Add active state to clicked item
      const clickedItem = document.querySelector(`.query-item[data-query-id="${queryId}"]`);
      if (clickedItem) clickedItem.classList.add('active');

      if (query.action === 'filter') {
        // Apply filter-based query
        applyQueryFilters(query.filters);
      } else if (query.action === 'cypher') {
        // Run Cypher query
        const cypherInput = document.getElementById('cypherInput');
        if (cypherInput) {
          cypherInput.value = query.query;
          // Trigger cypher execution
          document.getElementById('runCypherBtn').click();
        }
      }
    }

    // Apply filters from a query
    function applyQueryFilters(filters) {
      // Clear current filters first
      clearAllFilters();

      // Apply the query filters
      if (filters.severity) {
        filterState.severity = [...filters.severity];
        document.querySelectorAll('.severity-chip').forEach(chip => {
          if (filters.severity.includes(chip.dataset.severity)) {
            chip.classList.add('selected');
          }
        });
      }

      if (filters.hasAttackPaths) {
        filterState.hasAttackPaths = true;
        document.getElementById('hasAttackPathsToggle').checked = true;
        document.getElementById('hasAttackPathsToggle').closest('.toggle-row')?.classList.add('active');
      }

      if (filters.publicExposure) {
        filterState.publicExposure = true;
        document.getElementById('publicExposureToggle').checked = true;
        document.getElementById('publicExposureToggle').closest('.toggle-row')?.classList.add('active');
      }

      if (filters.misconfigured) {
        filterState.misconfigured = true;
        document.getElementById('misconfiguredToggle').checked = true;
        document.getElementById('misconfiguredToggle').closest('.toggle-row')?.classList.add('active');
      }

      if (filters.mitreTactics) {
        filterState.mitreTactics = [...filters.mitreTactics];
        document.querySelectorAll('.mitre-tactic').forEach(tactic => {
          if (filters.mitreTactics.includes(tactic.dataset.tactic)) {
            tactic.classList.add('selected');
          }
        });
      }

      if (filters.resourceCategories) {
        filterState.resourceCategories = [...filters.resourceCategories];
      }

      if (filters.edgeTypes) {
        filterState.edgeTypes = [...filters.edgeTypes];
      }

      // Update active filters display
      updateActiveFiltersBar();

      // Apply the filters
      applyFilters();
    }

    // Initialize query category dropdown
    function initQueryCategories() {
      const categorySelect = document.getElementById('queryCategory');
      if (!categorySelect) return;

      // Render initial category
      renderQueryList('common');

      // Listen for category changes
      categorySelect.addEventListener('change', (e) => {
        renderQueryList(e.target.value);
      });
    }

    // ============ Vulnerability Knowledge Base ============
    // Comprehensive security knowledge for expandable attack path rows
    const vulnerabilityKnowledgeBase = {
      // IAM Rules
      'aws-iam-open-trust': {
        description: 'IAM role has an overly permissive trust policy allowing any AWS principal to assume it',
        severity: 'critical',
        mitre: ['T1078.004', 'T1550.001'],
        category: 'Identity & Access',
        exploitation: {
          overview: 'An attacker can assume this role from any AWS account, gaining its permissions without authorization.',
          steps: [
            'Identify the vulnerable role ARN from the attack path',
            'From any AWS account, attempt to assume the role: aws sts assume-role --role-arn <ROLE_ARN> --role-session-name attacker',
            'If successful, use the temporary credentials to access resources',
            'Enumerate permissions: aws iam list-attached-role-policies --role-name <ROLE>',
            'Pivot to access sensitive data or escalate privileges further'
          ],
          tools: ['AWS CLI', 'Pacu (iam__enum_permissions)', 'enumerate-iam']
        },
        remediation: {
          overview: 'Restrict the trust policy to specific, known AWS accounts and principals.',
          steps: [
            'Review current trust policy: aws iam get-role --role-name <ROLE>',
            'Identify legitimate principals that need to assume this role',
            'Update trust policy to specify exact account IDs and principal ARNs',
            'Add conditions like aws:PrincipalOrgID for organization-only access',
            'Consider adding external ID requirement for cross-account roles'
          ],
          cliCommands: [
            'aws iam get-role --role-name <ROLE_NAME>',
            'aws iam update-assume-role-policy --role-name <ROLE_NAME> --policy-document file://restricted-trust-policy.json'
          ]
        }
      },
      'aws-iam-assume-role-chain': {
        description: 'Role assumption chain allows privilege escalation through multiple role hops',
        severity: 'high',
        mitre: ['T1078.004', 'T1548'],
        category: 'Identity & Access',
        exploitation: {
          overview: 'Attackers can chain role assumptions to escalate from low-privilege to high-privilege access.',
          steps: [
            'Map the role assumption chain using the graph',
            'Start with initial compromised credentials',
            'Assume first role: aws sts assume-role --role-arn <ROLE1_ARN> --role-session-name step1',
            'Use new credentials to assume next role in chain',
            'Continue until reaching high-privilege role',
            'Access sensitive resources with escalated permissions'
          ],
          tools: ['AWS CLI', 'Pacu (iam__privesc_scan)', 'PMapper', 'Cloudsplaining']
        },
        remediation: {
          overview: 'Break unnecessary role chains and implement least-privilege trust policies.',
          steps: [
            'Map all role assumption paths in your environment',
            'Identify and remove unnecessary trust relationships',
            'Implement permission boundaries on roles',
            'Add conditions to trust policies (source IP, MFA, etc.)',
            'Enable CloudTrail logging for AssumeRole events',
            'Set up alerts for unusual role assumption patterns'
          ],
          cliCommands: [
            'aws iam list-roles --query "Roles[*].[RoleName,AssumeRolePolicyDocument]"',
            'aws iam put-role-permissions-boundary --role-name <ROLE> --permissions-boundary <BOUNDARY_ARN>'
          ]
        }
      },
      'aws-iam-user-no-mfa': {
        description: 'IAM user does not have MFA enabled, vulnerable to credential theft',
        severity: 'high',
        mitre: ['T1078.004', 'T1556'],
        category: 'Identity & Access',
        exploitation: {
          overview: 'Stolen credentials can be used directly without additional authentication challenges.',
          steps: [
            'Obtain user credentials through phishing, code repository scanning, or other means',
            'Configure AWS CLI with stolen credentials',
            'Verify access: aws sts get-caller-identity',
            'Enumerate and access resources without MFA challenge',
            'Create persistence mechanisms (new access keys, roles)'
          ],
          tools: ['truffleHog', 'git-secrets', 'AWS CLI', 'Pacu']
        },
        remediation: {
          overview: 'Enable MFA for all IAM users, especially those with console or privileged access.',
          steps: [
            'List users without MFA: aws iam generate-credential-report',
            'Enable virtual MFA for each user',
            'Update IAM policies to require MFA for sensitive actions',
            'Consider hardware security keys for privileged users',
            'Implement MFA enforcement via SCP for the organization'
          ],
          cliCommands: [
            'aws iam create-virtual-mfa-device --virtual-mfa-device-name <USER>-mfa --outfile QRCode.png --bootstrap-method QRCodePNG',
            'aws iam enable-mfa-device --user-name <USER> --serial-number <MFA_ARN> --authentication-code1 <CODE1> --authentication-code2 <CODE2>'
          ]
        }
      },
      'aws-iam-user-multiple-keys': {
        description: 'IAM user has multiple active access keys, increasing attack surface',
        severity: 'medium',
        mitre: ['T1078.004', 'T1552.004'],
        category: 'Identity & Access',
        exploitation: {
          overview: 'Multiple access keys increase the chance of credential exposure and complicate key rotation.',
          steps: [
            'Identify users with multiple keys from IAM analysis',
            'Search for exposed keys in code repositories, logs, or config files',
            'Each additional key is another potential entry point',
            'Older keys may have been shared or stored insecurely'
          ],
          tools: ['truffleHog', 'git-secrets', 'AWS CLI']
        },
        remediation: {
          overview: 'Maintain single active access key per user and implement regular rotation.',
          steps: [
            'Audit all access keys: aws iam list-access-keys --user-name <USER>',
            'Identify which key is actively used via CloudTrail',
            'Deactivate unused keys before deletion',
            'Delete redundant keys after verification period',
            'Implement automated key rotation policy'
          ],
          cliCommands: [
            'aws iam list-access-keys --user-name <USER>',
            'aws iam update-access-key --user-name <USER> --access-key-id <KEY_ID> --status Inactive',
            'aws iam delete-access-key --user-name <USER> --access-key-id <KEY_ID>'
          ]
        }
      },

      // EC2 Rules
      'aws-ec2-open-security-group': {
        description: 'Security group allows unrestricted inbound access (0.0.0.0/0)',
        severity: 'high',
        mitre: ['T1190', 'T1133'],
        category: 'Network',
        exploitation: {
          overview: 'Publicly accessible services can be directly attacked from the internet.',
          steps: [
            'Scan the public IP range for open ports: nmap -sV <IP>',
            'Identify services running on exposed ports',
            'Attempt exploitation of vulnerable services (SSH brute force, web app attacks)',
            'If access gained, pivot to internal resources',
            'Query IMDS for credentials: curl http://169.254.169.254/latest/meta-data/iam/'
          ],
          tools: ['nmap', 'Metasploit', 'Burp Suite', 'Hydra']
        },
        remediation: {
          overview: 'Restrict security group rules to specific IP ranges and required ports only.',
          steps: [
            'Audit current security group rules',
            'Identify legitimate source IPs that need access',
            'Replace 0.0.0.0/0 with specific CIDR blocks',
            'Use AWS Systems Manager Session Manager instead of SSH',
            'Implement VPN or bastion host for administrative access',
            'Enable VPC Flow Logs for monitoring'
          ],
          cliCommands: [
            'aws ec2 describe-security-groups --group-ids <SG_ID>',
            'aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0',
            'aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr <YOUR_IP>/32'
          ]
        }
      },
      'aws-ec2-imds-exposure': {
        description: 'EC2 instance uses IMDSv1, vulnerable to SSRF credential theft',
        severity: 'critical',
        mitre: ['T1552.005', 'T1190'],
        category: 'Compute',
        exploitation: {
          overview: 'SSRF vulnerabilities can retrieve IAM credentials from the instance metadata service.',
          steps: [
            'Identify SSRF vulnerability in web application on the instance',
            'Craft request to IMDS: http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'Retrieve role name from response',
            'Fetch credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>',
            'Use stolen credentials to access AWS resources',
            'Credentials include AccessKeyId, SecretAccessKey, and Token'
          ],
          tools: ['curl', 'Burp Suite', 'SSRF testing tools', 'Pacu']
        },
        remediation: {
          overview: 'Enforce IMDSv2 which requires session tokens, preventing SSRF exploitation.',
          steps: [
            'Audit instances for IMDS version: aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,MetadataOptions]"',
            'Update existing instances to require IMDSv2',
            'Set HttpTokens to "required" in launch templates',
            'Test applications for IMDS compatibility',
            'Consider disabling IMDS if not needed'
          ],
          cliCommands: [
            'aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens required --http-endpoint enabled',
            'aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query "Reservations[*].Instances[*].MetadataOptions"'
          ]
        }
      },
      'aws-ec2-public-snapshot': {
        description: 'EBS snapshot is publicly shared, exposing potentially sensitive data',
        severity: 'critical',
        mitre: ['T1530', 'T1537'],
        category: 'Storage',
        exploitation: {
          overview: 'Anyone can copy public snapshots and extract sensitive data from them.',
          steps: [
            'List public snapshots: aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids <TARGET_ACCOUNT>',
            'Copy snapshot to attacker account: aws ec2 copy-snapshot --source-region <REGION> --source-snapshot-id <SNAP_ID>',
            'Create volume from snapshot',
            'Attach to attacker EC2 instance',
            'Mount and search for secrets, credentials, database dumps'
          ],
          tools: ['AWS CLI', 'Pacu (ebs__enum_snapshots)', 'grep/find for secrets']
        },
        remediation: {
          overview: 'Remove public access from snapshots and encrypt all EBS volumes.',
          steps: [
            'List public snapshots in your account',
            'Remove public permissions from snapshots',
            'Enable EBS encryption by default in all regions',
            'Use AWS KMS customer-managed keys for sensitive data',
            'Implement snapshot lifecycle policies'
          ],
          cliCommands: [
            'aws ec2 describe-snapshots --owner-ids self --query "Snapshots[?contains(to_string(CreateVolumePermissions), \'all\')]"',
            'aws ec2 modify-snapshot-attribute --snapshot-id <SNAP_ID> --attribute createVolumePermission --operation-type remove --group-names all'
          ]
        }
      },
      'aws-ec2-public-ami': {
        description: 'AMI is publicly shared, potentially exposing sensitive configurations',
        severity: 'high',
        mitre: ['T1530', 'T1537'],
        category: 'Compute',
        exploitation: {
          overview: 'Public AMIs can be launched to extract embedded secrets and configurations.',
          steps: [
            'Find public AMIs: aws ec2 describe-images --owners <TARGET_ACCOUNT> --query "Images[?Public==`true`]"',
            'Launch instance from public AMI in attacker account',
            'Search for hardcoded credentials in /etc, /home, /var',
            'Check for SSH keys, API tokens, database passwords',
            'Review application configurations and startup scripts'
          ],
          tools: ['AWS CLI', 'grep/find', 'truffleHog']
        },
        remediation: {
          overview: 'Make AMIs private and remove sensitive data before any sharing.',
          steps: [
            'Audit AMI permissions: aws ec2 describe-image-attribute --image-id <AMI_ID> --attribute launchPermission',
            'Remove public access from AMIs',
            'Use AWS Systems Manager Parameter Store for secrets instead of embedding',
            'Implement AMI scanning in CI/CD pipeline',
            'Create AMI sharing policies'
          ],
          cliCommands: [
            'aws ec2 modify-image-attribute --image-id <AMI_ID> --launch-permission "Remove=[{Group=all}]"',
            'aws ec2 describe-images --owners self --query "Images[?Public==`true`].[ImageId,Name]"'
          ]
        }
      },
      'aws-ec2-unencrypted-snapshot': {
        description: 'EBS snapshot is not encrypted, data at rest is unprotected',
        severity: 'medium',
        mitre: ['T1530'],
        category: 'Storage',
        exploitation: {
          overview: 'Unencrypted snapshots can be accessed if permissions are misconfigured.',
          steps: [
            'If snapshot becomes shared or public, data is immediately accessible',
            'Copy unencrypted snapshot to attacker-controlled account',
            'Create volume and attach to EC2 instance',
            'Mount filesystem and access all data without decryption'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Enable EBS encryption by default and encrypt existing snapshots.',
          steps: [
            'Enable EBS encryption by default: aws ec2 enable-ebs-encryption-by-default',
            'Copy unencrypted snapshots with encryption enabled',
            'Delete original unencrypted snapshots after verification',
            'Use customer-managed KMS keys for sensitive workloads'
          ],
          cliCommands: [
            'aws ec2 enable-ebs-encryption-by-default --region <REGION>',
            'aws ec2 copy-snapshot --source-region <REGION> --source-snapshot-id <SNAP_ID> --encrypted --kms-key-id <KEY_ID>'
          ]
        }
      },

      // S3 Rules
      'aws-s3-public-bucket': {
        description: 'S3 bucket allows public access, exposing stored data',
        severity: 'critical',
        mitre: ['T1530', 'T1537'],
        category: 'Storage',
        exploitation: {
          overview: 'Anyone on the internet can list and download objects from public buckets.',
          steps: [
            'Enumerate bucket: aws s3 ls s3://<BUCKET_NAME> --no-sign-request',
            'Download sensitive files: aws s3 cp s3://<BUCKET>/<KEY> . --no-sign-request',
            'Check for backup files, logs, credentials, PII',
            'If write access exists, upload malicious content',
            'Search for .env files, config files, database exports'
          ],
          tools: ['AWS CLI', 'S3Scanner', 'BucketFinder', 'AWSBucketDump']
        },
        remediation: {
          overview: 'Enable S3 Block Public Access and review bucket policies.',
          steps: [
            'Enable Block Public Access at account level',
            'Enable Block Public Access on individual buckets',
            'Review and remove public bucket policies',
            'Audit bucket ACLs for public grants',
            'Use S3 Access Analyzer to identify public buckets'
          ],
          cliCommands: [
            'aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true',
            'aws s3api get-bucket-policy --bucket <BUCKET>',
            'aws s3api delete-bucket-policy --bucket <BUCKET>'
          ]
        }
      },
      'aws-s3-policy-allows-all': {
        description: 'S3 bucket policy grants access to all AWS principals',
        severity: 'critical',
        mitre: ['T1530', 'T1537'],
        category: 'Storage',
        exploitation: {
          overview: 'Any authenticated AWS user can access this bucket, not just your organization.',
          steps: [
            'Identify bucket with wildcard principal policy',
            'Authenticate with any AWS credentials',
            'Access bucket contents: aws s3 ls s3://<BUCKET>',
            'Download sensitive data',
            'If write access granted, exfiltrate data or deploy backdoors'
          ],
          tools: ['AWS CLI', 'Pacu']
        },
        remediation: {
          overview: 'Restrict bucket policy to specific accounts and principals.',
          steps: [
            'Review current bucket policy',
            'Replace Principal: "*" with specific account IDs',
            'Use aws:PrincipalOrgID condition for organization-only access',
            'Implement least-privilege access patterns',
            'Enable S3 server access logging'
          ],
          cliCommands: [
            'aws s3api get-bucket-policy --bucket <BUCKET>',
            'aws s3api put-bucket-policy --bucket <BUCKET> --policy file://restricted-policy.json'
          ]
        }
      },
      'aws-s3-no-encryption': {
        description: 'S3 bucket does not have default encryption enabled',
        severity: 'medium',
        mitre: ['T1530'],
        category: 'Storage',
        exploitation: {
          overview: 'Objects stored without encryption are vulnerable if bucket access is compromised.',
          steps: [
            'If bucket permissions are misconfigured, data is immediately accessible',
            'No additional decryption step required to read objects',
            'Compliance violations for regulated data (PCI, HIPAA, GDPR)'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Enable default encryption using SSE-S3 or SSE-KMS.',
          steps: [
            'Enable default encryption on the bucket',
            'Use SSE-KMS for sensitive data with key rotation',
            'Implement bucket policy to deny unencrypted uploads',
            'Re-encrypt existing objects if needed'
          ],
          cliCommands: [
            'aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<KEY_ID>"}}]}\'',
            'aws s3api get-bucket-encryption --bucket <BUCKET>'
          ]
        }
      },
      'aws-s3-no-versioning': {
        description: 'S3 bucket does not have versioning enabled, vulnerable to data loss',
        severity: 'low',
        mitre: ['T1485', 'T1490'],
        category: 'Storage',
        exploitation: {
          overview: 'Deleted or overwritten objects cannot be recovered without versioning.',
          steps: [
            'If write access is obtained, data can be permanently deleted',
            'Ransomware attacks can encrypt and delete originals',
            'Accidental deletions are unrecoverable'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Enable versioning and consider MFA delete for critical buckets.',
          steps: [
            'Enable versioning on the bucket',
            'Consider MFA delete for production data',
            'Set up lifecycle rules for version management',
            'Implement Object Lock for compliance requirements'
          ],
          cliCommands: [
            'aws s3api put-bucket-versioning --bucket <BUCKET> --versioning-configuration Status=Enabled',
            'aws s3api get-bucket-versioning --bucket <BUCKET>'
          ]
        }
      },

      // KMS and Data Rules
      'aws-kms-key-public-access': {
        description: 'KMS key policy allows public access, enabling unauthorized decryption',
        severity: 'critical',
        mitre: ['T1552', 'T1530'],
        category: 'Security',
        exploitation: {
          overview: 'Anyone can use the KMS key to decrypt data encrypted with it.',
          steps: [
            'Identify the vulnerable KMS key ARN',
            'Use the key to decrypt data: aws kms decrypt --key-id <KEY_ARN> --ciphertext-blob <DATA>',
            'Access encrypted S3 objects, EBS volumes, RDS databases',
            'Potentially encrypt data with the key for ransomware'
          ],
          tools: ['AWS CLI', 'Pacu']
        },
        remediation: {
          overview: 'Restrict KMS key policy to specific principals and accounts.',
          steps: [
            'Review key policy: aws kms get-key-policy --key-id <KEY_ID> --policy-name default',
            'Remove wildcard principals from the policy',
            'Specify exact IAM roles/users that need access',
            'Enable key deletion protection',
            'Monitor key usage with CloudTrail'
          ],
          cliCommands: [
            'aws kms get-key-policy --key-id <KEY_ID> --policy-name default',
            'aws kms put-key-policy --key-id <KEY_ID> --policy-name default --policy file://restricted-key-policy.json'
          ]
        }
      },
      'aws-kms-key-no-rotation': {
        description: 'KMS key does not have automatic rotation enabled',
        severity: 'medium',
        mitre: ['T1552'],
        category: 'Security',
        exploitation: {
          overview: 'Keys without rotation may be compromised without detection.',
          steps: [
            'Long-lived keys increase exposure window if compromised',
            'Compliance frameworks often require key rotation',
            'Historical access to key material remains valid indefinitely'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Enable automatic key rotation for symmetric KMS keys.',
          steps: [
            'Enable automatic rotation (rotates yearly)',
            'Previous key versions retained for decryption',
            'New encryptions use latest key version',
            'Consider custom rotation for asymmetric keys'
          ],
          cliCommands: [
            'aws kms enable-key-rotation --key-id <KEY_ID>',
            'aws kms get-key-rotation-status --key-id <KEY_ID>'
          ]
        }
      },
      'aws-rds-public-snapshot': {
        description: 'RDS snapshot is publicly shared, exposing database contents',
        severity: 'critical',
        mitre: ['T1530', 'T1537'],
        category: 'Database',
        exploitation: {
          overview: 'Anyone can restore a public RDS snapshot and access all data.',
          steps: [
            'List public RDS snapshots from target account',
            'Restore snapshot in attacker account: aws rds restore-db-instance-from-db-snapshot',
            'Reset master password and connect to database',
            'Dump all tables and sensitive data',
            'Search for credentials, PII, business data'
          ],
          tools: ['AWS CLI', 'mysql/psql clients', 'mysqldump/pg_dump']
        },
        remediation: {
          overview: 'Remove public access from RDS snapshots and encrypt them.',
          steps: [
            'Audit RDS snapshots for public access',
            'Remove public sharing from snapshots',
            'Enable encryption for RDS instances and snapshots',
            'Use AWS KMS for encryption key management',
            'Implement snapshot lifecycle policies'
          ],
          cliCommands: [
            'aws rds describe-db-snapshots --snapshot-type public',
            'aws rds modify-db-snapshot-attribute --db-snapshot-identifier <SNAP_ID> --attribute-name restore --values-to-remove all'
          ]
        }
      },
      'aws-rds-unencrypted-snapshot': {
        description: 'RDS snapshot is not encrypted',
        severity: 'medium',
        mitre: ['T1530'],
        category: 'Database',
        exploitation: {
          overview: 'Unencrypted snapshots expose data if access controls are bypassed.',
          steps: [
            'If snapshot becomes shared, data is immediately accessible',
            'Copy and restore without decryption requirements',
            'Direct access to database contents'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Copy snapshots with encryption enabled using KMS.',
          steps: [
            'Create encrypted copy of the snapshot',
            'Delete original unencrypted snapshot',
            'Enable encryption on the RDS instance',
            'Use customer-managed KMS keys'
          ],
          cliCommands: [
            'aws rds copy-db-snapshot --source-db-snapshot-identifier <SNAP_ID> --target-db-snapshot-identifier <SNAP_ID>-encrypted --kms-key-id <KEY_ID>',
            'aws rds delete-db-snapshot --db-snapshot-identifier <SNAP_ID>'
          ]
        }
      },
      'aws-secrets-no-rotation': {
        description: 'Secrets Manager secret does not have rotation enabled',
        severity: 'medium',
        mitre: ['T1552.004'],
        category: 'Security',
        exploitation: {
          overview: 'Static secrets increase risk window if compromised.',
          steps: [
            'Compromised secrets remain valid indefinitely',
            'No automatic detection of credential theft',
            'Historical access patterns may indicate compromise'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Enable automatic rotation with Lambda rotation functions.',
          steps: [
            'Configure rotation Lambda function',
            'Enable automatic rotation with schedule',
            'Test rotation process before enabling',
            'Monitor rotation success in CloudWatch'
          ],
          cliCommands: [
            'aws secretsmanager rotate-secret --secret-id <SECRET_ID> --rotation-lambda-arn <LAMBDA_ARN> --rotation-rules AutomaticallyAfterDays=30',
            'aws secretsmanager describe-secret --secret-id <SECRET_ID>'
          ]
        }
      },

      // Compute Rules
      'aws-lambda-public-url': {
        description: 'Lambda function has public URL without authentication',
        severity: 'high',
        mitre: ['T1190', 'T1133'],
        category: 'Serverless',
        exploitation: {
          overview: 'Public Lambda URLs can be invoked by anyone on the internet.',
          steps: [
            'Identify public Lambda URL endpoint',
            'Send requests directly to the URL: curl https://<url>.lambda-url.<region>.on.aws/',
            'Attempt injection attacks in function parameters',
            'If function has IAM role, actions execute with those permissions',
            'Enumerate accessible AWS resources through the function'
          ],
          tools: ['curl', 'Burp Suite', 'Pacu']
        },
        remediation: {
          overview: 'Add authentication to Lambda function URL or use API Gateway with authorization.',
          steps: [
            'Change function URL auth type to AWS_IAM',
            'Or use API Gateway with Cognito/IAM authorizers',
            'Implement input validation in function code',
            'Apply least-privilege IAM role to function',
            'Enable function-level logging and monitoring'
          ],
          cliCommands: [
            'aws lambda get-function-url-config --function-name <FUNCTION>',
            'aws lambda update-function-url-config --function-name <FUNCTION> --auth-type AWS_IAM'
          ]
        }
      },
      'aws-eks-public-endpoint': {
        description: 'EKS cluster API endpoint is publicly accessible',
        severity: 'high',
        mitre: ['T1190', 'T1133'],
        category: 'Compute',
        exploitation: {
          overview: 'Public Kubernetes API can be attacked directly from the internet.',
          steps: [
            'Scan for the public EKS endpoint',
            'Attempt authentication bypass or brute force',
            'Exploit Kubernetes vulnerabilities (CVEs)',
            'If access gained, deploy malicious pods',
            'Pivot to underlying EC2 instances and AWS resources'
          ],
          tools: ['kubectl', 'kube-hunter', 'kubiscan', 'Metasploit']
        },
        remediation: {
          overview: 'Disable public endpoint access and use private endpoint.',
          steps: [
            'Enable private endpoint access',
            'Disable public endpoint access',
            'Use VPN or bastion for cluster management',
            'Implement network policies in Kubernetes',
            'Enable audit logging'
          ],
          cliCommands: [
            'aws eks update-cluster-config --name <CLUSTER> --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true',
            'aws eks describe-cluster --name <CLUSTER> --query "cluster.resourcesVpcConfig"'
          ]
        }
      },
      'aws-codebuild-privileged-mode': {
        description: 'CodeBuild project runs in privileged mode with Docker access',
        severity: 'medium',
        mitre: ['T1611', 'T1610'],
        category: 'Compute',
        exploitation: {
          overview: 'Privileged mode allows container escape to the underlying host.',
          steps: [
            'Inject malicious build commands if build process is compromised',
            'Use Docker socket to spawn privileged containers',
            'Escape container to access host filesystem',
            'Access IMDS credentials from the host',
            'Pivot to other AWS resources'
          ],
          tools: ['Docker', 'deepce', 'container escape scripts']
        },
        remediation: {
          overview: 'Disable privileged mode unless absolutely required for Docker builds.',
          steps: [
            'Review if privileged mode is necessary',
            'Use separate dedicated build environment for Docker',
            'Implement least-privilege IAM role for CodeBuild',
            'Use AWS Secrets Manager for build secrets',
            'Enable CloudWatch logging for builds'
          ],
          cliCommands: [
            'aws codebuild update-project --name <PROJECT> --environment privilegedMode=false',
            'aws codebuild batch-get-projects --names <PROJECT> --query "projects[*].environment.privilegedMode"'
          ]
        }
      },
      'aws-codebuild-env-secrets': {
        description: 'CodeBuild project has secrets exposed in environment variables',
        severity: 'high',
        mitre: ['T1552.001', 'T1552.004'],
        category: 'Compute',
        exploitation: {
          overview: 'Environment variable secrets are logged and exposed in build logs.',
          steps: [
            'Access CodeBuild logs in CloudWatch or S3',
            'Search for environment variable dumps',
            'Extract hardcoded credentials, API keys, tokens',
            'Use extracted secrets to access other systems'
          ],
          tools: ['AWS CLI', 'grep', 'truffleHog']
        },
        remediation: {
          overview: 'Use Secrets Manager or Parameter Store for sensitive values.',
          steps: [
            'Migrate secrets to AWS Secrets Manager',
            'Update buildspec to use secrets-manager: references',
            'Remove plaintext secrets from project configuration',
            'Enable build log encryption',
            'Implement least-privilege access to secrets'
          ],
          cliCommands: [
            'aws codebuild batch-get-projects --names <PROJECT> --query "projects[*].environment.environmentVariables"',
            'aws secretsmanager create-secret --name <SECRET_NAME> --secret-string <VALUE>'
          ]
        }
      },
      'aws-ecr-cross-account-access': {
        description: 'ECR repository allows cross-account access',
        severity: 'medium',
        mitre: ['T1525', 'T1204.003'],
        category: 'Compute',
        exploitation: {
          overview: 'External accounts can pull container images, potentially containing secrets.',
          steps: [
            'Identify ECR repositories with cross-account policies',
            'Pull images from allowed external accounts',
            'Analyze image layers for embedded secrets',
            'Understand application architecture from images',
            'Potentially push malicious images if write access'
          ],
          tools: ['docker', 'dive', 'trivy', 'AWS CLI']
        },
        remediation: {
          overview: 'Restrict ECR repository policies to specific accounts and implement image scanning.',
          steps: [
            'Review repository policies for cross-account access',
            'Remove unnecessary cross-account permissions',
            'Use AWS Organizations conditions for org-only access',
            'Enable ECR image scanning',
            'Implement image signing with cosign'
          ],
          cliCommands: [
            'aws ecr get-repository-policy --repository-name <REPO>',
            'aws ecr set-repository-policy --repository-name <REPO> --policy-text file://restricted-policy.json'
          ]
        }
      },

      // Logging Rules
      'aws-logging-no-cloudtrail': {
        description: 'CloudTrail is not enabled, no API activity audit trail',
        severity: 'high',
        mitre: ['T1562.008'],
        category: 'Logging',
        exploitation: {
          overview: 'Without CloudTrail, attacker activities go undetected.',
          steps: [
            'Attackers operate without fear of detection',
            'No forensic evidence of malicious API calls',
            'Credential abuse and data exfiltration unlogged',
            'Compliance violations for most frameworks'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Enable CloudTrail in all regions with S3 logging.',
          steps: [
            'Create S3 bucket for CloudTrail logs',
            'Create CloudTrail trail for all regions',
            'Enable log file validation',
            'Enable CloudWatch Logs integration',
            'Set up SNS notifications for API activities',
            'Enable management and data events as needed'
          ],
          cliCommands: [
            'aws cloudtrail create-trail --name <TRAIL_NAME> --s3-bucket-name <BUCKET> --is-multi-region-trail --enable-log-file-validation',
            'aws cloudtrail start-logging --name <TRAIL_NAME>'
          ]
        }
      },
      'aws-logging-cloudtrail-not-logging': {
        description: 'CloudTrail trail exists but logging is disabled',
        severity: 'high',
        mitre: ['T1562.008'],
        category: 'Logging',
        exploitation: {
          overview: 'Disabled CloudTrail creates a blind spot for security monitoring.',
          steps: [
            'Attacker may have disabled logging after initial access',
            'Activities during disabled period are not recorded',
            'Indicator of compromise - check for unauthorized StopLogging calls'
          ],
          tools: ['AWS CLI']
        },
        remediation: {
          overview: 'Re-enable logging and investigate why it was disabled.',
          steps: [
            'Start logging immediately',
            'Review CloudTrail event history for StopLogging calls',
            'Implement SCP to prevent StopLogging',
            'Set up CloudWatch alarm for logging status changes',
            'Investigate potential compromise'
          ],
          cliCommands: [
            'aws cloudtrail start-logging --name <TRAIL_NAME>',
            'aws cloudtrail get-trail-status --name <TRAIL_NAME>'
          ]
        }
      },
      'aws-logging-no-guardduty': {
        description: 'GuardDuty is not enabled for threat detection',
        severity: 'medium',
        mitre: ['T1562.001'],
        category: 'Logging',
        exploitation: {
          overview: 'Without GuardDuty, many attack patterns go undetected.',
          steps: [
            'Cryptocurrency mining undetected',
            'Credential abuse not flagged',
            'Data exfiltration not identified',
            'Instance compromise not alerted'
          ],
          tools: []
        },
        remediation: {
          overview: 'Enable GuardDuty in all regions for threat detection.',
          steps: [
            'Enable GuardDuty detector in each region',
            'Configure SNS notifications for findings',
            'Set up automatic response with Lambda',
            'Enable S3 protection and EKS protection',
            'Consider GuardDuty for Organizations'
          ],
          cliCommands: [
            'aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES',
            'aws guardduty list-detectors'
          ]
        }
      },
      'aws-logging-no-config': {
        description: 'AWS Config is not enabled for configuration compliance',
        severity: 'medium',
        mitre: ['T1562.001'],
        category: 'Logging',
        exploitation: {
          overview: 'Without Config, configuration changes and compliance drift go untracked.',
          steps: [
            'No visibility into configuration changes over time',
            'Compliance violations not detected',
            'Resource inventory incomplete',
            'Forensic investigation more difficult'
          ],
          tools: []
        },
        remediation: {
          overview: 'Enable AWS Config to track configuration changes.',
          steps: [
            'Create S3 bucket for Config history',
            'Create Config recorder and delivery channel',
            'Enable recording for all resource types',
            'Deploy Config rules for compliance',
            'Set up remediation actions'
          ],
          cliCommands: [
            'aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=<ROLE_ARN>',
            'aws configservice start-configuration-recorder --configuration-recorder-name default'
          ]
        }
      },
      'aws-logging-cloudwatch-no-retention': {
        description: 'CloudWatch Log Group has no retention policy, logs stored indefinitely',
        severity: 'low',
        mitre: ['T1530'],
        category: 'Logging',
        exploitation: {
          overview: 'Indefinite log retention increases data exposure and costs.',
          steps: [
            'Historical logs may contain sensitive data',
            'If access is gained, years of logs may be available',
            'Increased cost from unlimited storage'
          ],
          tools: []
        },
        remediation: {
          overview: 'Set appropriate retention periods based on compliance requirements.',
          steps: [
            'Determine retention requirements for each log group',
            'Set retention policy (common: 90 days, 1 year)',
            'Consider exporting to S3 Glacier for long-term archival',
            'Automate retention policy deployment'
          ],
          cliCommands: [
            'aws logs put-retention-policy --log-group-name <LOG_GROUP> --retention-in-days 90',
            'aws logs describe-log-groups --query "logGroups[?retentionInDays==null].[logGroupName]"'
          ]
        }
      },

      // Generic/fallback rule
      'default': {
        description: 'Security finding detected',
        severity: 'medium',
        mitre: [],
        category: 'General',
        exploitation: {
          overview: 'This finding indicates a potential security issue that should be investigated.',
          steps: [
            'Review the specific resources involved in this finding',
            'Understand the attack path and potential impact',
            'Check for related misconfigurations'
          ],
          tools: ['AWS CLI', 'AWS Console']
        },
        remediation: {
          overview: 'Address the security misconfiguration based on the finding details.',
          steps: [
            'Review the finding details and affected resources',
            'Follow AWS security best practices',
            'Implement least-privilege access',
            'Enable logging and monitoring'
          ],
          cliCommands: []
        }
      },

      // ============ Aliases for backend rule names ============
      'assume-role-chain': {
        description: 'Principal can reach privileged roles through a chain of role assumptions',
        severity: 'high',
        mitre: ['T1078.004', 'T1550.001'],
        category: 'Privilege Escalation',
        exploitation: {
          overview: 'An attacker with access to the source principal can escalate privileges by assuming a chain of roles, ultimately gaining access to a highly privileged role.',
          steps: [
            'Authenticate as the source principal (e.g., IAM user)',
            'Use AWS STS to assume the first role in the chain: aws sts assume-role --role-arn <role1>',
            'Use the temporary credentials to assume subsequent roles',
            'Continue until reaching the target privileged role',
            'Execute privileged operations with the final role credentials'
          ],
          tools: ['AWS CLI', 'Pacu', 'enumerate-iam', 'ScoutSuite']
        },
        remediation: {
          overview: 'Break the role assumption chain by restricting trust policies and implementing proper access controls.',
          steps: [
            'Map out all role trust relationships in your account',
            'Identify and remove unnecessary role assumption paths',
            'Restrict trust policies to specific principals rather than wildcards',
            'Implement permission boundaries to limit what roles can do',
            'Add external ID requirements for cross-account role assumptions',
            'Enable CloudTrail logging for AssumeRole events'
          ],
          cliCommands: [
            'aws iam get-role --role-name <ROLE> --query "Role.AssumeRolePolicyDocument"',
            'aws iam update-assume-role-policy --role-name <ROLE> --policy-document file://restricted-trust.json'
          ]
        }
      },

      'open-sg': {
        description: 'Security group allows ingress from 0.0.0.0/0 (the entire internet)',
        severity: 'medium',
        mitre: ['T1190', 'T1133'],
        category: 'Network Exposure',
        exploitation: {
          overview: 'Instances in this security group are accessible from any IP on the internet, enabling attackers to directly target exposed services.',
          steps: [
            'Scan for open ports: nmap -Pn <public-ip>',
            'Identify running services on exposed ports',
            'Attempt exploitation of vulnerable services',
            'If SSH/RDP is exposed, attempt brute force or credential stuffing',
            'Look for default credentials or known vulnerabilities'
          ],
          tools: ['nmap', 'Metasploit', 'Hydra', 'Shodan']
        },
        remediation: {
          overview: 'Restrict security group ingress rules to specific IP ranges or remove public access entirely.',
          steps: [
            'Audit which services actually need public access',
            'Replace 0.0.0.0/0 with specific CIDR blocks (e.g., office IP ranges)',
            'Use AWS Systems Manager Session Manager instead of SSH/RDP',
            'Implement a bastion host or VPN for administrative access',
            'Enable VPC Flow Logs to monitor traffic'
          ],
          cliCommands: [
            'aws ec2 describe-security-groups --group-ids <SG-ID>',
            'aws ec2 revoke-security-group-ingress --group-id <SG-ID> --protocol tcp --port 22 --cidr 0.0.0.0/0',
            'aws ec2 authorize-security-group-ingress --group-id <SG-ID> --protocol tcp --port 22 --cidr <YOUR-IP>/32'
          ]
        }
      },

      'public-s3': {
        description: 'S3 bucket or resource policy allows public access (Principal: "*")',
        severity: 'high',
        mitre: ['T1530', 'T1537'],
        category: 'Data Exposure',
        exploitation: {
          overview: 'The resource is accessible without authentication. Attackers can list, read, or potentially modify data depending on the permissions granted.',
          steps: [
            'Enumerate public buckets using tools or manual testing',
            'List bucket contents: aws s3 ls s3://<bucket> --no-sign-request',
            'Download sensitive files: aws s3 cp s3://<bucket>/<key> . --no-sign-request',
            'Check for sensitive data (credentials, PII, backups)',
            'If write access exists, attempt to upload malicious content'
          ],
          tools: ['AWS CLI', 'S3Scanner', 'Bucket Finder', 'Grayhat Warfare']
        },
        remediation: {
          overview: 'Remove public access and implement proper access controls with S3 Block Public Access.',
          steps: [
            'Enable S3 Block Public Access at account level',
            'Remove "Principal": "*" from bucket policies',
            'Use IAM policies for access control instead of bucket policies',
            'Enable S3 server access logging',
            'Consider using S3 Object Lock for sensitive data',
            'Implement bucket versioning for recovery'
          ],
          cliCommands: [
            'aws s3api get-bucket-policy --bucket <BUCKET>',
            'aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
            'aws s3api delete-bucket-policy --bucket <BUCKET>'
          ]
        }
      },

      'kms-cross-account': {
        description: 'KMS key policy allows access from external AWS accounts',
        severity: 'medium',
        mitre: ['T1552.005', 'T1078.004'],
        category: 'Cross-Account Access',
        exploitation: {
          overview: 'External accounts can use this KMS key to decrypt data or perform cryptographic operations, potentially accessing sensitive encrypted data.',
          steps: [
            'From the trusted external account, attempt to use the KMS key',
            'Decrypt data encrypted with this key: aws kms decrypt --key-id <key-arn> --ciphertext-blob <blob>',
            'If the key encrypts S3 objects, access the encrypted data',
            'Generate data keys for encryption/decryption: aws kms generate-data-key',
            'Look for EBS volumes or RDS instances encrypted with this key'
          ],
          tools: ['AWS CLI', 'Pacu']
        },
        remediation: {
          overview: 'Restrict KMS key policy to only necessary principals and implement proper cross-account controls.',
          steps: [
            'Audit which external accounts have access to the key',
            'Remove unnecessary cross-account principals from key policy',
            'Use grants instead of key policies for temporary access',
            'Implement key policy conditions (aws:PrincipalOrgID, etc.)',
            'Enable CloudTrail logging for KMS operations',
            'Consider using separate keys per environment/account'
          ],
          cliCommands: [
            'aws kms get-key-policy --key-id <KEY-ID> --policy-name default',
            'aws kms put-key-policy --key-id <KEY-ID> --policy-name default --policy file://restricted-policy.json',
            'aws kms list-grants --key-id <KEY-ID>'
          ]
        }
      },

      'imds-exposure': {
        description: 'Public EC2 instance with IAM role attached - IMDS credential theft risk',
        severity: 'medium',
        mitre: ['T1552.005', 'T1078.004'],
        category: 'Credential Exposure',
        exploitation: {
          overview: 'A publicly accessible EC2 instance with an IAM role can be exploited via SSRF or RCE to steal temporary credentials from the Instance Metadata Service (IMDS).',
          steps: [
            'Identify SSRF or RCE vulnerability in application on the instance',
            'Access IMDSv1: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>',
            'For IMDSv2, first get token: curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"',
            'Extract AccessKeyId, SecretAccessKey, and Token',
            'Use stolen credentials from attacker machine'
          ],
          tools: ['curl', 'AWS CLI', 'Pacu', 'Metasploit']
        },
        remediation: {
          overview: 'Enable IMDSv2 (requires token) and restrict the IAM role permissions to minimum necessary.',
          steps: [
            'Enable IMDSv2 requirement on all instances',
            'Set HttpTokens to "required" in instance metadata options',
            'Review and minimize IAM role permissions',
            'Implement VPC endpoints to reduce need for public instances',
            'Use AWS Systems Manager Session Manager instead of SSH',
            'Enable GuardDuty for anomalous credential usage detection'
          ],
          cliCommands: [
            'aws ec2 modify-instance-metadata-options --instance-id <INSTANCE-ID> --http-tokens required --http-endpoint enabled',
            'aws ec2 describe-instances --instance-ids <INSTANCE-ID> --query "Reservations[].Instances[].MetadataOptions"'
          ]
        }
      },

      'PrivilegeEscalation': {
        description: 'Principal can escalate to higher privileges through role assumption or other means',
        severity: 'high',
        mitre: ['T1078.004', 'T1548'],
        category: 'Privilege Escalation',
        exploitation: {
          overview: 'The principal can escalate their privileges to gain administrative or elevated access within the AWS account.',
          steps: [
            'Identify the privilege escalation path from the attack path details',
            'Assume the target role: aws sts assume-role --role-arn <target-role>',
            'Use the escalated credentials to access protected resources',
            'Enumerate additional permissions with the new access',
            'Look for further escalation paths or sensitive data access'
          ],
          tools: ['AWS CLI', 'Pacu', 'enumerate-iam', 'PMapper']
        },
        remediation: {
          overview: 'Remove unnecessary privilege escalation paths and implement least-privilege access.',
          steps: [
            'Review and restrict the trust policy on the target role',
            'Remove unnecessary sts:AssumeRole permissions',
            'Implement permission boundaries on IAM entities',
            'Use Service Control Policies (SCPs) in AWS Organizations',
            'Enable and monitor CloudTrail for AssumeRole events',
            'Regular access reviews and unused permission cleanup'
          ],
          cliCommands: [
            'aws iam get-role --role-name <ROLE> --query "Role.AssumeRolePolicyDocument"',
            'aws iam list-attached-user-policies --user-name <USER>',
            'aws iam update-assume-role-policy --role-name <ROLE> --policy-document file://restricted-trust.json'
          ]
        }
      }
    };

    // ============ Graph Analysis State (BloodHound-style) ============
    const graphAnalysisState = {
      sourceNode: null,
      targetNode: null,
      ownedNodes: new Set(),
      highValueNodes: new Set(),
      detectedHighValueNodes: new Set(),
      pathResults: [],
      queryMode: null,
      lastQuery: null
    };

    // ============ High-Value Target Detection Patterns ============
    // These patterns identify AWS resources that are high-priority targets for attackers
    const highValuePatterns = {
      // Administrative access - highest priority
      adminRoles: {
        category: 'Admin Privileges',
        priority: 1,
        patterns: [
          /administratoraccess/i,
          /admin[-_]?role/i,
          /poweruser/i,
          /:role\/admin/i,
          /fullaccess/i,
          /is_admin.*true/i
        ],
        propertyChecks: [
          (node) => node.data('is_admin') === true,
          (node) => (node.data('role_name') || '').toLowerCase().includes('admin'),
          (node) => (node.data('policies') || []).some(p => p.includes('AdministratorAccess'))
        ]
      },
      // Secrets and credentials
      secrets: {
        category: 'Secrets/Keys',
        priority: 2,
        patterns: [
          /secretsmanager/i,
          /ssm.*parameter/i,
          /:secret:/i,
          /:parameter\//i,
          /kms.*key/i,
          /:key\//i
        ],
        types: ['Secret', 'Parameter', 'KMSKey', 'Key']
      },
      // Data stores with sensitive information
      dataStores: {
        category: 'Data Stores',
        priority: 3,
        patterns: [
          /:rds:/i,
          /:dynamodb:/i,
          /:redshift:/i,
          /:s3:::/i,
          /:elasticache:/i,
          /database/i,
          /backup/i,
          /-db-/i,
          /-prod-/i,
          /production/i
        ],
        types: ['RDSInstance', 'DynamoDBTable', 'S3Bucket', 'RedshiftCluster', 'Database']
      },
      // Compute with high privileges
      privilegedCompute: {
        category: 'Privileged Compute',
        priority: 4,
        patterns: [
          /lambda.*admin/i,
          /bastion/i,
          /jumpbox/i,
          /management/i
        ],
        propertyChecks: [
          (node) => node.data('type') === 'Lambda' && node.outgoers('edge').some(e =>
            e.data('target')?.includes('AdministratorAccess') || e.data('target')?.includes('admin'))
        ]
      },
      // Identity providers and SSO
      identityProviders: {
        category: 'Identity/SSO',
        priority: 2,
        patterns: [
          /saml-provider/i,
          /oidc-provider/i,
          /identity-provider/i,
          /sso/i,
          /:iam::.*:user\//i
        ],
        types: ['SAMLProvider', 'OIDCProvider', 'IdentityProvider']
      },
      // Network boundary resources
      networkBoundary: {
        category: 'Network Boundary',
        priority: 5,
        patterns: [
          /internet/i,
          /nat-gateway/i,
          /internet-gateway/i,
          /load-balancer/i,
          /cloudfront/i,
          /api-gateway/i
        ],
        types: ['InternetGateway', 'NATGateway', 'LoadBalancer', 'CloudFront', 'APIGateway']
      },
      // Cross-account trust
      crossAccountTrust: {
        category: 'Cross-Account',
        priority: 3,
        propertyChecks: [
          (node) => {
            const trustPolicy = node.data('assume_role_policy') || '';
            // Check if trust policy references external accounts
            const accountMatch = trustPolicy.match(/\d{12}/g);
            if (accountMatch) {
              const currentAccount = extractAccountId(node.id());
              return accountMatch.some(acc => acc !== currentAccount);
            }
            return false;
          }
        ]
      }
    };

    // Identify internet-exposed entry points
    const internetEntryPoints = [
      'internet',
      'imds:cred-theft',
      /0\.0\.0\.0\/0/,
      /public/i,
      /:policy$/  // Resource policies often indicate public access
    ];

    // Initialize filter UI
    function initFilters() {
      // Collapsible sections
      document.querySelectorAll('.filter-header').forEach(header => {
        header.addEventListener('click', () => {
          const section = header.dataset.section;
          const content = document.getElementById(`${section}Content`);
          if (content) {
            header.classList.toggle('collapsed');
            content.classList.toggle('hidden');
          }
        });
      });

      // Severity chips
      document.querySelectorAll('.severity-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          chip.classList.toggle('selected');
          const severity = chip.dataset.severity;
          if (chip.classList.contains('selected')) {
            if (!filterState.severity.includes(severity)) {
              filterState.severity.push(severity);
            }
          } else {
            filterState.severity = filterState.severity.filter(s => s !== severity);
          }
          updateActiveFiltersBar();
        });
      });

      // Security toggles with active state styling
      document.getElementById('hasAttackPathsToggle').addEventListener('change', (e) => {
        filterState.hasAttackPaths = e.target.checked;
        e.target.closest('.toggle-row')?.classList.toggle('active', e.target.checked);
        updateActiveFiltersBar();
      });

      document.getElementById('publicExposureToggle').addEventListener('change', (e) => {
        filterState.publicExposure = e.target.checked;
        e.target.closest('.toggle-row')?.classList.toggle('active', e.target.checked);
        updateActiveFiltersBar();
      });

      document.getElementById('misconfiguredToggle').addEventListener('change', (e) => {
        filterState.misconfigured = e.target.checked;
        e.target.closest('.toggle-row')?.classList.toggle('active', e.target.checked);
        updateActiveFiltersBar();
      });

      // Search input
      document.getElementById('searchInput').addEventListener('input', (e) => {
        filterState.searchText = e.target.value;
        updateActiveFiltersBar();
      });

      // Multi-select dropdowns
      initMultiSelect('type', 'resourceTypes');
      initMultiSelect('provider', 'providers');
      initMultiSelect('region', 'regions');
      initMultiSelect('edgeType', 'edgeTypes');
      initMultiSelect('attackRule', 'attackRules');

      // Category chips
      document.querySelectorAll('.category-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          chip.classList.toggle('selected');
          const category = chip.dataset.category;
          if (chip.classList.contains('selected')) {
            if (!filterState.resourceCategories.includes(category)) {
              filterState.resourceCategories.push(category);
            }
          } else {
            filterState.resourceCategories = filterState.resourceCategories.filter(c => c !== category);
          }
          updateActiveFiltersBar();
        });
      });

      // MITRE tactic chips
      document.querySelectorAll('.mitre-tactic').forEach(chip => {
        chip.addEventListener('click', () => {
          chip.classList.toggle('selected');
          const tactic = chip.dataset.tactic;
          if (chip.classList.contains('selected')) {
            if (!filterState.mitreTactics.includes(tactic)) {
              filterState.mitreTactics.push(tactic);
            }
          } else {
            filterState.mitreTactics = filterState.mitreTactics.filter(t => t !== tactic);
          }
          updateActiveFiltersBar();
        });
      });

      // Presets
      document.querySelectorAll('.saved-filter-item[data-preset]').forEach(item => {
        item.addEventListener('click', () => {
          const presetKey = item.dataset.preset;
          const preset = filterPresets[presetKey];
          if (preset) {
            applyPreset(preset.filters);
          }
        });
      });

      // Clear all filters
      document.getElementById('clearAllFiltersBtn').addEventListener('click', clearAllFilters);

      // Save filter button
      document.getElementById('saveFilterBtn').addEventListener('click', saveCurrentFilter);

      // Load saved filters
      renderSavedFilters();
    }

    function initMultiSelect(name, stateKey) {
      const trigger = document.getElementById(`${name}Trigger`);
      const dropdown = document.getElementById(`${name}Dropdown`);
      const searchInput = document.getElementById(`${name}SearchInput`);

      if (!trigger || !dropdown) return;

      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        // Close other dropdowns
        document.querySelectorAll('.multi-select-dropdown').forEach(d => {
          if (d.id !== `${name}Dropdown`) d.classList.add('hidden');
        });
        dropdown.classList.toggle('hidden');
        trigger.classList.toggle('open');
        if (searchInput && !dropdown.classList.contains('hidden')) {
          searchInput.focus();
        }
      });

      // Close on outside click
      document.addEventListener('click', (e) => {
        if (!trigger.contains(e.target) && !dropdown.contains(e.target)) {
          dropdown.classList.add('hidden');
          trigger.classList.remove('open');
        }
      });

      // Search filtering
      if (searchInput) {
        searchInput.addEventListener('input', (e) => {
          const query = e.target.value.toLowerCase();
          const options = dropdown.querySelectorAll('.multi-select-option');
          options.forEach(opt => {
            const label = opt.textContent.toLowerCase();
            opt.style.display = label.includes(query) ? 'flex' : 'none';
          });
        });
      }
    }

    function updateMultiSelectOptions(name, options, stateKey) {
      const optionsContainer = document.getElementById(`${name}Options`);
      if (!optionsContainer) return;

      optionsContainer.innerHTML = options.map(opt => `
        <div class="multi-select-option ${filterState[stateKey].includes(opt) ? 'selected' : ''}" data-value="${opt}">
          <input type="checkbox" ${filterState[stateKey].includes(opt) ? 'checked' : ''}>
          <span>${opt}</span>
        </div>
      `).join('');

      // Add click handlers
      optionsContainer.querySelectorAll('.multi-select-option').forEach(option => {
        option.addEventListener('click', () => {
          const value = option.dataset.value;
          const checkbox = option.querySelector('input[type="checkbox"]');

          if (filterState[stateKey].includes(value)) {
            filterState[stateKey] = filterState[stateKey].filter(v => v !== value);
            option.classList.remove('selected');
            checkbox.checked = false;
          } else {
            filterState[stateKey].push(value);
            option.classList.add('selected');
            checkbox.checked = true;
          }

          updateMultiSelectTrigger(name, stateKey);
          updateActiveFiltersBar();
        });
      });
    }

    function updateMultiSelectTrigger(name, stateKey) {
      const trigger = document.getElementById(`${name}Trigger`);
      const tagsContainer = trigger.querySelector('.multi-select-tags');
      const selected = filterState[stateKey];

      if (selected.length === 0) {
        const placeholders = {
          type: 'Select types...',
          provider: 'All providers',
          region: 'All regions'
        };
        tagsContainer.innerHTML = `<span class="multi-select-placeholder">${placeholders[name] || 'Select...'}</span>`;
      } else {
        tagsContainer.innerHTML = selected.map(v => `
          <span class="multi-select-tag">
            ${v}
            <span class="remove" data-value="${v}" data-key="${stateKey}">&times;</span>
          </span>
        `).join('');

        // Add remove handlers
        tagsContainer.querySelectorAll('.remove').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const value = btn.dataset.value;
            const key = btn.dataset.key;
            filterState[key] = filterState[key].filter(v => v !== value);
            updateMultiSelectTrigger(name, key);
            updateMultiSelectOptions(name, name === 'type' ? availableTypes : (name === 'region' ? availableRegions : ['aws', 'gcp', 'azure']), key);
            updateActiveFiltersBar();
          });
        });
      }
    }

    function updateActiveFiltersBar() {
      const bar = document.getElementById('activeFiltersBar');
      const chipsContainer = document.getElementById('activeFiltersChips');
      const countBadge = document.getElementById('activeFiltersCount');
      const clearLink = document.getElementById('clearAllFiltersLink');
      const tags = [];

      // Category labels for better UX
      const categoryLabels = {
        searchText: 'Search',
        resourceTypes: 'Type',
        severity: 'Severity',
        providers: 'Provider',
        regions: 'Region',
        edgeTypes: 'Edge',
        attackRules: 'Rule',
        mitreTactics: 'MITRE',
        resourceCategories: 'Category',
        hasAttackPaths: 'Security',
        publicExposure: 'Security',
        misconfigured: 'Security'
      };

      if (filterState.searchText) {
        tags.push({ category: 'Search', label: filterState.searchText, key: 'searchText' });
      }

      filterState.resourceTypes.forEach(t => {
        tags.push({ category: 'Type', label: t, key: 'resourceTypes', value: t });
      });

      filterState.resourceCategories.forEach(c => {
        tags.push({ category: 'Category', label: c, key: 'resourceCategories', value: c });
      });

      filterState.severity.forEach(s => {
        tags.push({ category: 'Severity', label: s.charAt(0).toUpperCase() + s.slice(1), key: 'severity', value: s });
      });

      filterState.providers.forEach(p => {
        tags.push({ category: 'Provider', label: p.toUpperCase(), key: 'providers', value: p });
      });

      filterState.regions.forEach(r => {
        tags.push({ category: 'Region', label: r, key: 'regions', value: r });
      });

      filterState.edgeTypes.forEach(e => {
        tags.push({ category: 'Edge', label: e, key: 'edgeTypes', value: e });
      });

      filterState.attackRules.forEach(r => {
        tags.push({ category: 'Rule', label: r, key: 'attackRules', value: r });
      });

      filterState.mitreTactics.forEach(t => {
        const tacticName = mitreTactics[t]?.name || t;
        tags.push({ category: 'MITRE', label: tacticName, key: 'mitreTactics', value: t });
      });

      if (filterState.hasAttackPaths) {
        tags.push({ category: 'Security', label: 'Has Attack Paths', key: 'hasAttackPaths' });
      }

      if (filterState.publicExposure) {
        tags.push({ category: 'Security', label: 'Public Exposure', key: 'publicExposure' });
      }

      if (filterState.misconfigured) {
        tags.push({ category: 'Security', label: 'Misconfigured', key: 'misconfigured' });
      }

      // Update filter count badges on section headers
      updateFilterSectionCounts();

      if (tags.length === 0) {
        bar.classList.add('hidden');
        return;
      }

      bar.classList.remove('hidden');
      countBadge.textContent = tags.length;

      // Render chips with category labels
      chipsContainer.innerHTML = tags.map(tag => `
        <span class="active-filter-tag" data-key="${tag.key}" data-value="${tag.value || ''}">
          <span class="filter-category">${tag.category}</span>
          <span class="filter-value">${tag.label}</span>
          <span class="remove" title="Remove filter">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </span>
        </span>
      `).join('');

      // Add remove handlers
      chipsContainer.querySelectorAll('.active-filter-tag').forEach(tag => {
        const removeBtn = tag.querySelector('.remove');
        removeBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const key = tag.dataset.key;
          const value = tag.dataset.value;

          if (value) {
            filterState[key] = filterState[key].filter(v => v !== value);
            // Update UI based on filter type
            if (key === 'severity') {
              document.querySelector(`.severity-chip[data-severity="${value}"]`)?.classList.remove('selected');
            } else if (key === 'resourceCategories') {
              document.querySelector(`.category-chip[data-category="${value}"]`)?.classList.remove('selected');
            } else if (key === 'mitreTactics') {
              document.querySelector(`.mitre-tactic[data-tactic="${value}"]`)?.classList.remove('selected');
            } else if (key === 'resourceTypes') {
              updateMultiSelectTrigger('type', 'resourceTypes');
              updateMultiSelectOptions('type', availableTypes, 'resourceTypes');
            } else if (key === 'providers') {
              updateMultiSelectTrigger('provider', 'providers');
            } else if (key === 'regions') {
              updateMultiSelectTrigger('region', 'regions');
              updateMultiSelectOptions('region', availableRegions, 'regions');
            } else if (key === 'edgeTypes') {
              updateMultiSelectTrigger('edgeType', 'edgeTypes');
              updateMultiSelectOptions('edgeType', availableEdgeTypes, 'edgeTypes');
            } else if (key === 'attackRules') {
              updateMultiSelectTrigger('attackRule', 'attackRules');
              updateMultiSelectOptions('attackRule', availableAttackRules, 'attackRules');
            }
          } else {
            if (key === 'searchText') {
              filterState.searchText = '';
              document.getElementById('searchInput').value = '';
            } else {
              filterState[key] = false;
              const toggle = document.getElementById(`${key}Toggle`);
              if (toggle) toggle.checked = false;
            }
          }

          updateActiveFiltersBar();
        });
      });

      // Clear all link handler
      if (clearLink) {
        clearLink.onclick = clearAllFilters;
      }
    }

    // Update count badges on filter section headers
    function updateFilterSectionCounts() {
      const sectionCounts = {
        'types': filterState.resourceTypes.length,
        'severity': filterState.severity.length,
        'provider': filterState.providers.length,
        'security': (filterState.hasAttackPaths ? 1 : 0) + (filterState.publicExposure ? 1 : 0) + (filterState.misconfigured ? 1 : 0),
        'category': filterState.resourceCategories.length,
        'edgeType': filterState.edgeTypes.length,
        'attackRule': filterState.attackRules.length,
        'mitre': filterState.mitreTactics.length,
        'region': filterState.regions.length
      };

      Object.entries(sectionCounts).forEach(([section, count]) => {
        const header = document.querySelector(`.filter-header[data-section="${section}"]`);
        if (header) {
          let badge = header.querySelector('.filter-count');
          if (!badge) {
            badge = document.createElement('span');
            badge.className = 'filter-count hidden';
            header.querySelector('.filter-title').appendChild(badge);
          }

          if (count > 0) {
            badge.textContent = count;
            badge.classList.remove('hidden');
          } else {
            badge.classList.add('hidden');
          }
        }
      });
    }

    function clearAllFilters() {
      filterState.searchText = '';
      filterState.resourceTypes = [];
      filterState.resourceCategories = [];
      filterState.severity = [];
      filterState.providers = [];
      filterState.regions = [];
      filterState.edgeTypes = [];
      filterState.attackRules = [];
      filterState.mitreTactics = [];
      filterState.hasAttackPaths = false;
      filterState.publicExposure = false;
      filterState.misconfigured = false;

      // Reset UI
      document.getElementById('searchInput').value = '';
      document.querySelectorAll('.severity-chip').forEach(c => c.classList.remove('selected'));
      document.querySelectorAll('.category-chip').forEach(c => c.classList.remove('selected'));
      document.querySelectorAll('.mitre-tactic').forEach(c => c.classList.remove('selected'));
      document.querySelectorAll('.toggle-row').forEach(r => r.classList.remove('active'));
      document.getElementById('hasAttackPathsToggle').checked = false;
      document.getElementById('publicExposureToggle').checked = false;
      document.getElementById('misconfiguredToggle').checked = false;

      updateMultiSelectTrigger('type', 'resourceTypes');
      updateMultiSelectTrigger('provider', 'providers');
      updateMultiSelectTrigger('region', 'regions');
      updateMultiSelectTrigger('edgeType', 'edgeTypes');
      updateMultiSelectTrigger('attackRule', 'attackRules');
      updateActiveFiltersBar();

      // Rebuild graph with no filters
      if (nodes.length || edges.length) {
        buildGraph(nodes, edges);
        renderAttacks(edges);
      }
    }

    function applyPreset(filters) {
      clearAllFilters();

      if (filters.severity) {
        filterState.severity = [...filters.severity];
        filters.severity.forEach(s => {
          document.querySelector(`.severity-chip[data-severity="${s}"]`)?.classList.add('selected');
        });
      }

      if (filters.resourceTypes) {
        filterState.resourceTypes = [...filters.resourceTypes];
        updateMultiSelectTrigger('type', 'resourceTypes');
      }

      if (filters.resourceCategories) {
        filterState.resourceCategories = [...filters.resourceCategories];
        filters.resourceCategories.forEach(cat => {
          document.querySelector(`.category-chip[data-category="${cat}"]`)?.classList.add('selected');
        });
      }

      if (filters.edgeTypes) {
        filterState.edgeTypes = [...filters.edgeTypes];
        updateMultiSelectTrigger('edgeType', 'edgeTypes');
      }

      if (filters.attackRules) {
        filterState.attackRules = [...filters.attackRules];
        updateMultiSelectTrigger('attackRule', 'attackRules');
      }

      if (filters.mitreTactics) {
        filterState.mitreTactics = [...filters.mitreTactics];
        filters.mitreTactics.forEach(tactic => {
          document.querySelector(`.mitre-tactic[data-tactic="${tactic}"]`)?.classList.add('selected');
        });
      }

      if (filters.hasAttackPaths) {
        filterState.hasAttackPaths = true;
        const toggle = document.getElementById('hasAttackPathsToggle');
        toggle.checked = true;
        toggle.closest('.toggle-row')?.classList.add('active');
      }

      if (filters.publicExposure) {
        filterState.publicExposure = true;
        const toggle = document.getElementById('publicExposureToggle');
        toggle.checked = true;
        toggle.closest('.toggle-row')?.classList.add('active');
      }

      if (filters.misconfigured) {
        filterState.misconfigured = true;
        const toggle = document.getElementById('misconfiguredToggle');
        toggle.checked = true;
        toggle.closest('.toggle-row')?.classList.add('active');
      }

      if (filters.searchText) {
        filterState.searchText = filters.searchText;
        document.getElementById('searchInput').value = filters.searchText;
      }

      updateActiveFiltersBar();

      // Apply filters and refresh graph
      if (nodes.length || edges.length) {
        const filtered = applyFilters(nodes, edges);
        buildGraph(filtered.nodes, filtered.edges);
        renderAttacks(filtered.edges);
        showMessage(`Filters applied: ${filtered.nodes.length} nodes, ${filtered.edges.length} edges`, 'success');
      }
    }

    function saveCurrentFilter() {
      const name = prompt('Enter a name for this filter set:');
      if (!name) return;

      const filter = {
        id: Date.now().toString(),
        name,
        filters: { ...filterState }
      };

      savedFilters.push(filter);
      localStorage.setItem('arguscloud_saved_filters', JSON.stringify(savedFilters));
      renderSavedFilters();
      showMessage(`Filter "${name}" saved`, 'success');
    }

    function renderSavedFilters() {
      const container = document.getElementById('savedFiltersList');
      if (!container) return;

      if (savedFilters.length === 0) {
        container.innerHTML = '<div style="font-size: 11px; color: var(--text-muted); padding: 4px;">No saved filters</div>';
        return;
      }

      container.innerHTML = savedFilters.map(f => `
        <div class="saved-filter-item" data-filter-id="${f.id}">
          <span>${f.name}</span>
          <div class="saved-filter-actions">
            <button class="btn btn-sm btn-ghost delete-filter" data-id="${f.id}" title="Delete">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>
        </div>
      `).join('');

      // Add click handlers
      container.querySelectorAll('.saved-filter-item').forEach(item => {
        item.addEventListener('click', (e) => {
          if (e.target.closest('.delete-filter')) return;
          const id = item.dataset.filterId;
          const filter = savedFilters.find(f => f.id === id);
          if (filter) {
            applyPreset(filter.filters);
          }
        });
      });

      container.querySelectorAll('.delete-filter').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const id = btn.dataset.id;
          savedFilters = savedFilters.filter(f => f.id !== id);
          localStorage.setItem('arguscloud_saved_filters', JSON.stringify(savedFilters));
          renderSavedFilters();
        });
      });
    }

    function updateAvailableFilterOptions() {
      // Extract unique types from nodes
      const types = new Set();
      const regions = new Set();
      const edgeTypesSet = new Set();
      const attackRulesSet = new Set();

      nodes.forEach(node => {
        if (node.type) types.add(node.type);
        const region = node.properties?.region;
        if (region) regions.add(region);
      });

      // Extract edge types and attack rules from edges
      edges.forEach(edge => {
        if (edge.type) edgeTypesSet.add(edge.type);
        if (edge.type === 'AttackPath' && edge.properties?.rule) {
          attackRulesSet.add(edge.properties.rule);
        }
      });

      availableTypes = Array.from(types).sort();
      availableRegions = Array.from(regions).sort();
      availableEdgeTypes = Array.from(edgeTypesSet).sort();
      availableAttackRules = Array.from(attackRulesSet).sort();

      updateMultiSelectOptions('type', availableTypes, 'resourceTypes');
      updateMultiSelectOptions('region', availableRegions, 'regions');
      updateMultiSelectOptions('edgeType', availableEdgeTypes, 'edgeTypes');
      updateMultiSelectOptions('attackRule', availableAttackRules, 'attackRules');
    }

    function applyFilters(nodesList, edgesList) {
      let filteredNodes = [...nodesList];
      let filteredEdges = [...edgesList];

      // Search text filter
      if (filterState.searchText) {
        const query = filterState.searchText.toLowerCase();
        filteredNodes = filteredNodes.filter(n => {
          const id = (n.id || '').toLowerCase();
          const name = (n.properties?.name || '').toLowerCase();
          const arn = (n.properties?.arn || '').toLowerCase();
          const type = (n.type || '').toLowerCase();
          return id.includes(query) || name.includes(query) || arn.includes(query) || type.includes(query);
        });
      }

      // Resource type filter
      if (filterState.resourceTypes.length > 0) {
        filteredNodes = filteredNodes.filter(n => filterState.resourceTypes.includes(n.type));
      }

      // Resource category filter (maps categories to types)
      if (filterState.resourceCategories.length > 0) {
        const allowedTypes = new Set();
        filterState.resourceCategories.forEach(cat => {
          const types = resourceCategories[cat] || [];
          types.forEach(t => allowedTypes.add(t));
        });
        filteredNodes = filteredNodes.filter(n => allowedTypes.has(n.type));
      }

      // Provider filter
      if (filterState.providers.length > 0) {
        filteredNodes = filteredNodes.filter(n => filterState.providers.includes(n.provider));
      }

      // Region filter
      if (filterState.regions.length > 0) {
        filteredNodes = filteredNodes.filter(n => filterState.regions.includes(n.properties?.region));
      }

      // Edge type filter - filter edges by relationship type
      if (filterState.edgeTypes.length > 0) {
        filteredEdges = filteredEdges.filter(e => filterState.edgeTypes.includes(e.type));
      }

      // Attack rule filter - filter attack path edges by rule
      if (filterState.attackRules.length > 0) {
        filteredEdges = filteredEdges.filter(e => {
          if (e.type !== 'AttackPath') return true; // Keep non-attack edges
          const rule = e.properties?.rule;
          return rule && filterState.attackRules.includes(rule);
        });
      }

      // Severity filter for edges
      if (filterState.severity.length > 0) {
        filteredEdges = filteredEdges.filter(e => {
          if (e.type !== 'AttackPath') return true; // Keep non-attack edges
          const sev = (e.properties?.severity || '').toLowerCase();
          return filterState.severity.includes(sev);
        });
      }

      // MITRE ATT&CK tactic filter
      if (filterState.mitreTactics.length > 0) {
        filteredEdges = filteredEdges.filter(e => {
          if (e.type !== 'AttackPath') return true; // Keep non-attack edges
          const rule = e.properties?.rule;
          if (!rule) return false;
          const tactics = attackRuleToTactic[rule] || [];
          return tactics.some(t => filterState.mitreTactics.includes(t));
        });
      }

      // Has attack paths - show only nodes involved in attack paths
      if (filterState.hasAttackPaths) {
        const attackPaths = filteredEdges.filter(e => e.type === 'AttackPath');
        const nodesWithAttacks = new Set();
        attackPaths.forEach(e => {
          nodesWithAttacks.add(e.src);
          nodesWithAttacks.add(e.dst);
        });
        filteredNodes = filteredNodes.filter(n => nodesWithAttacks.has(n.id));
      }

      // Public exposure filter - show only publicly accessible resources
      if (filterState.publicExposure) {
        const publicRules = ['public-s3', 'open-sg', 'public-snapshot', 'imds-exposure'];
        const publicEdges = edgesList.filter(e =>
          e.type === 'AttackPath' && publicRules.includes(e.properties?.rule)
        );
        const publicNodes = new Set();
        publicEdges.forEach(e => {
          publicNodes.add(e.src);
          publicNodes.add(e.dst);
        });
        filteredNodes = filteredNodes.filter(n => publicNodes.has(n.id));
      }

      // Misconfigured filter - show only nodes with any attack path
      if (filterState.misconfigured) {
        const attackPaths = edgesList.filter(e => e.type === 'AttackPath');
        const misconfiguredNodes = new Set();
        attackPaths.forEach(e => {
          misconfiguredNodes.add(e.src);
          misconfiguredNodes.add(e.dst);
        });
        filteredNodes = filteredNodes.filter(n => misconfiguredNodes.has(n.id));
      }

      // Filter edges to only include those between filtered nodes
      const nodeIds = new Set(filteredNodes.map(n => n.id));
      filteredEdges = filteredEdges.filter(e => nodeIds.has(e.src) && nodeIds.has(e.dst));

      return { nodes: filteredNodes, edges: filteredEdges };
    }

    // ============ Profile Management ============

    async function loadProfiles() {
      const base = document.getElementById('apiBase').value;
      try {
        const resp = await fetch(`${base}/profiles`);
        if (!resp.ok) throw new Error('Failed to load profiles');
        const data = await resp.json();
        profiles = data.profiles || [];
        updateProfileDropdown();
      } catch (err) {
        console.error('Error loading profiles:', err);
        profiles = [];
        updateProfileDropdown();
      }
    }

    function updateProfileDropdown() {
      const select = document.getElementById('profileSelect');
      const currentValue = select.value;

      select.innerHTML = '<option value="">-- No Profile --</option>';
      for (const profile of profiles) {
        const option = document.createElement('option');
        option.value = profile.name;
        option.textContent = `${profile.name} (${profile.node_count || 0} nodes)`;
        select.appendChild(option);
      }

      // Restore selection if still valid
      if (currentValue && profiles.some(p => p.name === currentValue)) {
        select.value = currentValue;
      }
    }

    async function loadProfile(name) {
      if (!name) {
        // Clear data when "No Profile" selected
        nodes = [];
        edges = [];
        currentProfile = null;
        localStorage.removeItem('arguscloud_last_profile');
        if (cy) {
          cy.destroy();
          cy = null;
        }
        document.getElementById('cy').innerHTML = '<div class="empty-state" style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-tertiary);">Select a profile or load data</div>';
        document.querySelector('#attacksTable tbody').innerHTML = '<tr><td colspan="5" class="empty-state" style="padding: 32px;"><p>No attack paths loaded</p></td></tr>';
        document.getElementById('statsGrid').innerHTML = '<div class="empty-state">No data loaded</div>';
        return;
      }

      const base = document.getElementById('apiBase').value;
      try {
        showMessage('Loading profile...', 'info');
        const resp = await fetch(`${base}/profiles/${encodeURIComponent(name)}`);
        if (!resp.ok) throw new Error('Failed to load profile');
        const data = await resp.json();

        nodes = data.nodes || [];
        edges = data.edges || [];
        currentProfile = name;

        // Save as last used profile
        localStorage.setItem('arguscloud_last_profile', name);

        // Update available filter options from loaded data
        updateAvailableFilterOptions();

        buildGraph(nodes, edges);
        renderAttacks(edges);
        renderStats(nodes);
        renderEnvList(nodes);

        // Populate graph analysis node selects after graph is built
        populateNodeSelects();
        updateHighValueSummary();

        showMessage(`Loaded profile: ${name}`, 'success');
        switchTab('graph');
      } catch (err) {
        showMessage(`Error loading profile: ${err.message}`, 'error');
      }
    }

    function generateProfileName() {
      // Try to extract account ID from nodes
      for (const node of nodes) {
        const id = node.id || '';
        const match = id.match(/arn:aws:[^:]*:(\d{12})/);
        if (match) {
          return `AWS-${match[1]}`;
        }
        // Check properties
        const account = node.properties?.account;
        if (account && /^\d{12}$/.test(account)) {
          return `AWS-${account}`;
        }
      }
      // Fallback to timestamp
      return `Profile-${Date.now()}`;
    }

    async function saveProfile(name, mode = 'create') {
      if (!nodes.length && !edges.length) {
        showMessage('No data to save', 'error');
        return false;
      }

      const base = document.getElementById('apiBase').value;
      try {
        const resp = await fetch(`${base}/profiles`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, nodes, edges, mode })
        });

        const data = await resp.json();

        if (resp.status === 409 && data.exists) {
          // Profile exists, show conflict options
          return { conflict: true, name };
        }

        if (!resp.ok) {
          throw new Error(data.error || 'Save failed');
        }

        currentProfile = name;
        localStorage.setItem('arguscloud_last_profile', name);
        await loadProfiles();
        document.getElementById('profileSelect').value = name;

        showMessage(`Profile saved: ${name}`, 'success');
        return { success: true };
      } catch (err) {
        showMessage(`Error saving profile: ${err.message}`, 'error');
        return { error: err.message };
      }
    }

    async function deleteProfile(name) {
      const base = document.getElementById('apiBase').value;
      try {
        const resp = await fetch(`${base}/profiles/${encodeURIComponent(name)}`, {
          method: 'DELETE'
        });

        if (!resp.ok) {
          const data = await resp.json();
          throw new Error(data.error || 'Delete failed');
        }

        if (currentProfile === name) {
          currentProfile = null;
          localStorage.removeItem('arguscloud_last_profile');
        }

        await loadProfiles();
        document.getElementById('profileSelect').value = '';
        showMessage(`Profile deleted: ${name}`, 'success');
      } catch (err) {
        showMessage(`Error deleting profile: ${err.message}`, 'error');
      }
    }

    // Utilities
    function parseJsonl(text) {
      return text.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
    }

    async function readFile(input) {
      if (!input.files || !input.files.length) return [];
      return parseJsonl(await input.files[0].text());
    }

    // Multi-file import utilities
    let selectedFiles = new Map(); // filename -> File object
    let currentImportMode = 'multi';

    async function processMultipleFiles(files) {
      selectedFiles.clear();
      for (const file of files) {
        const name = file.name.toLowerCase();
        if (name.endsWith('.jsonl')) {
          selectedFiles.set(name, file);
        }
      }
      updateFilePreview();
    }

    async function processZipFile(file) {
      selectedFiles.clear();
      try {
        const JSZip = window.JSZip;
        if (!JSZip) {
          throw new Error('JSZip library not loaded. Please refresh the page.');
        }
        const zip = await JSZip.loadAsync(file);
        for (const [path, zipEntry] of Object.entries(zip.files)) {
          if (!zipEntry.dir && path.toLowerCase().endsWith('.jsonl')) {
            const name = path.split('/').pop().toLowerCase();
            const content = await zipEntry.async('string');
            // Create a pseudo-file object
            selectedFiles.set(name, { text: async () => content, name: path });
          }
        }
        updateFilePreview();
      } catch (err) {
        showMessage(`Error reading ZIP: ${err.message}`, 'error');
      }
    }

    function updateFilePreview() {
      const preview = document.getElementById('filePreview');
      const list = document.getElementById('fileList');

      if (selectedFiles.size === 0) {
        preview.classList.add('hidden');
        return;
      }

      preview.classList.remove('hidden');
      const hasNodes = selectedFiles.has('nodes.jsonl');
      const hasEdges = selectedFiles.has('edges.jsonl');

      let html = '';
      for (const [name] of selectedFiles) {
        const isRequired = name === 'nodes.jsonl' || name === 'edges.jsonl';
        const icon = isRequired ? '✓' : '○';
        const color = isRequired ? 'var(--accent-success)' : 'var(--text-tertiary)';
        html += `<div style="padding: 2px 0;"><span style="color: ${color}; margin-right: 6px;">${icon}</span>${name}</div>`;
      }

      if (!hasNodes || !hasEdges) {
        html += `<div style="color: var(--accent-danger); margin-top: 8px; font-weight: 500;">⚠ Missing: ${!hasNodes ? 'nodes.jsonl ' : ''}${!hasEdges ? 'edges.jsonl' : ''}</div>`;
      }

      list.innerHTML = html;
    }

    async function loadSelectedFiles() {
      if (selectedFiles.size === 0) {
        showMessage('Please select files first', 'error');
        return null;
      }

      if (!selectedFiles.has('nodes.jsonl') || !selectedFiles.has('edges.jsonl')) {
        showMessage('Both nodes.jsonl and edges.jsonl are required', 'error');
        return null;
      }

      try {
        const nodesFile = selectedFiles.get('nodes.jsonl');
        const edgesFile = selectedFiles.get('edges.jsonl');

        const nodesText = await nodesFile.text();
        const edgesText = await edgesFile.text();

        let edges = parseJsonl(edgesText);

        // Also load attack_paths.jsonl if present and merge into edges
        if (selectedFiles.has('attack_paths.jsonl')) {
          const attackPathsText = await selectedFiles.get('attack_paths.jsonl').text();
          const attackPaths = parseJsonl(attackPathsText);
          edges = edges.concat(attackPaths);
          console.log(`Merged ${attackPaths.length} attack paths`);
        }

        return {
          nodes: parseJsonl(nodesText),
          edges: edges
        };
      } catch (err) {
        showMessage(`Error parsing files: ${err.message}`, 'error');
        return null;
      }
    }

    function nodeLabel(n) {
      const p = n.properties || {};
      return p.name || p.role_name || p.user_name || n.id?.split('/').pop() || n.type;
    }

    function nodeColor(type) {
      const t = (type || '').toLowerCase();
      if (t.includes('account')) return getComputedStyle(document.documentElement).getPropertyValue('--node-account').trim();
      if (t.includes('role')) return getComputedStyle(document.documentElement).getPropertyValue('--node-role').trim();
      if (t.includes('user')) return getComputedStyle(document.documentElement).getPropertyValue('--node-user').trim();
      if (t.includes('s3')) return getComputedStyle(document.documentElement).getPropertyValue('--node-s3').trim();
      if (t.includes('ec2') || t.includes('instance')) return getComputedStyle(document.documentElement).getPropertyValue('--node-ec2').trim();
      if (t.includes('lambda')) return getComputedStyle(document.documentElement).getPropertyValue('--node-lambda').trim();
      if (t.includes('kms')) return getComputedStyle(document.documentElement).getPropertyValue('--node-kms').trim();
      if (t.includes('security')) return getComputedStyle(document.documentElement).getPropertyValue('--node-sg').trim();
      return getComputedStyle(document.documentElement).getPropertyValue('--node-default').trim();
    }

    function severityColor(sev) {
      const s = (sev || '').toLowerCase();
      if (s === 'critical') return getComputedStyle(document.documentElement).getPropertyValue('--severity-critical').trim();
      if (s === 'high') return getComputedStyle(document.documentElement).getPropertyValue('--severity-high').trim();
      if (s === 'medium') return getComputedStyle(document.documentElement).getPropertyValue('--severity-medium').trim();
      if (s === 'low') return getComputedStyle(document.documentElement).getPropertyValue('--severity-low').trim();
      return getComputedStyle(document.documentElement).getPropertyValue('--severity-info').trim();
    }

    // Build graph
    function buildGraph(nodeData, edgeData) {
      const searchTerm = document.getElementById('searchInput')?.value?.toLowerCase() || '';
      const layout = document.getElementById('layoutSelect')?.value || 'cose';

      // Use the advanced filter state for filtering
      const severityFilters = filterState.severity;
      const typeFilters = filterState.resourceTypes;

      // Filter edges by severity (from advanced filter state)
      const filteredEdges = edgeData.filter(e => {
        if (e.type !== 'AttackPath') return true;
        if (severityFilters.length > 0) {
          const edgeSeverity = (e.properties?.severity || '').toLowerCase();
          if (!severityFilters.includes(edgeSeverity)) return false;
        }
        return true;
      });

      // Build node map with filtering
      const nodeMap = {};
      nodeData.forEach(n => {
        // Search filter
        if (searchTerm && !n.id.toLowerCase().includes(searchTerm)) return;
        // Type filter (from advanced filter state)
        if (typeFilters.length > 0 && !typeFilters.includes(n.type)) return;
        nodeMap[n.id] = n;
      });

      // Ensure edge endpoints exist
      filteredEdges.forEach(e => {
        if (!nodeMap[e.src]) nodeMap[e.src] = { id: e.src, type: 'Unknown', properties: {} };
        if (!nodeMap[e.dst]) nodeMap[e.dst] = { id: e.dst, type: 'Unknown', properties: {} };
      });

      // Build Cytoscape elements
      const elements = [];
      Object.values(nodeMap).forEach(n => {
        elements.push({
          data: { id: n.id, label: nodeLabel(n), type: n.type, properties: n.properties }
        });
      });

      filteredEdges.forEach((e, i) => {
        elements.push({
          data: {
            id: `${e.src}->${e.dst}:${e.type}:${i}`,
            source: e.src,
            target: e.dst,
            label: e.type === 'AttackPath' ? (e.properties?.rule || e.type) : e.type,
            severity: e.properties?.severity || '',
            edgeType: e.type,
            properties: e.properties
          },
          classes: e.type === 'AttackPath' ? 'attack' : ''
        });
      });

      // Initialize or update Cytoscape
      if (!cy) {
        cy = cytoscape({
          container: document.getElementById('cy'),
          elements: elements,
          style: getCyStyle(),
          layout: { name: layout, animate: false },
          // Finer zoom control settings
          wheelSensitivity: 0.15,
          minZoom: 0.1,
          maxZoom: 5,
          zoomingEnabled: true,
          userZoomingEnabled: true,
          panningEnabled: true,
          userPanningEnabled: true
        });
        setupCyEvents();
      } else {
        cy.elements().remove();
        cy.add(elements);
        cy.layout({ name: layout, animate: false }).run();
      }
    }

    function getCyStyle() {
      const isDark = !document.body.classList.contains('light');
      const textColor = isDark ? '#f1f5f9' : '#0f172a';
      const edgeColor = isDark ? '#4a5568' : '#cbd5e1';
      // Edge label colors - lighter in dark mode, darker in light mode for better contrast
      const edgeLabelColor = isDark ? '#e2e8f0' : '#1e293b';

      return [
        {
          selector: 'node',
          style: {
            'background-color': ele => nodeColor(ele.data('type')),
            'label': 'data(label)',
            'font-size': '10px',
            'font-weight': '500',
            'color': textColor,
            'text-valign': document.getElementById('labelPos')?.value || 'center',
            'text-halign': 'center',
            'text-margin-y': document.getElementById('labelPos')?.value === 'bottom' ? 8 : (document.getElementById('labelPos')?.value === 'top' ? -8 : 0),
            'width': 32,
            'height': 32,
            'border-width': 2,
            'border-color': isDark ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.1)',
            'text-background-color': isDark ? '#0f1419' : '#ffffff',
            'text-background-opacity': 0.9,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'font-family': 'Inter, sans-serif'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': edgeColor,
            'target-arrow-color': edgeColor,
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '9px',
            'font-weight': '500',
            'color': edgeLabelColor,
            'text-rotation': 'autorotate',
            'text-background-color': isDark ? 'rgba(15, 20, 25, 0.85)' : 'rgba(255, 255, 255, 0.85)',
            'text-background-opacity': 1,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'font-family': 'Inter, sans-serif'
          }
        },
        {
          selector: '.attack',
          style: {
            'line-color': ele => severityColor(ele.data('severity')),
            'target-arrow-color': ele => severityColor(ele.data('severity')),
            'width': 2.5,
            'line-style': 'solid'
          }
        },
        {
          selector: ':selected',
          style: {
            'border-width': 3,
            'border-color': '#3b82f6'
          }
        },
        // Owned nodes (compromised)
        {
          selector: '.owned',
          style: {
            'border-width': 3,
            'border-color': '#f59e0b',
            'background-color': '#f59e0b',
            'border-style': 'double'
          }
        },
        // High-value targets
        {
          selector: '.high-value',
          style: {
            'border-width': 3,
            'border-color': '#dc2626',
            'border-style': 'dashed'
          }
        },
        // Highlighted path nodes
        {
          selector: '.path-node',
          style: {
            'border-width': 3,
            'border-color': '#22c55e',
            'background-blacken': -0.2
          }
        },
        // Highlighted path edges - prominent arrows
        {
          selector: '.path-edge',
          style: {
            'line-color': '#22c55e',
            'target-arrow-color': '#22c55e',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 1.5,
            'width': 4,
            'z-index': 100,
            'opacity': 1
          }
        },
        // Path start node (source)
        {
          selector: '.path-start',
          style: {
            'border-width': 4,
            'border-color': '#3b82f6',
            'background-color': '#3b82f6',
            'width': 40,
            'height': 40
          }
        },
        // Path end node (target/destination)
        {
          selector: '.path-end',
          style: {
            'border-width': 4,
            'border-color': '#ef4444',
            'background-color': '#ef4444',
            'width': 40,
            'height': 40
          }
        },
        // Generic highlighted class
        {
          selector: '.highlighted',
          style: {
            'opacity': 1,
            'z-index': 100
          }
        },
        // Dim non-highlighted when path is active
        {
          selector: 'node:not(.highlighted):not(.path-node):not(.owned)',
          style: {
            // Keep visible but slightly dimmed when filtering
          }
        }
      ];
    }

    function setupCyEvents() {
      cy.on('tap', 'node, edge', evt => {
        const data = evt.target.data();
        const isNode = evt.target.isNode();
        const html = `
          <div style="font-size: 12px;">
            <div style="font-weight: 600; margin-bottom: 8px; color: var(--accent-primary);">
              ${isNode ? 'Node' : 'Edge'}: ${data.type || data.edgeType || 'Unknown'}
            </div>
            <div style="margin-bottom: 8px;">
              <code style="word-break: break-all;">${data.id || ''}</code>
            </div>
            <pre style="margin: 0; max-height: 300px; overflow: auto;">${JSON.stringify(data.properties || data, null, 2)}</pre>
          </div>
        `;
        document.getElementById('detailContent').innerHTML = html;
      });

      cy.on('tap', evt => {
        if (evt.target === cy) {
          document.getElementById('detailContent').innerHTML = `
            <div class="detail-empty">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; margin-bottom: 12px; opacity: 0.5;">
                <circle cx="12" cy="12" r="10"></circle>
                <path d="M12 16v-4M12 8h.01"></path>
              </svg>
              <p>Click a node or edge in the graph to view details</p>
            </div>
          `;
        }
      });

      // Ctrl+click to mark nodes as owned
      cy.on('tap', 'node', evt => {
        if (evt.originalEvent.ctrlKey || evt.originalEvent.metaKey) {
          const nodeId = evt.target.id();
          toggleOwnedNode(nodeId);
        }
      });
    }

    // ============ Graph Analysis Functions (BloodHound-style) ============

    // Detect high-value targets in the graph based on patterns
    function detectHighValueTargets() {
      if (!cy || cy.nodes().empty()) return {};

      const detected = {};
      graphAnalysisState.detectedHighValueNodes.clear();

      cy.nodes().forEach(node => {
        const nodeId = node.id();
        const nodeType = node.data('type') || '';
        const nodeLabel = node.data('label') || nodeId;

        for (const [key, pattern] of Object.entries(highValuePatterns)) {
          let isMatch = false;

          // Check regex patterns against node ID
          if (pattern.patterns) {
            isMatch = pattern.patterns.some(regex => regex.test(nodeId) || regex.test(nodeLabel));
          }

          // Check type matches
          if (!isMatch && pattern.types) {
            isMatch = pattern.types.some(t => nodeType.toLowerCase().includes(t.toLowerCase()));
          }

          // Check property-based checks
          if (!isMatch && pattern.propertyChecks) {
            isMatch = pattern.propertyChecks.some(check => {
              try { return check(node); } catch { return false; }
            });
          }

          if (isMatch) {
            if (!detected[key]) {
              detected[key] = { ...pattern, nodes: [] };
            }
            detected[key].nodes.push({ id: nodeId, label: nodeLabel, type: nodeType });
            graphAnalysisState.detectedHighValueNodes.add(nodeId);
            node.addClass('high-value');
          }
        }
      });

      return detected;
    }

    // Update high-value targets summary UI
    function updateHighValueSummary() {
      const detected = detectHighValueTargets();
      const summaryEl = document.getElementById('highValueSummary');
      const countEl = document.getElementById('highValueCount');
      const categoriesEl = document.getElementById('highValueCategories');

      if (!summaryEl || !categoriesEl) return;

      const totalCount = graphAnalysisState.detectedHighValueNodes.size;
      if (countEl) countEl.textContent = `${totalCount} detected`;

      if (totalCount === 0) {
        categoriesEl.innerHTML = '<span style="font-size: 11px; color: var(--text-tertiary);">No high-value targets detected</span>';
        return;
      }

      // Sort by priority
      const sorted = Object.entries(detected).sort((a, b) => a[1].priority - b[1].priority);

      categoriesEl.innerHTML = sorted.map(([key, data]) => `
        <div class="hv-category" onclick="highlightHighValueCategory('${key}')" title="Click to highlight">
          <span class="hv-category-name">${data.category}</span>
          <span class="hv-category-count">${data.nodes.length}</span>
        </div>
      `).join('');
    }

    // Highlight all nodes in a high-value category
    function highlightHighValueCategory(categoryKey) {
      const detected = detectHighValueTargets();
      const category = detected[categoryKey];

      if (!category || !category.nodes.length) return;

      clearPathHighlight();

      category.nodes.forEach(n => {
        const node = cy.getElementById(n.id);
        if (!node.empty()) {
          node.addClass('highlighted path-node');
        }
      });

      showMessage(`Highlighted ${category.nodes.length} ${category.category} targets`, 'success');
    }

    // Get internet entry points (nodes that represent external/public access)
    function getInternetEntryPoints() {
      if (!cy) return cy.collection();

      return cy.nodes().filter(node => {
        const nodeId = node.id();
        const nodeType = node.data('type') || '';

        // Check against patterns
        for (const pattern of internetEntryPoints) {
          if (typeof pattern === 'string') {
            if (nodeId === pattern || nodeId.includes(pattern)) return true;
          } else if (pattern instanceof RegExp) {
            if (pattern.test(nodeId) || pattern.test(nodeType)) return true;
          }
        }

        // Also check for AttackPath edges pointing to 'internet'
        const hasInternetEdge = node.connectedEdges().some(e =>
          e.target().id() === 'internet' || e.source().id() === 'internet'
        );

        return hasInternetEdge;
      });
    }

    // Toggle owned status on a node
    function toggleOwnedNode(nodeId) {
      if (graphAnalysisState.ownedNodes.has(nodeId)) {
        graphAnalysisState.ownedNodes.delete(nodeId);
        cy.getElementById(nodeId).removeClass('owned');
      } else {
        graphAnalysisState.ownedNodes.add(nodeId);
        cy.getElementById(nodeId).addClass('owned');
      }
      updateMarkerCounts();
    }

    // Toggle high-value status on a node
    function toggleHighValueNode(nodeId) {
      if (graphAnalysisState.highValueNodes.has(nodeId)) {
        graphAnalysisState.highValueNodes.delete(nodeId);
        cy.getElementById(nodeId).removeClass('high-value');
      } else {
        graphAnalysisState.highValueNodes.add(nodeId);
        cy.getElementById(nodeId).addClass('high-value');
      }
      updateMarkerCounts();
    }

    // Mark selected nodes as owned
    function markSelectedAsOwned() {
      const selected = cy.$(':selected').nodes();
      if (selected.empty()) {
        showMessage('Select nodes first (click to select)', 'warning');
        return;
      }
      selected.forEach(node => {
        graphAnalysisState.ownedNodes.add(node.id());
        node.addClass('owned');
      });
      updateMarkerCounts();
      showMessage(`Marked ${selected.length} node(s) as owned`, 'success');
    }

    // Mark selected nodes as high-value
    function markSelectedAsHighValue() {
      const selected = cy.$(':selected').nodes();
      if (selected.empty()) {
        showMessage('Select nodes first (click to select)', 'warning');
        return;
      }
      selected.forEach(node => {
        graphAnalysisState.highValueNodes.add(node.id());
        node.addClass('high-value');
      });
      updateMarkerCounts();
      showMessage(`Marked ${selected.length} node(s) as high-value`, 'success');
    }

    // Clear all markers
    function clearAllMarkers() {
      graphAnalysisState.ownedNodes.forEach(nodeId => {
        cy.getElementById(nodeId).removeClass('owned');
      });
      graphAnalysisState.highValueNodes.forEach(nodeId => {
        cy.getElementById(nodeId).removeClass('high-value');
      });
      graphAnalysisState.ownedNodes.clear();
      graphAnalysisState.highValueNodes.clear();
      updateMarkerCounts();
      showMessage('Cleared all markers', 'info');
    }

    // Update marker counts in UI
    function updateMarkerCounts() {
      const ownedEl = document.getElementById('ownedNodesCount');
      const hvEl = document.getElementById('highValueNodesCount');
      if (ownedEl) ownedEl.textContent = graphAnalysisState.ownedNodes.size;
      if (hvEl) hvEl.textContent = graphAnalysisState.highValueNodes.size;
    }

    // Find shortest path between two nodes (improved with undirected fallback)
    function findShortestPath(sourceId, targetId) {
      if (!cy || !sourceId || !targetId) return null;

      const source = cy.getElementById(sourceId);
      const target = cy.getElementById(targetId);

      if (source.empty() || target.empty()) {
        showMessage('Source or target node not found in graph', 'error');
        return null;
      }

      try {
        // Try directed first
        let dijkstra = cy.elements().dijkstra({
          root: source,
          weight: edge => 1,
          directed: true
        });

        let path = dijkstra.pathTo(target);

        // If no directed path, try undirected
        if (path.empty()) {
          dijkstra = cy.elements().dijkstra({
            root: source,
            weight: edge => 1,
            directed: false
          });
          path = dijkstra.pathTo(target);
        }

        if (path.empty()) {
          showMessage('No path found between selected nodes', 'warning');
          return null;
        }

        return path;
      } catch (e) {
        console.error('Path finding error:', e);
        showMessage('Error finding path: ' + e.message, 'error');
        return null;
      }
    }

    // Find all paths up to a certain depth
    function findAllPaths(sourceId, targetId, maxDepth = 5, maxPaths = 10) {
      if (!cy || !sourceId || !targetId) return [];

      const paths = [];
      const visited = new Set();

      function dfs(currentId, currentPath, depth) {
        if (paths.length >= maxPaths) return;
        if (depth > maxDepth) return;
        if (currentId === targetId) {
          paths.push([...currentPath]);
          return;
        }

        visited.add(currentId);
        const node = cy.getElementById(currentId);
        const outgoers = node.outgoers('node');

        outgoers.forEach(neighbor => {
          const neighborId = neighbor.id();
          if (!visited.has(neighborId)) {
            currentPath.push(neighborId);
            dfs(neighborId, currentPath, depth + 1);
            currentPath.pop();
          }
        });

        visited.delete(currentId);
      }

      dfs(sourceId, [sourceId], 0);
      return paths;
    }

    // Find nodes reachable from a source within N hops
    function findReachableNodes(sourceId, maxHops = 3) {
      if (!cy || !sourceId) return cy.collection();

      const source = cy.getElementById(sourceId);
      if (source.empty()) return cy.collection();

      let reachable = source;
      let frontier = source;

      for (let i = 0; i < maxHops; i++) {
        const newFrontier = frontier.outgoers('node').difference(reachable);
        if (newFrontier.empty()) break;
        reachable = reachable.union(newFrontier);
        frontier = newFrontier;
      }

      return reachable;
    }

    // Highlight a path in the graph
    function highlightPath(path) {
      if (!cy) return;

      // Clear previous highlights
      cy.elements().removeClass('highlighted path-node path-edge');

      if (path && !path.empty()) {
        path.addClass('highlighted');
        path.nodes().addClass('path-node');
        path.edges().addClass('path-edge');
        cy.fit(path, 50);
      }
    }

    // Highlight multiple paths with animated arrows
    function highlightPaths(paths) {
      if (!cy || !paths.length) return;

      cy.elements().removeClass('highlighted path-node path-edge path-start path-end');

      let totalEdgesHighlighted = 0;

      paths.forEach((pathNodeIds, pathIndex) => {
        pathNodeIds.forEach((nodeId, i) => {
          const node = cy.getElementById(nodeId);
          if (!node.empty()) {
            node.addClass('highlighted path-node');
            // Mark start and end of path
            if (i === 0) node.addClass('path-start');
            if (i === pathNodeIds.length - 1) node.addClass('path-end');
          }
          // Highlight edge between consecutive nodes
          if (i < pathNodeIds.length - 1) {
            const nextId = pathNodeIds[i + 1];
            // Find edges in both directions
            const edges = cy.edges().filter(e =>
              (e.source().id() === nodeId && e.target().id() === nextId) ||
              (e.source().id() === nextId && e.target().id() === nodeId)
            );
            if (!edges.empty()) {
              edges.addClass('highlighted path-edge');
              totalEdgesHighlighted += edges.length;
            } else {
              // If no direct edge exists, create a visual connection
              console.log(`No edge found between ${nodeId} and ${nextId}`);
            }
          }
        });
      });

      // Fit to highlighted elements
      const highlighted = cy.$('.highlighted');
      if (!highlighted.empty()) {
        cy.fit(highlighted, 50);
        if (totalEdgesHighlighted > 0) {
          showMessage(`Showing ${paths.length} path(s) with ${totalEdgesHighlighted} edge(s)`, 'success');
        }
      }
    }

    // Clear path highlighting
    function clearPathHighlight() {
      if (!cy) return;
      cy.elements().removeClass('highlighted path-node path-edge path-start path-end');
      graphAnalysisState.pathResults = [];
      const resultsEl = document.getElementById('pathResults');
      if (resultsEl) resultsEl.classList.add('hidden');
    }

    // Find high-degree nodes
    function findHighDegreeNodes(minDegree = 3) {
      if (!cy) return cy.collection();

      return cy.nodes().filter(node => {
        const inDegree = node.indegree();
        const outDegree = node.outdegree();
        return inDegree >= minDegree || outDegree >= minDegree;
      });
    }

    // Execute a security query
    function executeSecurityQuery(queryId) {
      if (!cy || cy.nodes().empty()) {
        showMessage('Load graph data first', 'warning');
        return;
      }

      clearPathHighlight();
      graphAnalysisState.lastQuery = queryId;

      switch (queryId) {
        case 'internet-to-admin': {
          const internetNodes = getInternetEntryPoints();
          const adminNodes = cy.nodes().filter(n =>
            n.data('is_admin') === true ||
            n.id().toLowerCase().includes('admin') ||
            (n.data('role_name') || '').toLowerCase().includes('admin')
          );

          if (internetNodes.empty()) {
            showMessage('No internet entry points found', 'info');
            return;
          }
          if (adminNodes.empty()) {
            showMessage('No admin nodes found', 'info');
            return;
          }

          const allPaths = [];
          internetNodes.forEach(src => {
            adminNodes.forEach(dst => {
              if (src.id() !== dst.id()) {
                const paths = findAllPaths(src.id(), dst.id(), 6, 3);
                allPaths.push(...paths);
              }
            });
          });

          if (allPaths.length === 0) {
            showMessage('No paths from internet to admin found', 'info');
            return;
          }

          highlightPaths(allPaths.slice(0, 5));
          graphAnalysisState.pathResults = allPaths;
          updatePathResults(allPaths);
          showMessage(`Found ${allPaths.length} path(s) from internet to admin`, 'success');
          break;
        }

        case 'internet-to-data': {
          const internetNodes = getInternetEntryPoints();
          const dataNodes = cy.nodes().filter(n => {
            const id = n.id().toLowerCase();
            const type = (n.data('type') || '').toLowerCase();
            return id.includes('s3') || id.includes('rds') || id.includes('dynamodb') ||
                   id.includes('database') || id.includes('bucket') ||
                   type.includes('bucket') || type.includes('database');
          });

          if (internetNodes.empty() || dataNodes.empty()) {
            showMessage('No internet-to-data paths found', 'info');
            return;
          }

          const allPaths = [];
          internetNodes.forEach(src => {
            dataNodes.forEach(dst => {
              if (src.id() !== dst.id()) {
                const paths = findAllPaths(src.id(), dst.id(), 6, 3);
                allPaths.push(...paths);
              }
            });
          });

          if (allPaths.length === 0) {
            showMessage('No paths from internet to data stores found', 'info');
            return;
          }

          highlightPaths(allPaths.slice(0, 5));
          graphAnalysisState.pathResults = allPaths;
          updatePathResults(allPaths);
          showMessage(`Found ${allPaths.length} path(s) from internet to data stores`, 'success');
          break;
        }

        case 'internet-to-secrets': {
          const internetNodes = getInternetEntryPoints();
          const secretNodes = cy.nodes().filter(n => {
            const id = n.id().toLowerCase();
            return id.includes('secret') || id.includes('kms') || id.includes('key') ||
                   id.includes('parameter') || id.includes('ssm');
          });

          if (internetNodes.empty() || secretNodes.empty()) {
            showMessage('No internet-to-secrets paths found', 'info');
            return;
          }

          const allPaths = [];
          internetNodes.forEach(src => {
            secretNodes.forEach(dst => {
              if (src.id() !== dst.id()) {
                const paths = findAllPaths(src.id(), dst.id(), 6, 3);
                allPaths.push(...paths);
              }
            });
          });

          if (allPaths.length === 0) {
            showMessage('No paths from internet to secrets found', 'info');
            return;
          }

          highlightPaths(allPaths.slice(0, 5));
          graphAnalysisState.pathResults = allPaths;
          updatePathResults(allPaths);
          showMessage(`Found ${allPaths.length} path(s) from internet to secrets`, 'success');
          break;
        }

        case 'privesc-paths': {
          // Find edges that represent privilege escalation
          const privescEdges = cy.edges().filter(e => {
            const edgeType = e.data('edgeType') || e.data('type') || '';
            const rule = e.data('rule') || '';
            return edgeType === 'AttackPath' ||
                   rule.toLowerCase().includes('privesc') ||
                   rule.toLowerCase().includes('privilege') ||
                   edgeType.includes('CanAssume') ||
                   edgeType.includes('Trusts');
          });

          if (privescEdges.empty()) {
            showMessage('No privilege escalation paths found', 'info');
            return;
          }

          privescEdges.addClass('highlighted path-edge');
          privescEdges.connectedNodes().addClass('highlighted path-node');
          showMessage(`Found ${privescEdges.length} privilege escalation edges`, 'success');
          break;
        }

        case 'cross-account': {
          const crossAccountEdges = cy.edges().filter(edge => {
            const srcId = edge.source().id();
            const dstId = edge.target().id();
            const srcAccount = extractAccountId(srcId);
            const dstAccount = extractAccountId(dstId);
            return srcAccount && dstAccount && srcAccount !== dstAccount;
          });

          if (crossAccountEdges.empty()) {
            showMessage('No cross-account relationships found', 'info');
            return;
          }

          crossAccountEdges.addClass('highlighted path-edge');
          crossAccountEdges.connectedNodes().addClass('highlighted path-node');
          showMessage(`Found ${crossAccountEdges.length} cross-account relationships`, 'success');
          break;
        }

        case 'lateral-movement': {
          // Find trust and role assumption edges that enable lateral movement
          const lateralEdges = cy.edges().filter(e => {
            const edgeType = e.data('edgeType') || e.data('type') || '';
            return edgeType.includes('Trust') ||
                   edgeType.includes('CanAssume') ||
                   edgeType.includes('AssumesRole') ||
                   edgeType.includes('MemberOf');
          });

          if (lateralEdges.empty()) {
            showMessage('No lateral movement paths found', 'info');
            return;
          }

          lateralEdges.addClass('highlighted path-edge');
          lateralEdges.connectedNodes().addClass('highlighted path-node');
          showMessage(`Found ${lateralEdges.length} lateral movement edges`, 'success');
          break;
        }

        case 'from-owned': {
          if (graphAnalysisState.ownedNodes.size === 0) {
            showMessage('No owned nodes marked. Ctrl+click nodes to mark as owned.', 'info');
            return;
          }

          // Find all high-value targets reachable from owned nodes
          const hvTargets = [...graphAnalysisState.detectedHighValueNodes, ...graphAnalysisState.highValueNodes];
          const allPaths = [];

          graphAnalysisState.ownedNodes.forEach(ownedId => {
            hvTargets.forEach(hvId => {
              if (ownedId !== hvId) {
                const paths = findAllPaths(ownedId, hvId, 5, 2);
                allPaths.push(...paths);
              }
            });
          });

          if (allPaths.length === 0) {
            showMessage('No paths from owned nodes to high-value targets', 'info');
            return;
          }

          highlightPaths(allPaths.slice(0, 10));
          graphAnalysisState.pathResults = allPaths;
          updatePathResults(allPaths);
          showMessage(`Found ${allPaths.length} path(s) from owned to high-value targets`, 'success');
          break;
        }

        default:
          showMessage('Unknown query: ' + queryId, 'error');
      }
    }

    // Helper: Extract AWS account ID from ARN
    function extractAccountId(arn) {
      if (!arn) return null;
      const match = arn.match(/arn:aws:[^:]*:[^:]*:(\d{12})/);
      return match ? match[1] : null;
    }

    // Update path results display
    function updatePathResults(paths) {
      const resultsEl = document.getElementById('pathResults');
      const contentEl = document.getElementById('pathResultsContent');
      if (!resultsEl || !contentEl) return;

      if (!paths || paths.length === 0) {
        resultsEl.classList.add('hidden');
        return;
      }

      resultsEl.classList.remove('hidden');
      contentEl.innerHTML = paths.slice(0, 10).map((path, i) => {
        const startNode = path[0] || '';
        const endNode = path[path.length - 1] || '';
        return `
          <div class="path-result-item" onclick="highlightPathByIndex(${i})">
            <span class="path-length">${path.length - 1} hop${path.length - 1 !== 1 ? 's' : ''}</span>
            <span class="path-endpoints">${truncate(startNode.split('/').pop() || startNode, 20)} → ${truncate(endNode.split('/').pop() || endNode, 20)}</span>
          </div>
        `;
      }).join('') + (paths.length > 10 ? `<div style="font-size: 11px; color: var(--text-tertiary); padding: 8px;">...and ${paths.length - 10} more</div>` : '');
    }

    // Highlight a specific path by index
    function highlightPathByIndex(index) {
      const paths = graphAnalysisState.pathResults;
      if (!paths || !paths[index]) return;

      highlightPaths([paths[index]]);
    }

    // Populate node select dropdowns for path finding
    function populateNodeSelects() {
      const sourceSelect = document.getElementById('pathSourceSelect');
      const targetSelect = document.getElementById('pathTargetSelect');

      if (!sourceSelect || !targetSelect || !cy) return;

      // Get all nodes sorted by label
      const nodes = cy.nodes().map(n => ({
        id: n.id(),
        label: n.data('label') || n.id(),
        type: n.data('type') || ''
      })).sort((a, b) => a.label.localeCompare(b.label));

      // Group nodes by type for better organization
      const optionsHtml = nodes.map(n => {
        const displayLabel = truncate(n.label, 40);
        const typeLabel = n.type ? ` [${n.type}]` : '';
        return `<option value="${n.id}">${displayLabel}${typeLabel}</option>`;
      }).join('');

      // Add special options at top
      sourceSelect.innerHTML = `
        <option value="">Select source...</option>
        <option value="__INTERNET__">[Internet] All entry points</option>
        <optgroup label="All Nodes">
          ${optionsHtml}
        </optgroup>
      `;

      targetSelect.innerHTML = `
        <option value="">Select target...</option>
        <option value="__HIGH_VALUE__">[Any High-Value Target]</option>
        <option value="__ADMIN__">[Any Admin Role]</option>
        <option value="__DATA__">[Any Data Store]</option>
        <option value="__SECRETS__">[Any Secret/Key]</option>
        <optgroup label="All Nodes">
          ${optionsHtml}
        </optgroup>
      `;
    }

    // Handle path finding button click
    function handleFindPath(mode = 'shortest') {
      // Check if graph is loaded
      if (!cy || cy.nodes().length === 0) {
        showMessage('Please load a profile with data first', 'warning');
        return;
      }

      let sourceId = document.getElementById('pathSourceSelect')?.value;
      let targetId = document.getElementById('pathTargetSelect')?.value;

      if (!sourceId || !targetId) {
        showMessage('Please select both source and target nodes', 'warning');
        return;
      }

      clearPathHighlight();

      // Handle special source values
      let sourceNodes = [];
      if (sourceId === '__INTERNET__') {
        sourceNodes = getInternetEntryPoints().map(n => n.id());
        if (sourceNodes.length === 0) {
          showMessage('No internet entry points found in graph', 'warning');
          return;
        }
      } else {
        sourceNodes = [sourceId];
      }

      // Handle special target values
      let targetNodes = [];
      if (targetId === '__HIGH_VALUE__') {
        targetNodes = [...graphAnalysisState.detectedHighValueNodes, ...graphAnalysisState.highValueNodes];
        if (targetNodes.length === 0) {
          showMessage('No high-value targets detected. Open Graph Analysis panel to detect them.', 'warning');
          return;
        }
      } else if (targetId === '__ADMIN__') {
        targetNodes = cy.nodes().filter(n =>
          n.data('is_admin') === true ||
          n.id().toLowerCase().includes('admin') ||
          (n.data('role_name') || '').toLowerCase().includes('admin')
        ).map(n => n.id());
        if (targetNodes.length === 0) {
          showMessage('No admin nodes found in graph', 'warning');
          return;
        }
      } else if (targetId === '__DATA__') {
        targetNodes = cy.nodes().filter(n => {
          const id = n.id().toLowerCase();
          return id.includes('s3') || id.includes('rds') || id.includes('dynamodb') || id.includes('bucket');
        }).map(n => n.id());
        if (targetNodes.length === 0) {
          showMessage('No data store nodes found', 'warning');
          return;
        }
      } else if (targetId === '__SECRETS__') {
        targetNodes = cy.nodes().filter(n => {
          const id = n.id().toLowerCase();
          return id.includes('secret') || id.includes('kms') || id.includes('key');
        }).map(n => n.id());
        if (targetNodes.length === 0) {
          showMessage('No secret/key nodes found', 'warning');
          return;
        }
      } else {
        targetNodes = [targetId];
      }

      // Find paths
      const allPaths = [];
      const maxPathsPerPair = mode === 'shortest' ? 1 : 3;

      for (const src of sourceNodes) {
        for (const dst of targetNodes) {
          if (src === dst) continue;

          if (mode === 'shortest') {
            const path = findShortestPath(src, dst);
            if (path && !path.empty()) {
              // Convert cytoscape path to array of node IDs
              const pathNodeIds = path.nodes().map(n => n.id());
              allPaths.push(pathNodeIds);
            }
          } else {
            const paths = findAllPaths(src, dst, 6, maxPathsPerPair);
            allPaths.push(...paths);
          }

          // Limit total paths
          if (allPaths.length >= 20) break;
        }
        if (allPaths.length >= 20) break;
      }

      if (allPaths.length === 0) {
        showMessage('No paths found', 'info');
        return;
      }

      // Highlight and display results
      highlightPaths(allPaths.slice(0, 5));
      graphAnalysisState.pathResults = allPaths;
      updatePathResults(allPaths);

      const srcLabel = sourceId.startsWith('__') ? sourceId.replace(/_/g, '') : 'source';
      const dstLabel = targetId.startsWith('__') ? targetId.replace(/_/g, '') : 'target';
      showMessage(`Found ${allPaths.length} path(s) from ${srcLabel} to ${dstLabel}`, 'success');
    }

    function renderAttacks(edgeData) {
      const attacks = edgeData.filter(e => e.type === 'AttackPath');
      // Use advanced filter state for severity filtering
      const severityFilters = filterState.severity;
      const filtered = attacks.filter(e => {
        if (severityFilters.length > 0) {
          const edgeSeverity = (e.properties?.severity || '').toLowerCase();
          if (!severityFilters.includes(edgeSeverity)) return false;
        }
        return true;
      });

      document.getElementById('attackCount').textContent = `${filtered.length} finding${filtered.length !== 1 ? 's' : ''}`;

      const tbody = document.querySelector('#attacksTable tbody');
      if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state" style="padding: 32px;"><p>No attack paths found</p></td></tr>`;
        return;
      }

      // Build rows with expandable detail rows
      const rows = filtered.map((e, idx) => {
        const sev = (e.properties?.severity || 'info').toLowerCase();
        const rule = e.properties?.rule || 'unknown';
        const rowId = `attack-row-${idx}`;
        const detailId = `attack-detail-${idx}`;

        // Main row with expand button
        const mainRow = `
          <tr class="attack-row" id="${rowId}" data-rule="${rule}" data-detail-id="${detailId}" onclick="toggleAttackDetail('${rowId}', '${detailId}', '${rule}')">
            <td><code>${rule}</code></td>
            <td>${e.properties?.description || ''}</td>
            <td><span class="severity ${sev}">${sev}</span></td>
            <td>
              <code style="font-size: 11px;">${truncate(e.src, 30)}</code>
              <span class="arrow">→</span>
              <code style="font-size: 11px;">${truncate(e.dst, 30)}</code>
            </td>
            <td class="expand-cell">
              <button class="expand-btn" title="Expand details">▼</button>
            </td>
          </tr>
        `;

        // Hidden detail row (populated on expand)
        const detailRow = `
          <tr class="attack-detail hidden" id="${detailId}" data-rule="${rule}">
            <td colspan="5">
              <div class="detail-panel">
                <div class="detail-loading">Loading vulnerability details...</div>
              </div>
            </td>
          </tr>
        `;

        return mainRow + detailRow;
      }).join('');

      tbody.innerHTML = rows;
    }

    // Toggle attack detail row visibility
    function toggleAttackDetail(rowId, detailId, rule) {
      const row = document.getElementById(rowId);
      const detail = document.getElementById(detailId);

      if (detail.classList.contains('hidden')) {
        // Expand
        row.classList.add('expanded');
        detail.classList.remove('hidden');

        // Populate detail content if not already done
        const panel = detail.querySelector('.detail-panel');
        if (panel.querySelector('.detail-loading')) {
          panel.innerHTML = renderAttackDetailPanel(rule);
          initDetailTabs(detailId);
        }
      } else {
        // Collapse
        row.classList.remove('expanded');
        detail.classList.add('hidden');
      }
    }

    // Render the expandable detail panel content
    function renderAttackDetailPanel(rule) {
      const kb = vulnerabilityKnowledgeBase[rule] || vulnerabilityKnowledgeBase['default'];
      const mitreBadges = kb.mitre.map(t =>
        `<a href="https://attack.mitre.org/techniques/${t.replace('.', '/')}" target="_blank" class="mitre-badge" title="View in MITRE ATT&CK">${t}</a>`
      ).join(' ');

      return `
        <div class="detail-tabs">
          <button class="tab active" data-tab="overview">Overview</button>
          <button class="tab" data-tab="exploit">Exploitation</button>
          <button class="tab" data-tab="remediate">Remediation</button>
        </div>
        <div class="tab-content-container">
          <div class="tab-content active" data-tab="overview">
            <div class="detail-header">
              <span class="detail-category">${kb.category}</span>
              ${mitreBadges}
            </div>
            <p class="detail-description">${kb.description}</p>
            <div class="detail-section">
              <h4>Impact</h4>
              <p>${kb.exploitation.overview}</p>
            </div>
          </div>
          <div class="tab-content" data-tab="exploit">
            <div class="detail-section">
              <h4>How to Exploit</h4>
              <p>${kb.exploitation.overview}</p>
              <h4>Attack Steps</h4>
              <ol class="exploit-steps">
                ${kb.exploitation.steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
              </ol>
              ${kb.exploitation.tools.length > 0 ? `
                <h4>Tools</h4>
                <div class="tool-tags">
                  ${kb.exploitation.tools.map(t => `<span class="tool-tag">${escapeHtml(t)}</span>`).join('')}
                </div>
              ` : ''}
            </div>
          </div>
          <div class="tab-content" data-tab="remediate">
            <div class="detail-section">
              <h4>How to Remediate</h4>
              <p>${kb.remediation.overview}</p>
              <h4>Remediation Steps</h4>
              <ol class="remediation-steps">
                ${kb.remediation.steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
              </ol>
              ${kb.remediation.cliCommands.length > 0 ? `
                <h4>CLI Commands</h4>
                <div class="cli-commands">
                  ${kb.remediation.cliCommands.map(c => `<code>$ ${escapeHtml(c)}</code>`).join('')}
                </div>
              ` : ''}
            </div>
          </div>
        </div>
      `;
    }

    // Initialize tab switching within a detail panel
    function initDetailTabs(detailId) {
      const detail = document.getElementById(detailId);
      const tabs = detail.querySelectorAll('.detail-tabs .tab');
      const contents = detail.querySelectorAll('.tab-content');

      tabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
          e.stopPropagation(); // Prevent row collapse
          const tabName = tab.getAttribute('data-tab');

          // Update active tab
          tabs.forEach(t => t.classList.remove('active'));
          tab.classList.add('active');

          // Update visible content
          contents.forEach(c => {
            c.classList.toggle('active', c.getAttribute('data-tab') === tabName);
          });
        });
      });
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    function truncate(str, len) {
      if (!str) return '';
      return str.length > len ? str.slice(0, len) + '...' : str;
    }

    function renderStats(nodeData) {
      const counts = {};
      nodeData.forEach(n => {
        counts[n.type] = (counts[n.type] || 0) + 1;
      });

      const grid = document.getElementById('statsGrid');
      const keys = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);

      if (!keys.length) {
        grid.innerHTML = '<div class="empty-state"><p>Load data to see resource statistics</p></div>';
        return;
      }

      grid.innerHTML = keys.map(k => `
        <div class="stat-card">
          <div class="stat-value">${counts[k]}</div>
          <div class="stat-label">${k}</div>
        </div>
      `).join('');
    }

    function renderEnvList(nodeData) {
      document.getElementById('objectCount').textContent = `${nodeData.length} object${nodeData.length !== 1 ? 's' : ''}`;

      const list = document.getElementById('envList');
      if (!nodeData.length) {
        list.innerHTML = '<li class="empty-state"><p>No environment data loaded</p></li>';
        return;
      }

      list.innerHTML = nodeData.slice(0, 100).map(n => `
        <li class="env-item">
          <span class="env-type">${n.type}</span>
          <span class="env-id">${n.id}</span>
        </li>
      `).join('');
    }

    function showMessage(text, type = 'error') {
      const msg = document.getElementById('msg');
      msg.textContent = text;
      msg.className = `message ${type}`;
      msg.classList.remove('hidden');
      setTimeout(() => msg.classList.add('hidden'), 5000);
    }

    // Toggle Graph Analysis Panel visibility
    function toggleGraphAnalysisPanel() {
      const content = document.getElementById('graphAnalysisContent');
      const panel = document.getElementById('graphAnalysisPanel');
      const toggle = document.getElementById('graphAnalysisToggle');

      if (!content || !panel) return;

      content.classList.toggle('hidden');

      if (!content.classList.contains('hidden')) {
        if (toggle) toggle.style.transform = 'rotate(180deg)';
        // Populate node selects and detect high-value targets when panel opens
        populateNodeSelects();
        updateHighValueSummary();
        updateMarkerCounts();
      } else {
        if (toggle) toggle.style.transform = 'rotate(0deg)';
      }
    }

    function updateStatus(apiOk, neoOk) {
      const api = document.getElementById('apiStatus');
      const neo = document.getElementById('neo4jStatus');

      api.className = `status-badge ${apiOk ? 'ok' : 'error'}`;
      api.innerHTML = `<span class="status-dot"></span><span>API: ${apiOk ? 'Connected' : 'Error'}</span>`;

      neo.className = `status-badge ${neoOk ? 'ok' : ''}`;
      neo.innerHTML = `<span class="status-dot"></span><span>Neo4j: ${neoOk ? 'Connected' : 'Unknown'}</span>`;
    }

    // Event Listeners

    // Profile selector
    document.getElementById('profileSelect').addEventListener('change', (e) => {
      loadProfile(e.target.value);
    });

    // Save profile button
    document.getElementById('saveProfileBtn').addEventListener('click', () => {
      if (!nodes.length && !edges.length) {
        showMessage('No data to save. Load files first.', 'error');
        return;
      }
      // Pre-fill with auto-generated name
      document.getElementById('profileNameInput').value = currentProfile || generateProfileName();
      document.getElementById('conflictOptions').classList.add('hidden');
      document.getElementById('modeCreate').checked = true;
      document.getElementById('saveProfileModal').classList.remove('hidden');
    });

    // Cancel save
    document.getElementById('cancelSaveBtn').addEventListener('click', () => {
      document.getElementById('saveProfileModal').classList.add('hidden');
    });

    // Confirm save
    document.getElementById('confirmSaveBtn').addEventListener('click', async () => {
      let name = document.getElementById('profileNameInput').value.trim();
      if (!name) {
        name = generateProfileName();
        document.getElementById('profileNameInput').value = name;
      }

      const mode = document.querySelector('input[name="saveMode"]:checked').value;
      const result = await saveProfile(name, mode);

      if (result.conflict) {
        // Show conflict options
        document.getElementById('conflictOptions').classList.remove('hidden');
        return;
      }

      if (result.success) {
        document.getElementById('saveProfileModal').classList.add('hidden');
      }
    });

    // Delete profile button
    document.getElementById('deleteProfileBtn').addEventListener('click', () => {
      const name = document.getElementById('profileSelect').value;
      if (!name) {
        showMessage('No profile selected', 'error');
        return;
      }
      document.getElementById('deleteProfileName').textContent = name;
      document.getElementById('deleteProfileModal').classList.remove('hidden');
    });

    // Cancel delete
    document.getElementById('cancelDeleteBtn').addEventListener('click', () => {
      document.getElementById('deleteProfileModal').classList.add('hidden');
    });

    // Confirm delete
    document.getElementById('confirmDeleteBtn').addEventListener('click', async () => {
      const name = document.getElementById('profileSelect').value;
      await deleteProfile(name);
      document.getElementById('deleteProfileModal').classList.add('hidden');
    });

    // Rename profile button
    document.getElementById('renameProfileBtn').addEventListener('click', () => {
      const name = document.getElementById('profileSelect').value;
      if (!name) {
        showMessage('No profile selected', 'error');
        return;
      }
      document.getElementById('currentProfileName').value = name;
      document.getElementById('newProfileName').value = '';
      document.getElementById('renameProfileModal').classList.remove('hidden');
    });

    // Cancel rename
    document.getElementById('cancelRenameBtn').addEventListener('click', () => {
      document.getElementById('renameProfileModal').classList.add('hidden');
    });

    // Confirm rename
    document.getElementById('confirmRenameBtn').addEventListener('click', async () => {
      const oldName = document.getElementById('currentProfileName').value;
      const newName = document.getElementById('newProfileName').value.trim();

      if (!newName) {
        showMessage('Please enter a new name', 'error');
        return;
      }

      if (newName === oldName) {
        showMessage('New name must be different', 'error');
        return;
      }

      const base = document.getElementById('apiBase').value;
      try {
        const resp = await fetch(`${base}/profiles/${encodeURIComponent(oldName)}/rename`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ new_name: newName })
        });

        const data = await resp.json();

        if (!resp.ok) {
          throw new Error(data.error || 'Rename failed');
        }

        // Update current profile reference
        if (currentProfile === oldName) {
          currentProfile = newName;
          localStorage.setItem('arguscloud_last_profile', newName);
        }

        // Reload profiles and update selection
        await loadProfiles();
        document.getElementById('profileSelect').value = newName;
        document.getElementById('renameProfileModal').classList.add('hidden');

        showMessage(`Profile renamed: ${oldName} → ${newName}`, 'success');
      } catch (err) {
        showMessage(`Error renaming profile: ${err.message}`, 'error');
      }
    });

    // ============ AWS Collection ============

    let currentCollectJobId = null;
    let collectPollInterval = null;

    // Open collect modal
    document.getElementById('collectBtn').addEventListener('click', () => {
      // Reset form
      document.getElementById('awsAccessKey').value = '';
      document.getElementById('awsSecretKey').value = '';
      document.getElementById('awsSessionToken').value = '';
      document.getElementById('awsRegion').value = '';
      document.getElementById('collectProfileName').value = '';
      document.getElementById('collectForm').classList.remove('hidden');
      document.getElementById('collectProgress').classList.add('hidden');
      document.getElementById('startCollectBtn').disabled = false;
      document.getElementById('startCollectBtn').textContent = 'Start Collection';
      currentCollectJobId = null;
      document.getElementById('collectModal').classList.remove('hidden');
    });

    // Cancel/close collect modal
    document.getElementById('cancelCollectBtn').addEventListener('click', () => {
      if (currentCollectJobId && collectPollInterval) {
        // Cancel job if running
        const base = document.getElementById('apiBase').value;
        fetch(`${base}/collect/${currentCollectJobId}/cancel`, { method: 'POST' }).catch(() => {});
      }
      if (collectPollInterval) {
        clearInterval(collectPollInterval);
        collectPollInterval = null;
      }
      document.getElementById('collectModal').classList.add('hidden');
      // Clear sensitive fields
      document.getElementById('awsAccessKey').value = '';
      document.getElementById('awsSecretKey').value = '';
      document.getElementById('awsSessionToken').value = '';
    });

    // Start collection
    document.getElementById('startCollectBtn').addEventListener('click', async () => {
      const accessKey = document.getElementById('awsAccessKey').value.trim();
      const secretKey = document.getElementById('awsSecretKey').value.trim();
      const sessionToken = document.getElementById('awsSessionToken').value.trim();
      const region = document.getElementById('awsRegion').value;
      const profileName = document.getElementById('collectProfileName').value.trim();

      // Validate
      if (!accessKey || !secretKey) {
        showMessage('Access Key and Secret Key are required', 'error');
        return;
      }

      // Get selected services
      const services = Array.from(document.querySelectorAll('.service-checkbox:checked'))
        .map(cb => cb.value);

      if (services.length === 0) {
        showMessage('Please select at least one service', 'error');
        return;
      }

      // Show progress, hide form
      document.getElementById('collectForm').classList.add('hidden');
      document.getElementById('collectProgress').classList.remove('hidden');
      document.getElementById('startCollectBtn').disabled = true;
      document.getElementById('collectStatusText').textContent = 'Starting collection...';
      document.getElementById('collectProgressText').textContent = `0 / ${services.length} services`;
      document.getElementById('collectProgressBar').style.width = '0%';
      document.getElementById('collectNodeCount').textContent = '0';
      document.getElementById('collectEdgeCount').textContent = '0';
      document.getElementById('collectErrors').classList.add('hidden');

      const base = document.getElementById('apiBase').value;

      try {
        const resp = await fetch(`${base}/collect/aws`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            access_key: accessKey,
            secret_key: secretKey,
            session_token: sessionToken || null,
            region: region || null,
            profile_name: profileName || null,
            services: services
          })
        });

        // Clear credentials from memory immediately
        document.getElementById('awsAccessKey').value = '';
        document.getElementById('awsSecretKey').value = '';
        document.getElementById('awsSessionToken').value = '';

        const data = await resp.json();

        if (!resp.ok) {
          throw new Error(data.error || 'Failed to start collection');
        }

        currentCollectJobId = data.job_id;
        showMessage('Collection started', 'info');

        // Start polling for status
        collectPollInterval = setInterval(() => pollCollectionStatus(services.length), 1000);

      } catch (err) {
        showMessage(`Collection error: ${err.message}`, 'error');
        document.getElementById('collectForm').classList.remove('hidden');
        document.getElementById('collectProgress').classList.add('hidden');
        document.getElementById('startCollectBtn').disabled = false;
      }
    });

    async function pollCollectionStatus(totalServices) {
      if (!currentCollectJobId) return;

      const base = document.getElementById('apiBase').value;
      try {
        const resp = await fetch(`${base}/collect/${currentCollectJobId}`);
        const job = await resp.json();

        if (!resp.ok) {
          throw new Error(job.error || 'Failed to get job status');
        }

        // Update UI
        const progress = job.progress || {};
        const completed = progress.completed_services?.length || 0;
        const percent = totalServices > 0 ? Math.round((completed / totalServices) * 100) : 0;

        document.getElementById('collectProgressText').textContent = `${completed} / ${totalServices} services`;
        document.getElementById('collectProgressBar').style.width = `${percent}%`;
        document.getElementById('collectNodeCount').textContent = progress.nodes_collected || 0;
        document.getElementById('collectEdgeCount').textContent = progress.edges_collected || 0;

        // Status text
        const statusMap = {
          'pending': 'Starting...',
          'validating': 'Validating credentials...',
          'collecting': `Collecting: ${progress.current_service || '...'}`,
          'normalizing': 'Normalizing data...',
          'analyzing': 'Analyzing security...',
          'saving': 'Saving to database...',
          'completed': 'Collection complete!',
          'failed': 'Collection failed',
          'cancelled': 'Collection cancelled'
        };
        document.getElementById('collectStatusText').textContent = statusMap[job.status] || job.status;
        document.getElementById('collectCurrentService').textContent = progress.current_service ? `Service: ${progress.current_service}` : '';

        // Show errors if any
        if (progress.errors?.length > 0) {
          document.getElementById('collectErrors').classList.remove('hidden');
          document.getElementById('collectErrors').innerHTML = progress.errors.map(e => `<div>• ${e}</div>`).join('');
        }

        // Handle completion
        if (job.status === 'completed') {
          clearInterval(collectPollInterval);
          collectPollInterval = null;
          document.getElementById('collectSpinner').innerHTML = '<span style="color: var(--accent-success); font-size: 32px;">✓</span>';
          showMessage(`Collection complete! Profile: ${job.profile_name}`, 'success');

          // Reload profiles and load the new one
          await loadProfiles();
          if (job.profile_name) {
            document.getElementById('profileSelect').value = job.profile_name;
            await loadProfile(job.profile_name);
          }

          // Close modal after delay
          setTimeout(() => {
            document.getElementById('collectModal').classList.add('hidden');
          }, 2000);
        } else if (job.status === 'failed' || job.status === 'cancelled') {
          clearInterval(collectPollInterval);
          collectPollInterval = null;
          document.getElementById('collectSpinner').innerHTML = '<span style="color: var(--accent-danger); font-size: 32px;">✗</span>';
          showMessage(`Collection ${job.status}: ${job.error || 'Unknown error'}`, 'error');
          document.getElementById('startCollectBtn').disabled = false;
          document.getElementById('startCollectBtn').textContent = 'Retry';
        }

      } catch (err) {
        console.error('Poll error:', err);
      }
    }

    // ============ Bulk Upload ============
    let bulkUploadFiles = [];
    let uploadPollInterval = null;
    let currentUploadJobId = null;

    // Open bulk upload modal
    document.getElementById('bulkUploadBtn').addEventListener('click', () => {
      resetBulkUploadModal();
      document.getElementById('bulkUploadModal').classList.remove('hidden');
    });

    // Cancel/close bulk upload modal
    document.getElementById('cancelBulkUploadBtn').addEventListener('click', () => {
      if (uploadPollInterval) {
        clearInterval(uploadPollInterval);
        uploadPollInterval = null;
      }
      document.getElementById('bulkUploadModal').classList.add('hidden');
    });

    // Click outside to close
    document.getElementById('bulkUploadModal').addEventListener('click', (e) => {
      if (e.target.id === 'bulkUploadModal' && !uploadPollInterval) {
        document.getElementById('bulkUploadModal').classList.add('hidden');
      }
    });

    function resetBulkUploadModal() {
      bulkUploadFiles = [];
      currentUploadJobId = null;
      document.getElementById('bulkUploadForm').classList.remove('hidden');
      document.getElementById('bulkUploadProgress').classList.add('hidden');
      document.getElementById('bulkFilePreview').classList.add('hidden');
      document.getElementById('bulkFileList').innerHTML = '';
      document.getElementById('bulkFileCount').textContent = '0 files';
      document.getElementById('bulkFileInput').value = '';
      document.getElementById('startBulkUploadBtn').disabled = true;
      document.getElementById('uploadProfilesCreated').classList.add('hidden');
      document.getElementById('uploadErrors').classList.add('hidden');
    }

    // Drop zone click
    document.getElementById('dropZone').addEventListener('click', () => {
      document.getElementById('bulkFileInput').click();
    });

    // Drag and drop handlers
    const dropZone = document.getElementById('dropZone');

    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      handleBulkFiles(e.dataTransfer.files);
    });

    // File input change
    document.getElementById('bulkFileInput').addEventListener('change', (e) => {
      handleBulkFiles(e.target.files);
    });

    function handleBulkFiles(files) {
      for (const file of files) {
        const ext = file.name.toLowerCase();
        if (ext.endsWith('.zip') || ext.endsWith('.jsonl')) {
          // Avoid duplicates
          if (!bulkUploadFiles.some(f => f.name === file.name && f.size === file.size)) {
            bulkUploadFiles.push(file);
          }
        }
      }
      updateBulkFilePreview();
    }

    function updateBulkFilePreview() {
      const preview = document.getElementById('bulkFilePreview');
      const list = document.getElementById('bulkFileList');
      const count = document.getElementById('bulkFileCount');
      const uploadBtn = document.getElementById('startBulkUploadBtn');

      if (bulkUploadFiles.length === 0) {
        preview.classList.add('hidden');
        uploadBtn.disabled = true;
        return;
      }

      preview.classList.remove('hidden');
      uploadBtn.disabled = false;
      count.textContent = `${bulkUploadFiles.length} file${bulkUploadFiles.length !== 1 ? 's' : ''}`;

      list.innerHTML = bulkUploadFiles.map((f, i) => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px solid var(--border-subtle);">
          <span style="display: flex; align-items: center; gap: 6px;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              ${f.name.endsWith('.zip') ?
                '<path d="M21 8v13H3V8M1 3h22v5H1zM10 12h4"></path>' :
                '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline>'
              }
            </svg>
            ${f.name}
          </span>
          <span style="color: var(--text-tertiary); font-size: 11px;">${formatFileSize(f.size)}</span>
        </div>
      `).join('');
    }

    function formatFileSize(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // Clear bulk files
    document.getElementById('clearBulkFilesBtn').addEventListener('click', () => {
      bulkUploadFiles = [];
      document.getElementById('bulkFileInput').value = '';
      updateBulkFilePreview();
    });

    // Start bulk upload
    document.getElementById('startBulkUploadBtn').addEventListener('click', async () => {
      if (bulkUploadFiles.length === 0) return;

      const base = document.getElementById('apiBase').value;

      // Show progress, hide form
      document.getElementById('bulkUploadForm').classList.add('hidden');
      document.getElementById('bulkUploadProgress').classList.remove('hidden');
      document.getElementById('uploadStatusText').textContent = 'Uploading files...';
      document.getElementById('uploadProgressBar').style.width = '0%';
      document.getElementById('startBulkUploadBtn').disabled = true;

      try {
        // Create FormData with files
        const formData = new FormData();
        for (const file of bulkUploadFiles) {
          formData.append('files[]', file, file.name);
        }

        // Upload files
        const resp = await fetch(`${base}/upload`, {
          method: 'POST',
          body: formData
        });

        if (!resp.ok) {
          const err = await resp.json();
          throw new Error(err.error || `HTTP ${resp.status}`);
        }

        const data = await resp.json();
        currentUploadJobId = data.job_id;

        document.getElementById('uploadStatusText').textContent = 'Processing...';
        document.getElementById('uploadJobStatus').textContent = `Job: ${data.job_id.slice(0, 8)}...`;

        // Start polling for progress
        uploadPollInterval = setInterval(() => pollUploadStatus(), 1000);

      } catch (err) {
        document.getElementById('uploadStatusText').textContent = `Upload failed: ${err.message}`;
        document.getElementById('uploadProgressBar').style.background = 'var(--accent-danger)';
        document.getElementById('uploadProgressBar').style.width = '100%';
        showMessage(`Bulk upload failed: ${err.message}`, 'error');
      }
    });

    async function pollUploadStatus() {
      if (!currentUploadJobId) return;

      const base = document.getElementById('apiBase').value;

      try {
        const resp = await fetch(`${base}/upload/${currentUploadJobId}`);
        if (!resp.ok) throw new Error('Failed to get job status');

        const job = await resp.json();
        const progress = job.progress || {};

        // Update progress display
        const processed = progress.processed_files || 0;
        const total = progress.total_files || 1;
        const percent = Math.round((processed / total) * 100);

        document.getElementById('uploadProgressBar').style.width = `${percent}%`;
        document.getElementById('uploadProgressText').textContent = `${processed} / ${total} profiles`;

        if (progress.current_file) {
          document.getElementById('uploadCurrentFile').textContent = `Processing: ${progress.current_file}`;
        }

        // Show profiles created
        if (progress.profiles_created && progress.profiles_created.length > 0) {
          document.getElementById('uploadProfilesCreated').classList.remove('hidden');
          document.getElementById('uploadProfilesList').innerHTML = progress.profiles_created.map(p =>
            `<div style="padding: 2px 0;">${p}</div>`
          ).join('');
        }

        // Show errors
        if (progress.errors && progress.errors.length > 0) {
          document.getElementById('uploadErrors').classList.remove('hidden');
          document.getElementById('uploadErrors').innerHTML = progress.errors.map(e =>
            `<div style="padding: 2px 0;">${e}</div>`
          ).join('');
        }

        // Check completion
        if (job.status === 'completed') {
          clearInterval(uploadPollInterval);
          uploadPollInterval = null;

          document.getElementById('uploadStatusText').innerHTML = '<span style="color: var(--accent-success);">Upload Complete!</span>';
          document.getElementById('uploadCurrentFile').textContent = '';

          const profilesCreated = progress.profiles_created || [];
          if (profilesCreated.length > 0) {
            showMessage(`Created ${profilesCreated.length} profile(s): ${profilesCreated.join(', ')}`, 'success');

            // Reload profiles
            await loadProfiles();

            // Load the first created profile
            if (profilesCreated.length > 0) {
              document.getElementById('profileSelect').value = profilesCreated[0];
              await loadProfile(profilesCreated[0]);
            }
          }

          // Close modal after delay
          setTimeout(() => {
            document.getElementById('bulkUploadModal').classList.add('hidden');
          }, 2000);

        } else if (job.status === 'failed') {
          clearInterval(uploadPollInterval);
          uploadPollInterval = null;

          document.getElementById('uploadStatusText').innerHTML = '<span style="color: var(--accent-danger);">Upload Failed</span>';
          document.getElementById('uploadProgressBar').style.background = 'var(--accent-danger)';
          showMessage(`Bulk upload failed`, 'error');
        }

      } catch (err) {
        console.error('Upload poll error:', err);
      }
    }

    // Import tab switching
    document.querySelectorAll('.import-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.import-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentImportMode = tab.dataset.tab;

        document.querySelectorAll('.import-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById(`import-${currentImportMode}`).classList.remove('hidden');

        // Clear file preview when switching modes
        selectedFiles.clear();
        updateFilePreview();
      });
    });

    // Multi-file input handler
    document.getElementById('multiFiles').addEventListener('change', (e) => {
      processMultipleFiles(e.target.files);
    });

    // ZIP file input handler
    document.getElementById('zipFile').addEventListener('change', async (e) => {
      if (e.target.files.length > 0) {
        await processZipFile(e.target.files[0]);
      }
    });

    // Folder input handler
    document.getElementById('folderInput').addEventListener('change', (e) => {
      processMultipleFiles(e.target.files);
    });

    // Load button
    document.getElementById('loadBtn').addEventListener('click', async () => {
      try {
        const data = await loadSelectedFiles();
        if (!data) return;

        nodes = data.nodes;
        edges = data.edges;

        if (!nodes.length && !edges.length) {
          showMessage('No data found in uploaded files');
          return;
        }

        // Update available filter options from loaded data
        updateAvailableFilterOptions();

        showMessage(`Loaded ${nodes.length} nodes and ${edges.length} edges`, 'success');
        buildGraph(nodes, edges);
        renderAttacks(edges);
        renderStats(nodes);
        renderEnvList(nodes);

        // Auto-save to profile with generated name
        const profileName = generateProfileName();
        showMessage(`Saving to profile: ${profileName}...`, 'info');

        const result = await saveProfile(profileName, 'overwrite');
        if (result.success) {
          document.getElementById('profileSelect').value = profileName;
          showMessage(`Saved as profile: ${profileName}`, 'success');
        } else if (result.error) {
          showMessage(`Data loaded but save failed: ${result.error}`, 'error');
        }

        // Switch to graph tab
        switchTab('graph');
      } catch (err) {
        showMessage(`Error loading files: ${err.message}`, 'error');
      }
    });

    document.getElementById('filterBtn').addEventListener('click', () => {
      if (!nodes.length && !edges.length) return;
      // Apply advanced filters
      const filtered = applyFilters(nodes, edges);
      buildGraph(filtered.nodes, filtered.edges);
      renderAttacks(filtered.edges);
      showMessage(`Showing ${filtered.nodes.length} nodes, ${filtered.edges.length} edges`, 'success');
    });

    // Clear all data
    document.getElementById('clearBtn').addEventListener('click', () => {
      // Clear data
      nodes = [];
      edges = [];
      selectedFiles.clear();

      // Clear graph
      if (cy) {
        cy.destroy();
        cy = null;
      }

      // Clear UI elements
      document.getElementById('filePreview').classList.add('hidden');
      document.getElementById('fileList').innerHTML = '';
      document.getElementById('multiFiles').value = '';
      document.getElementById('zipFile').value = '';
      document.getElementById('folderInput').value = '';
      document.querySelector('#attacksTable tbody').innerHTML = '<tr><td colspan="4" class="empty-state" style="padding: 32px;"><p>No attack paths loaded</p></td></tr>';
      document.getElementById('statsGrid').innerHTML = '<div class="empty-state">No data loaded</div>';
      document.getElementById('envList').innerHTML = '';

      // Reset graph container
      document.getElementById('cy').innerHTML = '<div class="empty-state" style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-tertiary);">Load data to visualize the graph</div>';

      showMessage('All data cleared', 'success');
    });

    document.getElementById('fetchApiBtn').addEventListener('click', async () => {
      const base = document.getElementById('apiBase').value;
      try {
        const resp = await fetch(`${base}/graph?limit=1000`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        nodes = data.nodes || [];
        edges = data.edges || [];

        buildGraph(nodes, edges);
        renderAttacks(edges);
        renderStats(nodes);
        renderEnvList(nodes);
        updateStatus(true, true);
        switchTab('graph');
      } catch (err) {
        showMessage(`API fetch failed: ${err.message}`);
        updateStatus(false, false);
      }
    });

    document.getElementById('runCypherBtn').addEventListener('click', async () => {
      const base = document.getElementById('apiBase').value;
      const cypher = document.getElementById('cypherInput').value;
      const status = document.getElementById('cypherStatus');
      const output = document.getElementById('cypherOutput');

      status.textContent = 'Running...';
      status.className = 'cypher-status';

      try {
        const resp = await fetch(`${base}/query`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ cypher, limit: 200 })
        });
        const data = await resp.json();

        if (!resp.ok) {
          status.textContent = `Error: ${data.error || resp.status}`;
          status.className = 'cypher-status error';
          return;
        }

        status.textContent = `Success - ${(data.results || []).length} results`;
        status.className = 'cypher-status success';
        output.textContent = JSON.stringify(data.results || [], null, 2);

        // Highlight results in the graph
        if (cy && data.results && data.results.length > 0) {
          highlightCypherResults(data.results, cypher);
        }
      } catch (err) {
        status.textContent = `Error: ${err.message}`;
        status.className = 'cypher-status error';
      }
    });

    // Highlight Cypher query results in the graph with attack paths
    function highlightCypherResults(results, query) {
      if (!cy) return;

      // Clear previous highlighting
      cy.elements().removeClass('highlighted path-node path-edge');

      const matchedNodeIds = new Set();
      const matchedPaths = [];

      // Extract node IDs and paths from results
      results.forEach(row => {
        // Handle different result structures
        Object.values(row).forEach(val => {
          if (!val) return;

          // Direct node ID string
          if (typeof val === 'string' && val.includes(':')) {
            matchedNodeIds.add(val);
          }
          // Node object with id
          else if (val.id) {
            matchedNodeIds.add(val.id);
          }
          // Path result (array of nodes)
          else if (Array.isArray(val)) {
            const pathIds = val.map(n => typeof n === 'string' ? n : n?.id).filter(Boolean);
            if (pathIds.length > 1) {
              matchedPaths.push(pathIds);
            }
            pathIds.forEach(id => matchedNodeIds.add(id));
          }
          // Extract from ARN-like strings
          else if (typeof val === 'string' && val.includes('arn:aws')) {
            matchedNodeIds.add(val);
          }
        });
      });

      // If query contains RETURN path, try to build paths from results
      const isPathQuery = query.toLowerCase().includes('return path') ||
                          query.toLowerCase().includes('return p') ||
                          query.toLowerCase().includes('*1..') ||
                          query.toLowerCase().includes('*2..');

      if (matchedNodeIds.size === 0) {
        showMessage('No matching nodes found in graph', 'info');
        return;
      }

      // Highlight matched nodes
      matchedNodeIds.forEach(nodeId => {
        const node = cy.getElementById(nodeId);
        if (!node.empty()) {
          node.addClass('highlighted path-node');
        }
      });

      // For path queries or admin queries, find and highlight paths between matched nodes
      if (isPathQuery && matchedPaths.length > 0) {
        highlightPaths(matchedPaths);
      } else if (matchedNodeIds.size >= 2) {
        // Try to find attack path edges connecting matched nodes
        const matchedNodesArr = [...matchedNodeIds];
        const connectedEdges = cy.edges().filter(edge => {
          const srcId = edge.source().id();
          const tgtId = edge.target().id();
          return matchedNodeIds.has(srcId) && matchedNodeIds.has(tgtId);
        });

        if (!connectedEdges.empty()) {
          connectedEdges.addClass('highlighted path-edge');
        }

        // Also find any edges TO or FROM matched nodes to show context
        const contextEdges = cy.edges().filter(edge => {
          const srcId = edge.source().id();
          const tgtId = edge.target().id();
          return matchedNodeIds.has(srcId) || matchedNodeIds.has(tgtId);
        });

        // Highlight context edges with a different style (attack paths)
        contextEdges.filter(e => e.data('type') === 'AttackPath' || e.hasClass('attack'))
                    .addClass('highlighted path-edge');
      }

      // Fit view to highlighted elements
      const highlighted = cy.$('.highlighted');
      if (!highlighted.empty()) {
        cy.fit(highlighted, 50);
        showMessage(`Highlighted ${matchedNodeIds.size} node(s) and their attack paths`, 'success');
      }
    }

    document.getElementById('downloadReportBtn').addEventListener('click', () => {
      const attacks = edges.filter(e => e.type === 'AttackPath');
      const counts = {};
      nodes.forEach(n => { counts[n.type] = (counts[n.type] || 0) + 1; });

      const report = {
        generated_at: new Date().toISOString(),
        summary: {
          total_nodes: nodes.length,
          total_edges: edges.length,
          attack_paths: attacks.length,
          resource_counts: counts
        },
        attack_paths: attacks,
        sample_nodes: nodes.slice(0, 100)
      };

      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `arguscloud-report-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });

    // Tab switching
    function switchTab(tabName) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelector(`.tab[data-tab="${tabName}"]`).classList.add('active');

      ['graph', 'env', 'data', 'settings'].forEach(t => {
        const el = document.getElementById(`tab-${t}`);
        if (el) el.classList.toggle('hidden', t !== tabName);
      });

      if (tabName === 'graph' && cy) cy.resize();
    }

    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Theme toggle
    document.getElementById('themeToggle').addEventListener('click', () => {
      document.body.classList.toggle('light');
      document.getElementById('theme').value = document.body.classList.contains('light') ? 'light' : 'dark';
      if (cy) {
        cy.style(getCyStyle());
      }
    });

    document.getElementById('theme').addEventListener('change', (e) => {
      document.body.classList.toggle('light', e.target.value === 'light');
      if (cy) {
        cy.style(getCyStyle());
      }
    });

    // Fullscreen
    document.getElementById('fullscreenBtn').addEventListener('click', () => {
      const card = document.getElementById('graphCard');
      isFullscreen = !isFullscreen;
      card.classList.toggle('graph-fullscreen', isFullscreen);
      document.getElementById('fullscreenBtn').textContent = isFullscreen ? 'Exit Fullscreen' : 'Fullscreen';
      if (cy) cy.resize();
    });

    // Reset layout
    document.getElementById('resetLayoutBtn').addEventListener('click', () => {
      if (cy) {
        cy.layout({ name: document.getElementById('layoutSelect').value, animate: true }).run();
      }
    });

    // Layout change
    document.getElementById('layoutSelect').addEventListener('change', () => {
      if (cy) {
        cy.layout({ name: document.getElementById('layoutSelect').value, animate: true }).run();
      }
    });

    // Label position change
    document.getElementById('labelPos').addEventListener('change', () => {
      if (cy) {
        cy.style(getCyStyle());
      }
    });

    // Graph resizer
    const resizer = document.getElementById('graphResizer');
    let isResizing = false;

    resizer.addEventListener('mousedown', (e) => {
      isResizing = true;
      e.preventDefault();
    });

    window.addEventListener('mousemove', (e) => {
      if (!isResizing) return;
      const cyEl = document.getElementById('cy');
      const rect = cyEl.getBoundingClientRect();
      const newH = Math.min(900, Math.max(300, e.clientY - rect.top));
      cyEl.style.height = `${newH}px`;
      if (cy) cy.resize();
    });

    window.addEventListener('mouseup', () => { isResizing = false; });

    // Escape key for fullscreen
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && isFullscreen) {
        document.getElementById('fullscreenBtn').click();
      }
    });

    // ============ Sidebar Resize Functionality ============
    function initSidebarResize() {
      const sidebar = document.getElementById('filterSidebar');
      const resizeHandle = document.getElementById('sidebarResizeHandle');
      const layout = document.querySelector('.layout');

      if (!sidebar || !resizeHandle) return;

      let isResizingSidebar = false;
      let startX = 0;
      let startWidth = 0;

      // Load saved width from localStorage
      const savedWidth = localStorage.getItem('arguscloud_sidebar_width');
      if (savedWidth) {
        const width = parseInt(savedWidth, 10);
        if (width >= 260 && width <= 600) {
          sidebar.style.width = `${width}px`;
          layout.style.gridTemplateColumns = `${width}px 1fr`;
        }
      }

      resizeHandle.addEventListener('mousedown', (e) => {
        isResizingSidebar = true;
        startX = e.clientX;
        startWidth = sidebar.offsetWidth;
        document.body.classList.add('sidebar-resizing');
        resizeHandle.classList.add('dragging');
        e.preventDefault();
      });

      document.addEventListener('mousemove', (e) => {
        if (!isResizingSidebar) return;

        const deltaX = e.clientX - startX;
        let newWidth = startWidth + deltaX;

        // Clamp to min/max
        newWidth = Math.max(260, Math.min(600, newWidth));

        sidebar.style.width = `${newWidth}px`;
        layout.style.gridTemplateColumns = `${newWidth}px 1fr`;

        // Resize Cytoscape if active
        if (cy) {
          cy.resize();
        }
      });

      document.addEventListener('mouseup', () => {
        if (isResizingSidebar) {
          isResizingSidebar = false;
          document.body.classList.remove('sidebar-resizing');
          resizeHandle.classList.remove('dragging');

          // Save width to localStorage
          localStorage.setItem('arguscloud_sidebar_width', sidebar.offsetWidth.toString());
        }
      });

      // Double-click to reset to default width
      resizeHandle.addEventListener('dblclick', () => {
        sidebar.style.width = '280px';
        layout.style.gridTemplateColumns = '280px 1fr';
        localStorage.removeItem('arguscloud_sidebar_width');
        if (cy) cy.resize();
      });
    }

    // Initial status check and profile loading
    (async function init() {
      const base = document.getElementById('apiBase').value;

      // Check API status
      try {
        const resp = await fetch(`${base}/health`);
        const data = await resp.json();
        updateStatus(data.status === 'ok', data.status === 'ok');
      } catch {
        updateStatus(false, false);
      }

      // Initialize sidebar resize functionality
      initSidebarResize();

      // Initialize advanced filter system
      initFilters();

      // Initialize AWS attack query categories
      initQueryCategories();

      // Load profiles list
      await loadProfiles();

      // Auto-load last used profile
      const lastProfile = localStorage.getItem('arguscloud_last_profile');
      if (lastProfile && profiles.some(p => p.name === lastProfile)) {
        document.getElementById('profileSelect').value = lastProfile;
        await loadProfile(lastProfile);
      }
    })();
  </script>
