import boto3
import datetime
import json
import argparse
import google.generativeai as genai

class CloudAWSCloudScanner:
    def __init__(self, profile=None, regions=None):
        self.session = boto3.Session(profile_name=profile)
        ec2_client = self.session.client('ec2')
        self.regions = regions or [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        self.findings = []
        
    def log(self, severity, title, resource, details="", region="global", remediation=""):
        risk_score = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[severity]
        self.findings.append({
            "severity": severity,
            "title": title,
            "resource": resource,
            "region": region,
            "details": details,
            "remediation": remediation,
            "score": risk_score
        })
        emoji = "🔴" if severity == "HIGH" else "🟠" if severity == "MEDIUM" else "🟡"
        print(f"{emoji} [{severity}] {title} → {resource} ({region})")

    # ==================== Scan Functions ====================

    def scan_s3(self):
        print("🔍 Scanning S3 buckets...")
        s3 = self.session.client('s3')
        try:
            buckets = s3.list_buckets()['Buckets']
            for b in buckets:
                name = b['Name']
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    pab_conf = pab['PublicAccessBlockConfiguration']
                    if not all([pab_conf.get(k, False) for k in ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']]):
                        self.log("MEDIUM", "S3 Public Access Block not fully enabled", name,
                                 remediation="Go to S3 Console → Bucket → Permissions → Block public access → Turn ON all four options.")
                except:
                    pass
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get('Grants', []):
                        if grant.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            self.log("HIGH", "Publicly accessible S3 bucket (ACL)", name,
                                     remediation="S3 Console → Bucket → Permissions → ACL → Remove 'Everyone'/'AllUsers'. Enable Block Public Access.")
                except:
                    pass
        except Exception as e:
            print(f"  ⚠️ S3 scan error: {e}")

    def scan_security_groups(self):
        print("🔍 Scanning Security Groups...")
        risky_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379]
        for region in self.regions:
            ec2 = self.session.client('ec2', region_name=region)
            try:
                sgs = ec2.describe_security_groups()['SecurityGroups']
                for sg in sgs:
                    sg_id = sg['GroupId']
                    for perm in sg.get('IpPermissions', []):
                        for ipr in perm.get('IpRanges', []):
                            if ipr.get('CidrIp') == '0.0.0.0/0':
                                from_port = perm.get('FromPort')
                                if from_port in risky_ports or from_port is None:
                                    self.log("HIGH", f"World-open Security Group (port {from_port or 'all'})", sg_id,
                                             region=region,
                                             remediation="EC2 → Security Groups → Edit inbound rules → Change source from 0.0.0.0/0 to specific IP or Security Group.")
            except:
                continue

    def scan_iam(self):
        print("🔍 Scanning IAM...")
        iam = self.session.client('iam')
        try:
            users = iam.list_users()['Users']
            for user in users:
                name = user['UserName']
                try:
                    policies = iam.list_attached_user_policies(UserName=name)['AttachedPolicies']
                    for p in policies:
                        if "AdministratorAccess" in p['PolicyName']:
                            self.log("HIGH", "User has AdministratorAccess policy", name,
                                     remediation="IAM → Users → Select user → Permissions → Detach AdministratorAccess. Apply least-privilege policy.")
                except:
                    pass
                try:
                    keys = iam.list_access_keys(UserName=name)['AccessKeyMetadata']
                    for key in keys:
                        age = (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days
                        if age > 90:
                            self.log("MEDIUM", "Access key older than 90 days", f"{name}/{key['AccessKeyId']}",
                                     remediation="IAM → Users → Security credentials → Delete or rotate old access keys.")
                except:
                    pass
        except Exception as e:
            print(f"  ⚠️ IAM scan error: {e}")

    def scan_ec2(self):
        print("🔍 Scanning EC2 instances...")
        for region in self.regions:
            ec2 = self.session.client('ec2', region_name=region)
            try:
                instances = ec2.describe_instances(Filters=[{'Name': 'instance-state.name', 'Values': ['running']}])['Reservations']
                for res in instances:
                    for inst in res['Instances']:
                        instance_id = inst['InstanceId']
                        if inst.get('PublicIpAddress'):
                            self.log("MEDIUM", "EC2 instance with public IP", instance_id,
                                     remediation="Move instance to private subnet and use Systems Manager Session Manager or bastion host.")
                        try:
                            userdata = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute='userData')['UserData']
                            if userdata and userdata.get('Value'):
                                self.log("MEDIUM", "EC2 instance has User Data", instance_id,
                                         remediation="Review User Data for secrets. Use AWS Secrets Manager instead.")
                        except:
                            pass
            except:
                continue

    def scan_lambda(self):
        print("🔍 Scanning Lambda functions...")
        for region in self.regions:
            lambda_client = self.session.client('lambda', region_name=region)
            try:
                functions = lambda_client.list_functions()['Functions']
                for func in functions:
                    func_name = func['FunctionName']
                    try:
                        policy = lambda_client.get_policy(FunctionName=func_name)
                        if policy and 'Policy' in policy and '"Principal": "*"' in policy['Policy']:
                            self.log("HIGH", "Lambda function has public invoke permission", func_name,
                                     remediation="Lambda Console → Configuration → Permissions → Resource-based policy → Remove wildcard (*) principal.")
                    except:
                        pass
            except:
                continue

    def scan_rds(self):
        print("🔍 Scanning RDS databases...")
        for region in self.regions:
            rds = self.session.client('rds', region_name=region)
            try:
                instances = rds.describe_db_instances()['DBInstances']
                for db in instances:
                    db_id = db['DBInstanceIdentifier']
                    if db.get('PubliclyAccessible'):
                        self.log("HIGH", "RDS instance is publicly accessible", db_id,
                                 remediation="RDS Console → Modify → Connectivity → Set Public access to 'No'.")
            except:
                continue

    def scan_ebs_snapshots(self):
        print("🔍 Scanning EBS snapshots...")
        for region in self.regions:
            ec2 = self.session.client('ec2', region_name=region)
            try:
                snapshots = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
                for snap in snapshots:
                    snap_id = snap['SnapshotId']
                    if snap.get('CreateVolumePermission'):
                        if any(p.get('Group') == 'all' for p in snap.get('CreateVolumePermission', [])):
                            self.log("HIGH", "Public EBS Snapshot", snap_id,
                                     remediation="EC2 → Snapshots → Modify permissions → Remove public access.")
            except:
                continue

    def scan_kms(self):
        print("🔍 Scanning KMS keys...")
        for region in self.regions:
            kms = self.session.client('kms', region_name=region)
            try:
                keys = kms.list_keys()['Keys']
                for key in keys:
                    key_id = key['KeyId']
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get('KeyRotationEnabled', False):
                            self.log("MEDIUM", "KMS key rotation disabled", key_id,
                                     remediation="KMS Console → Select key → Enable automatic key rotation.")
                    except:
                        pass
            except:
                continue

    def scan_cloudtrail(self):
        print("🔍 Scanning CloudTrail...")
        cloudtrail = self.session.client('cloudtrail')
        try:
            trails = cloudtrail.describe_trails()['trailList']
            if not trails:
                self.log("HIGH", "No CloudTrail trails configured", "Global",
                         remediation="CloudTrail Console → Create a new multi-region trail with logging enabled.")
            else:
                multi_region = any(t.get('IsMultiRegionTrail', False) for t in trails)
                if not multi_region:
                    self.log("MEDIUM", "CloudTrail not multi-region", "Global",
                             remediation="Edit trail and enable 'Apply trail to all regions'.")
        except Exception as e:
            print(f"  ⚠️ CloudTrail scan error: {e}")

    # ==================== AI Integration ====================
    
    def get_secret(self):
        """Fetches the Gemini API key from AWS Secrets Manager securely"""
        secret_name = "grok-scanner/api-keys"
        # Use the configured region, fallback to the first available region if undefined
        region = self.session.region_name if self.session.region_name else self.regions[0]
        client = self.session.client(service_name='secretsmanager', region_name=region)

        try:
            get_secret_value_response = client.get_secret_value(SecretId=secret_name)
            secret_string = get_secret_value_response['SecretString']
            secret_dict = json.loads(secret_string)
            return secret_dict.get('GEMINI_API_KEY')
        except Exception as e:
            print(f"  ⚠️ Failed to retrieve secret from AWS: {e}")
            return None

    def generate_ai_executive_summary(self):
        print("🧠 Retrieving API Key from AWS Secrets Manager...")
        api_key = self.get_secret()
        
        if not api_key:
            print("  ⚠️ Could not fetch API key. Skipping AI summary.")
            return "<p class='text-red-400'>AI Summary unavailable. Could not retrieve API key from AWS Secrets Manager.</p>"

        if not self.findings:
            return "<p class='text-green-400'>No vulnerabilities found. The AWS environment is currently secure.</p>"

        print("🧠 Generating AI Executive Summary via Google Gemini...")
        
        # Configure the AI using the dynamically fetched key
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash')

        summary_data = [{"severity": f["severity"], "issue": f["title"], "resource": f["resource"]} for f in self.findings]

        prompt = f"""
        You are an expert AWS Cloud Security Architect. Review the following JSON list of security vulnerabilities found in an AWS account:
        {json.dumps(summary_data)}

        Write a concise, professional Executive Summary for a CTO. 
        Format it using HTML tags (like <b>, <p>, <ul>, <li>) so it renders nicely in a web report.
        Focus on:
        1. The overall security posture.
        2. The most critical risks that need immediate attention.
        3. A brief strategic recommendation for remediation.
        Do not use markdown, ONLY valid HTML snippets. Do not include ```html blocks.
        """

        try:
            response = model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            print(f"  ⚠️ AI Generation failed: {e}")
            return f"<p class='text-red-400'>AI Summary generation failed due to an API error: {e}</p>"

    # ==================== Enhanced HTML Report ====================
    
    def generate_html_report(self):
        # Fetch the AI summary first
        ai_summary_html = self.generate_ai_executive_summary()

        high = len([f for f in self.findings if f['severity'] == 'HIGH'])
        medium = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
        low = len([f for f in self.findings if f['severity'] == 'LOW'])
        total = len(self.findings)
        risk_score = round((high * 3 + medium * 2 + low * 1) / max(total, 1) * 33.3, 1)  # 0-100 scale

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud AWS Security Scan Report</title>
    <script src="[https://cdn.tailwindcss.com](https://cdn.tailwindcss.com)"></script>
    <link rel="stylesheet" href="[https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css](https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css)">
    <style>
        body {{ background: #0f172a; color: #e2e8f0; }}
        .finding-row {{ transition: all 0.2s; }}
        .finding-row:hover {{ background-color: #1e2937; transform: scale(1.01); }}
        .ai-content p {{ margin-bottom: 0.75rem; }}
        .ai-content ul {{ list-style-type: disc; margin-left: 1.5rem; margin-bottom: 0.75rem; }}
    </style>
</head>
<body class="min-h-screen p-6">
    <div class="max-w-7xl mx-auto">
        <div class="flex justify-between items-center mb-8">
            <div>
                <h1 class="text-4xl font-bold text-blue-400 flex items-center gap-3">
                    <i class="fas fa-shield-alt"></i> Cloud AWS Security Scanner
                </h1>
                <p class="text-slate-400 mt-1">Comprehensive Cloud Security Posture Report</p>
            </div>
            <div class="text-right">
                <button onclick="window.print()" 
                        class="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded-lg flex items-center gap-2">
                    <i class="fas fa-print"></i> Print Report
                </button>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-5 gap-6 mb-10">
            <div class="bg-slate-800 p-6 rounded-2xl">
                <div class="text-slate-400 text-sm">Overall Risk Score</div>
                <div class="text-5xl font-bold mt-2 { 'text-red-400' if risk_score > 60 else 'text-orange-400' if risk_score > 30 else 'text-green-400' }">{risk_score}</div>
                <div class="w-full bg-slate-700 h-2 rounded mt-4">
                    <div class="h-2 rounded {'bg-red-500' if risk_score > 60 else 'bg-orange-500' if risk_score > 30 else 'bg-green-500'}" 
                         style="width: {risk_score}%"></div>
                </div>
            </div>
            <div class="bg-slate-800 p-6 rounded-2xl">
                <div class="flex justify-between">
                    <div><i class="fas fa-exclamation-triangle text-red-400 text-2xl"></i></div>
                    <div class="text-right">
                        <div class="text-4xl font-bold text-red-400">{high}</div>
                        <div class="text-sm text-slate-400">High Severity</div>
                    </div>
                </div>
            </div>
            <div class="bg-slate-800 p-6 rounded-2xl">
                <div class="flex justify-between">
                    <div><i class="fas fa-exclamation-circle text-orange-400 text-2xl"></i></div>
                    <div class="text-right">
                        <div class="text-4xl font-bold text-orange-400">{medium}</div>
                        <div class="text-sm text-slate-400">Medium Severity</div>
                    </div>
                </div>
            </div>
            <div class="bg-slate-800 p-6 rounded-2xl">
                <div class="flex justify-between">
                    <div><i class="fas fa-info-circle text-yellow-400 text-2xl"></i></div>
                    <div class="text-right">
                        <div class="text-4xl font-bold text-yellow-400">{low}</div>
                        <div class="text-sm text-slate-400">Low Severity</div>
                    </div>
                </div>
            </div>
            <div class="bg-slate-800 p-6 rounded-2xl flex items-center justify-center">
                <div class="text-center">
                    <div class="text-5xl font-bold">{total}</div>
                    <div class="text-slate-400">Total Findings</div>
                </div>
            </div>
        </div>

        <!-- AI Executive Summary Section -->
        <div class="bg-gradient-to-r from-indigo-900 to-slate-800 p-8 rounded-3xl mb-10 border border-indigo-500/30 shadow-lg shadow-indigo-500/10">
            <h2 class="text-2xl font-bold text-indigo-300 mb-4 flex items-center gap-2">
                <i class="fas fa-robot"></i> AI Executive Summary
            </h2>
            <div class="text-slate-200 leading-relaxed ai-content">
                {ai_summary_html}
            </div>
        </div>

        <!-- Controls -->
        <div class="flex flex-col md:flex-row gap-4 mb-6">
            <input type="text" id="searchInput" 
                   onkeyup="filterTable()" 
                   placeholder="Search findings..." 
                   class="flex-1 bg-slate-800 border border-slate-600 rounded-xl px-5 py-3 focus:outline-none focus:border-blue-500">
            
            <div class="flex gap-3">
                <button onclick="filterBySeverity('all')" 
                        class="px-5 py-3 bg-slate-700 hover:bg-slate-600 rounded-xl">All</button>
                <button onclick="filterBySeverity('HIGH')" 
                        class="px-5 py-3 bg-red-900/30 hover:bg-red-900/50 text-red-400 rounded-xl">High</button>
                <button onclick="filterBySeverity('MEDIUM')" 
                        class="px-5 py-3 bg-orange-900/30 hover:bg-orange-900/50 text-orange-400 rounded-xl">Medium</button>
                <button onclick="filterBySeverity('LOW')" 
                        class="px-5 py-3 bg-yellow-900/30 hover:bg-yellow-900/50 text-yellow-400 rounded-xl">Low</button>
            </div>
        </div>

        <!-- Findings Table -->
        <div class="bg-slate-800 rounded-3xl overflow-hidden">
            <table class="w-full" id="findingsTable">
                <thead>
                    <tr class="bg-slate-900">
                        <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(0)">Severity</th>
                        <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(1)">Title</th>
                        <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(2)">Resource</th>
                        <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(3)">Region</th>
                        <th class="py-5 px-6 text-left">Remediation</th>
                    </tr>
                </thead>
                <tbody>
"""

        for finding in sorted(self.findings, key=lambda x: x['score'], reverse=True):
            color = "text-red-400" if finding['severity'] == "HIGH" else "text-orange-400" if finding['severity'] == "MEDIUM" else "text-yellow-400"
            html_content += f"""
                    <tr class="finding-row border-t border-slate-700">
                        <td class="py-5 px-6">
                            <span class="font-bold {color}">{finding['severity']}</span>
                        </td>
                        <td class="py-5 px-6 font-medium">{finding['title']}</td>
                        <td class="py-5 px-6 text-slate-300">{finding['resource']}</td>
                        <td class="py-5 px-6 text-slate-400">{finding['region']}</td>
                        <td class="py-5 px-6 text-slate-300 text-sm">{finding.get('remediation', 'Review in AWS Console')}</td>
                    </tr>
"""

        html_content += f"""
                </tbody>
            </table>
        </div>

        <div class="text-center text-slate-500 text-sm mt-10">
            Generated by Cloud Simple AWS Cloud Security Scanner • Agentless • {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>

    <script>
        function filterTable() {{
            const input = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('#findingsTable tbody tr');
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(input) ? '' : 'none';
            }});
        }}

        function filterBySeverity(severity) {{
            const rows = document.querySelectorAll('#findingsTable tbody tr');
            rows.forEach(row => {{
                if (severity === 'all') {{
                    row.style.display = '';
                }} else {{
                    const sevCell = row.cells[0].textContent.trim();
                    row.style.display = sevCell === severity ? '' : 'none';
                }}
            }});
        }}

        function sortTable(col) {{
            const table = document.getElementById("findingsTable");
            let switching = true;
            while (switching) {{
                switching = false;
                const rows = table.rows;
                for (let i = 1; i < (rows.length - 1); i++) {{
                    let shouldSwitch = false;
                    const x = rows[i].getElementsByTagName("TD")[col];
                    const y = rows[i + 1].getElementsByTagName("TD")[col];
                    if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {{
                        shouldSwitch = true;
                        break;
                    }}
                }}
                if (shouldSwitch) {{
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                }}
            }}
        }}
    </script>
</body>
</html>
"""

        with open("aws-security-report.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print("📄 Enhanced interactive HTML report generated: aws-security-report.html")
        print("   Open the file in your browser to view the AI summary, filters, and nice visuals!")

    # ==================== Run Full Scan ====================
    def run_full_scan(self):
        print("\n🚀 Starting Cloud Simple AWS Cloud Security Scanner (Enhanced AI Edition)...\n")
        
        self.scan_s3()
        self.scan_security_groups()
        self.scan_iam()
        self.scan_ec2()
        self.scan_lambda()
        self.scan_rds()
        self.scan_ebs_snapshots()
        self.scan_kms()
        self.scan_cloudtrail()
        
        print(f"\n✅ Scan complete! Found {len(self.findings)} findings.\n")
        
        self.findings.sort(key=lambda x: x['score'], reverse=True)
        
        # Save JSON
        report = {
            "summary": {
                "total_findings": len(self.findings), 
                "high": len([f for f in self.findings if f['severity'] == "HIGH"]),
                "medium": len([f for f in self.findings if f['severity'] == "MEDIUM"]), 
                "low": len([f for f in self.findings if f['severity'] == "LOW"])
            },
            "findings": self.findings,
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "Cloud AWS Scanner - Enhanced AI Report"
        }
        
        with open("aws-security-report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        self.generate_html_report()
        
        print("\n🔥 Top 10 findings:")
        for f in self.findings[:10]:
            print(f"   {f['severity']} | {f['title']} → {f['resource']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud Simple AWS Cloud Security Scanner")
    parser.add_argument("--profile", help="AWS CLI profile name", default=None)
    parser.add_argument("--regions", help="Comma-separated list of regions (default: all)", default=None)
    args = parser.parse_args()
    
    regions = args.regions.split(",") if args.regions else None
    scanner = CloudAWSCloudScanner(profile=args.profile, regions=regions)
    scanner.run_full_scan()