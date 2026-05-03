# 🛡️ AI-Powered AWS Cloud Security Scanner

An agentless, least-privilege cloud security posture management (CSPM) tool built with Python, Boto3, and Google Gemini AI. 

This tool scans an AWS environment for common misconfigurations and generates a responsive, interactive HTML report complete with an AI-generated Executive Summary.

## 🚀 Features
* **Agentless Scanning:** Uses AWS APIs (Boto3) directly—no agents to install on EC2 instances.
* **Least Privilege Design:** Operates entirely on `ReadOnlyAccess` and strict IAM policies.
* **AI Executive Summary:** Integrates with Google Gemini via AWS Secrets Manager to analyze findings and write a CTO-level summary.
* **Interactive HTML Report:** Sort, filter, and search vulnerabilities by severity directly in the browser.

## 🔍 Checks Performed
* **IAM:** Stale access keys (>90 days), `AdministratorAccess` overuse.
* **S3:** Public Access Blocks, Public ACLs.
* **EC2 & VPC:** Open Security Groups (0.0.0.0/0 on SSH/RDP/DB ports), Public IPs, UserData secrets.
* **RDS:** Publicly accessible databases.
* **KMS & CloudTrail:** Key rotation disabled, Missing multi-region trails.

## 🛠️ Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/cloud-aws-scanner.git](https://github.com/YOUR_USERNAME/cloud-aws-scanner.git)
   cd cloud-aws-scanner