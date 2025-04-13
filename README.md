# 🏛️ cloudius-iam-lite


![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)



**Scan IAM roles for wildcard permissions and identify risky configurations in seconds.**

A free, lightweight command-line tool for AWS users to detect over-permissive IAM policies across their account. Ideal for small teams, solo engineers, or anyone wanting to tighten IAM security fast.

## Features (Free Edition)

- Scans IAM roles across your AWS account
- Flags risky policies containing:
  - `"Action": "*"`
  - `"Resource": "*"`
- Displays up to:
  - 10 roles with risky policies
  - 10 roles with no detected issues
- Works with any AWS CLI profile (just needs read access to IAM)
- Optional summary flag: `--summary`

## Usage

```bash
python cloudius-iam-lite.py --profile your-aws-profile-name [--region eu-central-1] [--summary]
```

### Example Output
```
AWS Session successfully created. Profile: my-dev-profile in region eu-central-1

[!] - Role: EC2AutoTagger
   → Attached policy 'AmazonEC2SpotFleetTaggingRole' contains wildcard

[!] - Role: QuickSightDataRole
   → Attached policy 'AWSQuicksightAthenaAccess' contains wildcard
   → Attached policy 'AWSQuickSightRedshiftPolicy' contains wildcard
   → Attached policy 'AWSQuickSightIAMPolicy' contains wildcard
   → Attached policy 'AWSQuickSightRDSPolicy' contains wildcard

[!] - Role: PowerAdminSSO
   → Attached policy 'AdministratorAccess' contains wildcard

[OK] - Role: AnalyticsLambdaExecutor
   → No wildcards detected

⚠️ Free version limited to 10 flagged + 10 OK roles.

📬 **Want deeper scans or export options?**
💡 Open a [GitHub Issue](https://github.com/your-org/cloudius-iam-lite/issues) and let us know what you need!

```

## Requirements
- Python 3.11+
- `boto3` and `colorama` installed:

```bash
pip install -r requirements.txt
```

## Setup

1. Clone the repository
2. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the tool:
   ```bash
   python cloudius-iam-.ite.py --profile your-profile-name
   ```

## License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute this code — just retain the copyright notice.

See the [LICENSE](./LICENSE) file for details.

