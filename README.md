# 🏛️ cloudius-iam-lite

**Scan IAM roles for wildcard permissions and identify risky configurations in seconds.**

A free, lightweight command-line tool for AWS users to detect over-permissive IAM policies across their account. Ideal for small teams, solo engineers, or anyone wanting to tighten IAM security fast.

## 🚀 Features (Free Edition)

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
python iam_role_analyzer.py --profile your-aws-profile-name [--region eu-central-1] [--summary]
```

### Example Output
```
🔐 Risky Roles (limited to 10):
- Role: AdminRole
  → Attached policy 'AdministratorAccess' contains wildcard

✅ Roles with No Detected Issues (limited to 10):
- Role: ReadOnlyLambda
  → No wildcards detected

⚠️ This free tool displays up to 10 flagged + 10 OK roles.
💡 Need more? Open a [GitHub Issue](https://github.com/your-org/cloudius-iam-lite/issues) to suggest features or share feedback.
```

## Requirements
- Python 3.7+
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
   python iam_role_analyzer.py --profile your-profile-name
   ```

## License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute this code — just retain the copyright notice.

See the [LICENSE](./LICENSE) file for details.

