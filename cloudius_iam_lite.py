"""
Script: iam_role_analyzer.py
Purpose: Scans all IAM roles in the current AWS account and flags any that have over-permissive IAM policies.
         Specifically, it identifies policies with "Action": "*" or "Resource": "*".

Date: 2025-04-13
Author: Cloudius Aurelius

Usage:
    python cloudius-iam-lite.py --profile your-aws-profile-name [--region eu-central-1] [--summary]

Environment:
    Run this script from a local terminal or any environment where the AWS CLI is configured
    and has read access to IAM (ListRoles, GetRolePolicy, ListAttachedRolePolicies, etc.).

Setup:
    1. Create and activate a virtual environment (optional but recommended):
       python -m venv venv
       source venv/bin/activate  # On Windows: venv\\Scripts\\activate

    2. Install dependencies:
       pip install -r requirements.txt

    3. Run the script using the appropriate AWS profile:
       python iam_role_analyzer.py --profile your-profile-name
"""

import boto3
from colorama import Fore, Style, init
import argparse
import sys

# Initialize colorama
init(autoreset=True)

# Free version caps
MAX_RISKY = 10
MAX_OK = 10

def print_banner():
    print("""
    =========================================
    Cloudius IAM Lite ▸ v0.1.0 ▸ Free Edition
    Scan IAM roles for wildcard permissions and risks
    =========================================
    """)

def create_aws_session(profile_name, region_name='eu-central-1'):
    """
    Create a scoped AWS session using the specified profile and optional region.
    """
    try:
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        print(f"AWS Session successfully created. Profile: {profile_name} in region {region_name}")
        return session
    except Exception as e:
        print(f"Error creating session for profile {profile_name}: {e}")
        return None

def fetch_all_roles(iam):
    """
    Fetch all IAM roles in the AWS account using pagination.
    """
    paginator = iam.get_paginator('list_roles')
    roles = []
    for page in paginator.paginate():
        roles.extend(page['Roles'])
    return roles

def get_all_policies_for_role(iam, role_name):
    """
    Retrieve inline and attached managed policies for a given IAM role.
    """
    inline_policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    return inline_policies, attached_policies

def is_policy_risky(policy_doc):
    """
    Analyze a policy document and flag it as risky if it contains wildcard actions or resources.
    """
    for stmt in policy_doc.get('Statement', []):
        if stmt.get('Effect') != 'Allow':
            continue
        actions = stmt.get('Action', [])
        resources = stmt.get('Resource', [])
        if isinstance(actions, str): actions = [actions]
        if isinstance(resources, str): resources = [resources]
        if "*" in actions or "*" in resources:
            return True
    return False

def main():
    """
    Main function that scans all IAM roles and evaluates their policies for over-permissive access.
    """
    print_banner()

    try:
        parser = argparse.ArgumentParser(description='Scan IAM roles for risky policies')
        parser.add_argument('--profile', required=True, help='AWS CLI profile to use')
        parser.add_argument('--region', help='Optional AWS region')
        parser.add_argument('--summary', action='store_true', help='Print summary of risky vs. safe roles')
        args = parser.parse_args()
    except Exception as e:
        print(f"Argument error: {e}")
        sys.exit(1)

    session = create_aws_session(profile_name=args.profile, region_name=args.region)
    if not session:
        return

    iam = session.client('iam')
    roles = fetch_all_roles(iam)

    risky_count = 0
    safe_count = 0

    for role in roles:
        if risky_count >= MAX_RISKY and safe_count >= MAX_OK:
            break

        role_name = role['RoleName']
        inline_policies, attached_policies = get_all_policies_for_role(iam, role_name)
        risky = False
        messages = []

        # Inline policies
        for name in inline_policies:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)['PolicyDocument']
            if is_policy_risky(doc):
                messages.append(f"→ Inline policy '{name}' contains wildcard")
                risky = True

        # Managed policies
        for ap in attached_policies:
            policy_arn = ap['PolicyArn']
            versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
            default = next(v for v in versions if v['IsDefaultVersion'])
            doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default['VersionId'])['PolicyVersion']['Document']
            if is_policy_risky(doc):
                messages.append(f"→ Attached policy '{ap['PolicyName']}' contains wildcard")
                risky = True

        # Output per role
        if risky and risky_count < MAX_RISKY:
            print(f"{Fore.RED}[!] - Role: {role_name}{Style.RESET_ALL}")
            for line in messages:
                print(f"  {line}")
            risky_count += 1
        elif not risky and safe_count < MAX_OK:
            print(f"{Fore.GREEN}[OK] - Role: {role_name}{Style.RESET_ALL}")
            print("  → No wildcards detected")
            safe_count += 1

    print("\n⚠️ Free version limited to 10 flagged + 10 OK roles.")
    print("📬 Need more? Open a GitHub Issue to suggest features or share feedback.\n")

    if args.summary:
        total = risky_count + safe_count
        print("\n--- Summary ---")
        print(f"Total IAM Roles Analyzed: {total}")
        print(f"Roles With Risky Policies: {risky_count}")
        print(f"Roles With Safe Policies: {safe_count}")

if __name__ == "__main__":
    main()

