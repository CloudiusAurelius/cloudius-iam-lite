# _tests/test_iam_integration.py
# 🧪 Unit Tests for IAM Role + Policy Fetch Functions (Mocked)
# 
# This test suite covers two key integration functions in iam_role_analyzer.py:
#
# 1. fetch_all_roles(iam):
#    - Ensures pagination is handled correctly
#    - Simulates IAM client returning multiple pages of roles
#
# 2. get_all_policies_for_role(iam, role_name):
#    - Ensures inline and attached policies are both returned
#    - Verifies correct dictionary structure of results
#
# These tests mock the boto3 IAM client, so no real AWS calls are made.
# Date: 2025-04-11

import pytest
from unittest.mock import MagicMock
from cloudius_iam_lite import fetch_all_roles, get_all_policies_for_role

def test_fetch_all_roles_handles_pagination():
    """Simulates paginated IAM response and ensures roles are accumulated correctly."""
    mock_iam = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {'Roles': [{'RoleName': 'RoleA'}, {'RoleName': 'RoleB'}]},
        {'Roles': [{'RoleName': 'RoleC'}]}
    ]
    mock_iam.get_paginator.return_value = paginator

    roles = fetch_all_roles(mock_iam)
    role_names = [r['RoleName'] for r in roles]

    assert len(roles) == 3
    assert "RoleA" in role_names
    assert "RoleC" in role_names

def test_get_all_policies_for_role_returns_correct_data():
    """Tests inline and attached policy fetching."""
    mock_iam = MagicMock()
    mock_iam.list_role_policies.return_value = {
        'PolicyNames': ['InlinePolicy1']
    }
    mock_iam.list_attached_role_policies.return_value = {
        'AttachedPolicies': [{'PolicyName': 'ManagedPolicy1', 'PolicyArn': 'arn:aws:iam::123:policy/ManagedPolicy1'}]
    }

    inline, attached = get_all_policies_for_role(mock_iam, 'TestRole')

    assert inline == ['InlinePolicy1']
    assert attached[0]['PolicyName'] == 'ManagedPolicy1'
