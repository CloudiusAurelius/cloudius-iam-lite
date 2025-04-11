# _tests/test_policy_checks.py
# Unit tests for is_policy_risky() from iam_role_analyzer.py
# Evaluates the policy evalluation logic
# Date: 2025-04-11

import pytest
from cloudius_iam_lite import is_policy_risky

def test_allows_wildcard_action_and_resource():
    """Test if policy with both '*' in Action and Resource is flagged as risky."""
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }
    assert is_policy_risky(policy) is True

def test_allows_specific_action_and_wildcard_resource():
    """Test if policy with wildcard Resource is flagged as risky."""
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }]
    }
    assert is_policy_risky(policy) is True

def test_allows_wildcard_action_and_specific_resource():
    """Test if policy with wildcard Action is flagged as risky."""
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "arn:aws:s3:::example_bucket/*"
        }]
    }
    assert is_policy_risky(policy) is True

def test_allows_specific_action_and_resource():
    """Test if a safe policy is not flagged as risky."""
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::example_bucket/*"
        }]
    }
    assert is_policy_risky(policy) is False

def test_denies_wildcard_action():
    """Test if Deny effect is ignored (should not be flagged)."""
    policy = {
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }]
    }
    assert is_policy_risky(policy) is False

def test_multiple_statements_some_risky():
    """Test if one risky statement makes the policy risky."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:StartInstances",
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "arn:aws:s3:::secure-bucket"
            }
        ]
    }
    assert is_policy_risky(policy) is True

