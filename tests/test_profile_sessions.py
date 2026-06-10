"""Tests for profile-aware session creation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import src.collector.base as base_mod
from src.collector.base import (
    get_current_account_id,
    get_management_session,
    get_session_for_account,
)


def _reset_mgmt_cache():
    """Clear the cached management account ID between tests."""
    base_mod._mgmt_account_id = None


class TestGetManagementSession:
    """Tests for get_management_session()."""

    def test_with_profile(self):
        """When profile is set, session uses profile_name."""
        sentinel_session = MagicMock()
        with patch("src.collector.base.settings") as mock_settings:
            mock_settings.aws.profile = "Master"
            with patch("src.collector.base.boto3.Session") as mock_cls:
                mock_cls.return_value = sentinel_session
                session = get_management_session()
                mock_cls.assert_called_once_with(profile_name="Master")
                assert session is sentinel_session

    def test_without_profile(self):
        """When profile is empty, session uses default credentials."""
        sentinel_session = MagicMock()
        with patch("src.collector.base.settings") as mock_settings:
            mock_settings.aws.profile = ""
            with patch("src.collector.base.boto3.Session") as mock_cls:
                mock_cls.return_value = sentinel_session
                session = get_management_session()
                mock_cls.assert_called_once_with()
                assert session is sentinel_session


class TestGetCurrentAccountId:
    """Tests for get_current_account_id() using management session."""

    def setup_method(self):
        _reset_mgmt_cache()

    def teardown_method(self):
        _reset_mgmt_cache()

    def test_uses_management_session(self):
        """get_current_account_id delegates to the management session."""
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "111222333444",
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_sts

        with patch(
            "src.collector.base.get_management_session",
            return_value=mock_session,
        ):
            account_id = get_current_account_id()

        assert account_id == "111222333444"
        mock_session.client.assert_called_once()

    def test_caches_result(self):
        """Second call returns cached value without STS call."""
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "111222333444",
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_sts

        with patch(
            "src.collector.base.get_management_session",
            return_value=mock_session,
        ):
            first = get_current_account_id()
            second = get_current_account_id()

        assert first == second == "111222333444"
        # STS called only once despite two invocations
        mock_sts.get_caller_identity.assert_called_once()


class TestGetSessionForAccount:
    """Tests for get_session_for_account() with profile support."""

    def setup_method(self):
        _reset_mgmt_cache()

    def teardown_method(self):
        _reset_mgmt_cache()

    def test_single_account_returns_management_session(self):
        """Without cross-account role, returns management session."""
        mock_session = MagicMock()

        with (
            patch("src.collector.base.settings") as mock_settings,
            patch(
                "src.collector.base.get_management_session",
                return_value=mock_session,
            ),
        ):
            mock_settings.aws.cross_account_role_name = ""
            result = get_session_for_account("123456789012")

        assert result is mock_session

    def test_skips_assume_role_for_management_account(self):
        """When target is the management account, skip assume-role."""
        mock_session = MagicMock()

        with (
            patch("src.collector.base.settings") as mock_settings,
            patch(
                "src.collector.base.get_management_session",
                return_value=mock_session,
            ),
            patch(
                "src.collector.base.get_current_account_id",
                return_value="123456789012",
            ),
        ):
            mock_settings.aws.cross_account_role_name = "OrganizationAccessRole"
            mock_settings.aws.mgmt_account_id = ""
            mock_settings.aws.ssl_verify = False
            result = get_session_for_account("123456789012")

        assert result is mock_session
        # No assume_role call should have been made
        mock_session.client.return_value.assume_role.assert_not_called()

    def test_multi_account_assumes_role_via_management_session(self):
        """With cross-account role, uses management session for STS."""
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKID",
                "SecretAccessKey": "SECRET",
                "SessionToken": "TOKEN",
            },
        }
        mock_mgmt_session = MagicMock()
        mock_mgmt_session.client.return_value = mock_sts
        sentinel_session = MagicMock()

        with (
            patch("src.collector.base.settings") as mock_settings,
            patch(
                "src.collector.base.get_management_session",
                return_value=mock_mgmt_session,
            ),
            patch(
                "src.collector.base.get_current_account_id",
                return_value="123456789012",
            ),
            patch("src.collector.base.boto3.Session") as mock_cls,
        ):
            mock_settings.aws.cross_account_role_name = "OrganizationAccessRole"
            mock_settings.aws.ssl_verify = False
            mock_cls.return_value = sentinel_session

            result = get_session_for_account("999888777666")

        mock_sts.assume_role.assert_called_once()
        call_kwargs = mock_sts.assume_role.call_args[1]
        assert "999888777666" in call_kwargs["RoleArn"]
        assert "OrganizationAccessRole" in call_kwargs["RoleArn"]

        mock_cls.assert_called_once_with(
            aws_access_key_id="AKID",
            aws_secret_access_key="SECRET",
            aws_session_token="TOKEN",
        )
        assert result is sentinel_session
