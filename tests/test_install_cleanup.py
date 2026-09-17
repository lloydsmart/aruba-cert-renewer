"""Installation cleanup failures use synthetic CLI responses, never a device."""

import unittest
from unittest.mock import Mock, call

import aruba_cert_renewer as checker


def make_connection():
    connection = Mock()
    connection.send_command.side_effect = [
        "webcert2027 Web CSR webprofile2026\n",
        "webcert2027 Web 2027/02/02 webprofile2026\n",
        "Certificate Detail:\nVersion: 3 (0x2)\n",
    ]
    connection.send_command_timing.side_effect = [
        checker.CERTIFICATE_PASTE_PROMPT,
        "Certificate installed",
    ]
    connection.read_channel_timing.return_value = checker.CERTIFICATE_REPLACEMENT_PROMPT
    return connection


def install(connection):
    # This dialogue-level unit test starts after the caller's certificate checks.
    # No real certificate, credential, transport, or crypto operation is needed.
    checker.install_signed_certificate(
        connection,
        "webcert2027",
        "synthetic public certificate\n",
        "webprofile2026",
    )


class TestInstallCleanup(unittest.TestCase):
    def test_success_exits_config_mode_before_post_install_verification(self):
        connection = make_connection()

        install(connection)

        self.assertEqual(
            connection.mock_calls,
            [
                call.send_command("show crypto pki local-certificate summary"),
                call.config_mode(),
                call.send_command_timing(
                    "crypto pki install-signed-certificate", read_timeout=30
                ),
                call.write_channel("synthetic public certificate\n"),
                call.write_channel("\n"),
                call.read_channel_timing(read_timeout=60),
                call.send_command_timing("y", read_timeout=60),
                call.exit_config_mode(),
                call.send_command("show crypto pki local-certificate summary"),
                call.send_command(
                    "show crypto pki local-certificate webcert2027", read_timeout=30
                ),
            ],
        )

    def test_exit_error_after_confirmation_reports_possible_installation(self):
        for error_type in (OSError, RuntimeError):
            with self.subTest(error_type=error_type):
                connection = make_connection()
                exit_error = error_type("transport failed")
                connection.exit_config_mode.side_effect = exit_error

                with self.assertRaisesRegex(
                    checker.CertificateInstallationAttemptError,
                    "may already have changed.*config mode could not be exited",
                ) as raised:
                    install(connection)

                self.assertIs(raised.exception.__cause__, exit_error)
                connection.exit_config_mode.assert_called_once_with()
                self.assertEqual(connection.send_command.call_count, 1)
                self.assertEqual(
                    connection.send_command_timing.call_args_list,
                    [
                        call("crypto pki install-signed-certificate", read_timeout=30),
                        call("y", read_timeout=60),
                    ],
                )

    def test_exit_error_preserves_the_original_prompt_failure(self):
        for stage in ("paste", "replacement"):
            with self.subTest(stage=stage):
                connection = make_connection()
                connection.exit_config_mode.side_effect = OSError("cleanup failed")
                if stage == "paste":
                    connection.send_command_timing.side_effect = ["Unexpected prompt"]
                    expected_error = "expected certificate-paste prompt"
                else:
                    connection.read_channel_timing.return_value = "Unexpected prompt"
                    expected_error = "expected certificate-replacement prompt"

                with self.assertRaisesRegex(
                    checker.CertificateInstallationAttemptError, expected_error
                ) as raised:
                    install(connection)

                self.assertIsInstance(raised.exception.__cause__, ValueError)
                self.assertIn(expected_error, str(raised.exception.__cause__))
                connection.exit_config_mode.assert_called_once_with()
                connection.send_command_timing.assert_called_once_with(
                    "crypto pki install-signed-certificate", read_timeout=30
                )
                self.assertEqual(connection.send_command.call_count, 1)

    def test_failure_entering_config_mode_does_not_attempt_install_or_exit(self):
        connection = make_connection()
        entry_error = OSError("config mode unavailable")
        connection.config_mode.side_effect = entry_error

        with self.assertRaises(OSError) as raised:
            install(connection)

        self.assertIs(raised.exception, entry_error)
        connection.exit_config_mode.assert_not_called()
        connection.send_command_timing.assert_not_called()
        connection.write_channel.assert_not_called()

    def test_exit_error_does_not_replace_an_interruption(self):
        connection = make_connection()
        interruption = KeyboardInterrupt()
        connection.send_command_timing.side_effect = interruption
        connection.exit_config_mode.side_effect = OSError("cleanup failed")

        with self.assertRaises(KeyboardInterrupt) as raised:
            install(connection)

        self.assertIs(raised.exception, interruption)
        connection.exit_config_mode.assert_called_once_with()
        self.assertEqual(connection.send_command_timing.call_count, 1)
        connection.write_channel.assert_not_called()

    def test_callers_handled_exception_does_not_hide_exit_failure(self):
        connection = make_connection()
        connection.exit_config_mode.side_effect = OSError("cleanup failed")

        try:
            raise ValueError("unrelated caller exception")
        except ValueError:
            with self.assertRaisesRegex(
                checker.CertificateInstallationAttemptError,
                "config mode could not be exited",
            ):
                install(connection)
