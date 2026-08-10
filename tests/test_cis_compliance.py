"""Tests for CIS Benchmark Compliance Assessment Engine (SI-06)."""

import unittest

from scripts.cis_compliance_report import (
    CISCheckStatus,
    CISComplianceReport,
    CISRuleCheck,
    evaluate_wazuh_sca_payload,
)


class TestCISComplianceAssessment(unittest.TestCase):
    def test_cis_compliance_report_calculation(self) -> None:
        report = CISComplianceReport(
            agent_id="001",
            agent_name="synthetic-server-01",
            os_platform="Ubuntu 22.04 LTS",
            benchmark_title="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0",
        )

        report.checks.extend([
            CISRuleCheck(
                rule_id="5.2.1",
                title="Ensure permissions on /etc/ssh/sshd_config are configured",
                description="Permissions on sshd_config must be 600 or more restrictive",
                rationale="Protect SSH daemon configuration from unauthorized modification",
                level="Level 1",
                status=CISCheckStatus.PASS,
                remediation="chmod 600 /etc/ssh/sshd_config",
            ),
            CISRuleCheck(
                rule_id="5.2.2",
                title="Ensure SSH Protocol is set to 2",
                description="SSH v1 protocol is vulnerable to MITM attacks",
                rationale="Enforce SSH v2 protocol only",
                level="Level 1",
                status=CISCheckStatus.PASS,
                remediation="Protocol 2 in /etc/ssh/sshd_config",
            ),
            CISRuleCheck(
                rule_id="5.2.3",
                title="Ensure SSH PermitRootLogin is disabled",
                description="Direct root SSH access increases risk of brute force",
                rationale="Require non-privileged login before escalation",
                level="Level 1",
                status=CISCheckStatus.FAIL,
                remediation="PermitRootLogin no in /etc/ssh/sshd_config",
            ),
            CISRuleCheck(
                rule_id="1.1.1.1",
                title="Ensure mounting of cramfs filesystems is disabled",
                description="Unneeded filesystems increase attack surface",
                rationale="Disable unused filesystems",
                level="Level 2",
                status=CISCheckStatus.PASS,
                remediation="modprobe -n -v cramfs",
            ),
        ])

        self.assertEqual(report.total_checks, 4)
        self.assertEqual(report.passed_checks, 3)
        self.assertEqual(report.failed_checks, 1)
        self.assertEqual(report.compliance_score, 75.0)

        summary = report.summary()
        self.assertEqual(summary["compliance_score_percent"], 75.0)
        self.assertEqual(summary["passed"], 3)
        self.assertEqual(summary["failed"], 1)

    def test_evaluate_wazuh_sca_payload_parsing(self) -> None:
        raw_sca_event = {
            "agent": {
                "id": "005",
                "name": "gateway-router-01",
            },
            "sca": {
                "name": "CIS Debian Linux 11 Benchmark",
                "policy": "CIS Debian 11 Benchmark v1.0.0",
                "checks": [
                    {
                        "id": "1.1.1",
                        "title": "Ensure /tmp is configured",
                        "result": "passed",
                        "description": "Separate partition for /tmp",
                    },
                    {
                        "id": "1.1.2",
                        "title": "Ensure nodev option set on /tmp",
                        "result": "failed",
                        "description": "Prevent device files in /tmp",
                    },
                ],
            },
        }

        report = evaluate_wazuh_sca_payload(raw_sca_event)

        self.assertEqual(report.agent_id, "005")
        self.assertEqual(report.agent_name, "gateway-router-01")
        self.assertEqual(report.total_checks, 2)
        self.assertEqual(report.passed_checks, 1)
        self.assertEqual(report.failed_checks, 1)
        self.assertEqual(report.compliance_score, 50.0)


if __name__ == "__main__":
    unittest.main()
