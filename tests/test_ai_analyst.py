"""Unit tests for AI Analyst Engine and MCP Tool Registry."""

import unittest
import sys
import os

# Add required paths to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../services/workflow/src")))

from dcim_workflow.ai_analyst import (
    AIAnalystEngine,
    AIAnalystVerdict,
    MCPSOARToolRegistry,
    AIAnalystError,
)


class TestAIAnalystEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AIAnalystEngine()
        self.mcp = MCPSOARToolRegistry()

    def test_parse_json_llm_response(self):
        raw = '{"verdict": "true_positive", "confidence": 0.95, "mitre_tactics": ["T1059.001"], "summary": "Malicious script executed"}'
        verdict = self.engine.parse_llm_response(raw)
        self.assertEqual(verdict.verdict, "true_positive")
        self.assertEqual(verdict.confidence, 0.95)
        self.assertIn("T1059.001", verdict.mitre_tactics)

    def test_parse_markdown_fenced_json(self):
        raw = """Here is the SOC analysis verdict:
```json
{
    "verdict": "false_positive",
    "confidence": 0.90,
    "mitre_tactics": [],
    "summary": "Authorized admin activity"
}
```
Follow up if needed."""
        verdict = self.engine.parse_llm_response(raw)
        self.assertEqual(verdict.verdict, "false_positive")
        self.assertEqual(verdict.confidence, 0.90)

    def test_fallback_text_parsing(self):
        raw = "This alert is a TRUE POSITIVE attack detected on host 198.51.100.5 using T1078 credentials."
        verdict = self.engine.parse_llm_response(raw)
        self.assertEqual(verdict.verdict, "true_positive")
        self.assertIn("T1078", verdict.mitre_tactics)
        self.assertEqual(verdict.recommended_playbook, "containment_host_isolation")

    def test_empty_llm_response(self):
        verdict = self.engine.parse_llm_response("")
        self.assertEqual(verdict.verdict, "inconclusive")
        self.assertEqual(verdict.confidence, 0.5)

    def test_analyze_alert_by_rule_level(self):
        alert_high = {"data": {"rule": {"level": 12}}}
        verdict_high = self.engine.analyze_alert(alert_high)
        self.assertEqual(verdict_high.verdict, "true_positive")

        alert_low = {"data": {"rule": {"level": 3}}}
        verdict_low = self.engine.analyze_alert(alert_low)
        self.assertEqual(verdict_low.verdict, "false_positive")

    def test_mcp_list_tools(self):
        tools = self.mcp.list_tools()
        self.assertIn("tools", tools)
        tool_names = [t["name"] for t in tools["tools"]]
        self.assertIn("query_threat_intel", tool_names)
        self.assertIn("check_misp_ioc", tool_names)
        self.assertIn("recommend_containment_playbook", tool_names)

    def test_mcp_call_tool_threat_intel(self):
        res = self.mcp.call_tool("query_threat_intel", {"ioc_type": "hash", "value": "a1b2c3d4"})
        self.assertIn("content", res)
        self.assertIn("malicious", res["content"][0]["text"])

    def test_mcp_call_tool_ot_playbook_recommendation(self):
        res_it = self.mcp.call_tool("recommend_containment_playbook", {"asset_type": "it_workstation"})
        self.assertIn("containment_host_isolation", res_it["content"][0]["text"])

        res_ot = self.mcp.call_tool("recommend_containment_playbook", {"asset_type": "ot_plc"})
        self.assertIn("ot_critical_safety_block", res_ot["content"][0]["text"])

    def test_mcp_unknown_tool_raises(self):
        with self.assertRaises(AIAnalystError):
            self.mcp.call_tool("invalid_tool", {})


if __name__ == "__main__":
    unittest.main()
