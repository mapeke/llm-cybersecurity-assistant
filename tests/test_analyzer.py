import sys
import unittest
from pathlib import Path
import logging

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

# Import modules to test
from utils.threat_analyzer import ThreatAnalyzer

# Disable logging output during tests
logging.disable(logging.CRITICAL)

class TestThreatAnalyzer(unittest.TestCase):
    """Tests for the ThreatAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = ThreatAnalyzer()
    
    def test_analyze_text_query(self):
        """Test basic text query analysis"""
        query = "What are common indicators of a phishing attack?"
        response = self.analyzer.analyze_text_query(query)
        
        # Check response structure
        self.assertIn("answer", response)
        self.assertIn("confidence", response)
        
        # Check that answer is not empty
        self.assertTrue(len(response["answer"]) > 0)
        
        # Check confidence score is in expected range
        self.assertGreaterEqual(response["confidence"], 0.0)
        self.assertLessEqual(response["confidence"], 1.0)
    
    def test_analyze_wazuh_alert(self):
        """Test Wazuh alert analysis"""
        # Sample alert data
        alert_data = {
            "id": "12345",
            "rule": {
                "id": "31501",
                "description": "Windows login attempt using explicit credentials."
            },
            "agent": {
                "name": "workstation01"
            },
            "timestamp": "2025-04-20T10:30:45.123Z",
            "description": "Suspicious login detected"
        }
        
        response = self.analyzer.analyze_wazuh_alert(alert_data)
        
        # Check response structure
        self.assertIn("answer", response)
        self.assertIn("confidence", response)
        
        # Check that answer contains analysis
        self.assertTrue(len(response["answer"]) > 0)
    
    def test_generate_remediation_steps(self):
        """Test remediation steps generation"""
        threat_type = "ransomware"
        steps = self.analyzer.generate_remediation_steps(threat_type)
        
        # Check that steps are returned as a list
        self.assertIsInstance(steps, list)
        
        # Check that steps are not empty
        self.assertTrue(len(steps) > 0)
    
    def test_generate_security_policy(self):
        """Test security policy generation"""
        policy_type = "password"
        policy = self.analyzer.generate_security_policy(policy_type)
        
        # Check response structure
        self.assertIn("policy_type", policy)
        self.assertIn("policy_content", policy)
        self.assertIn("confidence", policy)
        
        # Check that policy content is not empty
        self.assertTrue(len(policy["policy_content"]) > 0)
        
        # Check policy type matches request
        self.assertEqual(policy["policy_type"], policy_type)


if __name__ == "__main__":
    unittest.main()