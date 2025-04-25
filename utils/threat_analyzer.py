import logging
from typing import Dict, List, Any, Optional, Union, Tuple
import json
import sys
from pathlib import Path

# Import project modules
sys.path.append(str(Path(__file__).parent.parent))
from config import config
from utils.llm_module import get_llm_instance
from integrations.wazuh.client import get_wazuh_client
from integrations.splunk.client import get_splunk_client

# Set up logging
logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    """Class for analyzing security threats using LLM and security tool integrations"""
    
    def __init__(self):
        self.llm = get_llm_instance()
        self.wazuh = get_wazuh_client() if config["integrations"]["wazuh"]["enabled"] else None
        self.splunk = get_splunk_client() if config["integrations"]["splunk"]["enabled"] else None
    
    def analyze_text_query(self, query: str) -> Dict[str, Any]:
        """Analyze a text query related to cybersecurity"""
        try:
            logger.info(f"Analyzing text query: {query}")
            
            # Prepare context with baseline cybersecurity knowledge
            context = {
                "query_type": "text",
                "domain": "cybersecurity"
            }
            
            # Generate response using LLM
            response = self.llm.generate_response(query, context)
            return response
        except Exception as e:
            logger.error(f"Error analyzing text query: {str(e)}")
            return {
                "answer": "I encountered an error analyzing your query.",
                "confidence": 0.0,
                "error": str(e)
            }
    
    def analyze_wazuh_alert(self, alert_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze a Wazuh security alert using LLM"""
        try:
            logger.info("Analyzing Wazuh alert")
            
            # Convert dict to string if needed
            if isinstance(alert_data, dict):
                alert_text = json.dumps(alert_data, indent=2)
            else:
                alert_text = alert_data
            
            # Prepare the query with instructions
            query = (
                "Analyze this security alert from Wazuh and provide: \n"
                "1. A summary of the alert\n"
                "2. The potential severity (low, medium, high, critical)\n"
                "3. Recommended actions\n\n"
                f"Alert: {alert_text}"
            )
            
            # Prepare context
            context = {
                "query_type": "alert_analysis",
                "source": "wazuh",
                "domain": "cybersecurity"
            }
            
            # Generate response using LLM
            response = self.llm.generate_response(query, context)
            return response
        except Exception as e:
            logger.error(f"Error analyzing Wazuh alert: {str(e)}")
            return {
                "answer": "I encountered an error analyzing the alert.",
                "confidence": 0.0,
                "error": str(e)
            }
    
    def analyze_splunk_event(self, event_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze a Splunk security event using LLM"""
        try:
            logger.info("Analyzing Splunk event")
            
            # Convert dict to string if needed
            if isinstance(event_data, dict):
                event_text = json.dumps(event_data, indent=2)
            else:
                event_text = event_data
            
            # Prepare the query with instructions
            query = (
                "Analyze this security event from Splunk and provide: \n"
                "1. A summary of what happened\n"
                "2. The potential security implications\n"
                "3. Recommended follow-up actions\n\n"
                f"Event: {event_text}"
            )
            
            # Prepare context
            context = {
                "query_type": "event_analysis",
                "source": "splunk",
                "domain": "cybersecurity"
            }
            
            # Generate response using LLM
            response = self.llm.generate_response(query, context)
            return response
        except Exception as e:
            logger.error(f"Error analyzing Splunk event: {str(e)}")
            return {
                "answer": "I encountered an error analyzing the event.",
                "confidence": 0.0,
                "error": str(e)
            }
    
    def get_recent_security_insights(self, hours_back: int = 24) -> Dict[str, Any]:
        """Get insights from recent security data across integrated tools"""
        insights = {
            "summary": "",
            "wazuh_insights": None,
            "splunk_insights": None,
            "recommendations": []
        }
        
        # Get data from integrations if available
        wazuh_data = None
        splunk_data = None
        
        if self.wazuh:
            try:
                wazuh_data = self.wazuh.get_formatted_alerts(limit=10)
                insights["wazuh_insights"] = "Wazuh data collected successfully"
            except Exception as e:
                logger.error(f"Error getting Wazuh data: {str(e)}")
                insights["wazuh_insights"] = f"Error getting Wazuh data: {str(e)}"
        
        if self.splunk:
            try:
                splunk_data = self.splunk.get_formatted_security_events(hours_back=hours_back, max_count=10)
                insights["splunk_insights"] = "Splunk data collected successfully"
            except Exception as e:
                logger.error(f"Error getting Splunk data: {str(e)}")
                insights["splunk_insights"] = f"Error getting Splunk data: {str(e)}"
        
        # Combine data and analyze with LLM
        combined_data = ""
        if wazuh_data:
            combined_data += f"--- WAZUH ALERTS ---\n{wazuh_data}\n\n"
        if splunk_data:
            combined_data += f"--- SPLUNK EVENTS ---\n{splunk_data}\n\n"
        
        if combined_data:
            query = (
                "Based on the following security data, provide:\n"
                "1. A summary of the current security status\n"
                "2. Key findings and potential threats\n"
                "3. Recommended actions\n\n"
                f"{combined_data}"
            )
            
            context = {
                "query_type": "security_insights",
                "domain": "cybersecurity",
                "timeframe": f"last {hours_back} hours"
            }
            
            try:
                response = self.llm.generate_response(query, context)
                insights["summary"] = response.get("answer", "No insights generated")
                
                # Extract recommendations (simplified)
                lines = insights["summary"].split("\n")
                in_recommendations = False
                for line in lines:
                    if "recommend" in line.lower() or "action" in line.lower():
                        in_recommendations = True
                    if in_recommendations and line.strip().startswith("-"):
                        insights["recommendations"].append(line.strip()[2:])
            except Exception as e:
                logger.error(f"Error generating security insights: {str(e)}")
                insights["summary"] = f"Error generating security insights: {str(e)}"
        else:
            insights["summary"] = "No security data available from integrations."
            
        return insights
    
    def generate_remediation_steps(self, threat_type: str) -> List[str]:
        """Generate remediation steps for a specific type of security threat"""
        try:
            logger.info(f"Generating remediation steps for: {threat_type}")
            
            query = f"Provide a step-by-step remediation plan for a {threat_type} attack or threat. Include specific actions, tools, and commands if applicable."
            
            context = {
                "query_type": "remediation",
                "threat_type": threat_type,
                "domain": "cybersecurity"
            }
            
            response = self.llm.generate_response(query, context)
            answer = response.get("answer", "")
            
            # Extract steps as a list
            steps = []
            lines = answer.split("\n")
            
            for line in lines:
                line = line.strip()
                if line.startswith("Step") or line.startswith("-") or line.startswith("*") or (len(line) > 2 and line[0].isdigit() and line[1] == '.'):
                    steps.append(line)
            
            # If no structured steps found, split by newlines and filter out empty lines
            if not steps:
                steps = [line.strip() for line in lines if line.strip()]
            
            return steps
        except Exception as e:
            logger.error(f"Error generating remediation steps: {str(e)}")
            return [f"Error: {str(e)}"]
    
    def generate_security_policy(self, policy_type: str) -> Dict[str, Any]:
        """Generate a security policy of the specified type"""
        try:
            logger.info(f"Generating security policy for: {policy_type}")
            
            policy_types = {
                "password": "password management and complexity requirements",
                "access_control": "access control and user permissions",
                "data_protection": "data protection and privacy",
                "incident_response": "security incident response",
                "byod": "bring your own device (BYOD)",
                "remote_work": "remote work and telecommuting",
                "acceptable_use": "acceptable use of company resources"
            }
            
            policy_description = policy_types.get(policy_type, policy_type)
            
            query = f"Generate a comprehensive security policy for {policy_description}. Include policy purpose, scope, roles and responsibilities, guidelines, compliance requirements, and enforcement."
            
            context = {
                "query_type": "policy_generation",
                "policy_type": policy_type,
                "domain": "cybersecurity"
            }
            
            response = self.llm.generate_response(query, context)
            
            return {
                "policy_type": policy_type,
                "policy_content": response.get("answer", ""),
                "confidence": response.get("confidence", 0.0)
            }
        except Exception as e:
            logger.error(f"Error generating security policy: {str(e)}")
            return {
                "policy_type": policy_type,
                "policy_content": f"Error generating policy: {str(e)}",
                "confidence": 0.0
            }
    
    def answer_security_question(self, question: str) -> str:
        """Answer employee questions about cybersecurity best practices"""
        try:
            logger.info(f"Answering security question: {question}")
            
            query = f"As a cybersecurity expert, answer this question from an employee: {question}"
            
            context = {
                "query_type": "education",
                "domain": "cybersecurity",
                "audience": "employee"
            }
            
            response = self.llm.generate_response(query, context)
            return response.get("answer", "I'm unable to answer this question at the moment.")
        except Exception as e:
            logger.error(f"Error answering security question: {str(e)}")
            return f"I encountered an error while trying to answer your question: {str(e)}"


# Helper function to get a singleton instance
def get_threat_analyzer() -> ThreatAnalyzer:
    """Get singleton instance of ThreatAnalyzer"""
    return ThreatAnalyzer()


if __name__ == "__main__":
    # Simple test if called directly
    logging.basicConfig(level=logging.INFO)
    
    analyzer = ThreatAnalyzer()
    
    # Test text query analysis
    response = analyzer.analyze_text_query("What are common indicators of a phishing attack?")
    print("\nPhishing Indicators:\n", response.get("answer", ""))
    
    # Test remediation steps
    steps = analyzer.generate_remediation_steps("ransomware")
    print("\nRansomware Remediation Steps:")
    for step in steps:
        print(f"- {step}")
        
    # Test policy generation
    policy = analyzer.generate_security_policy("password")
    print("\nPassword Policy Sample:\n", policy.get("policy_content", "")[:300] + "...")