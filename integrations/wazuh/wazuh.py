import requests
import json
import logging
import base64
from typing import Dict, List, Any, Optional, Union, Tuple
import sys
from pathlib import Path

# Import project config
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from config import config

# Set up logging
logger = logging.getLogger(__name__)

class WazuhClient:
    """Client for interacting with Wazuh API"""
    
    def __init__(self, 
                 api_url: Optional[str] = None, 
                 username: Optional[str] = None, 
                 password: Optional[str] = None):
        """Initialize the Wazuh client with connection details"""
        self.api_url = api_url or config["integrations"]["wazuh"]["api_url"]
        self.username = username or config["integrations"]["wazuh"]["username"]
        self.password = password or config["integrations"]["wazuh"]["password"]
        self.token = None
        self.verify_ssl = False  # Set to True in production with proper SSL certs
        
        if not self.api_url or not self.username:
            logger.warning("Wazuh API URL or username not configured. Integration will be disabled.")
    
    def _get_auth_header(self) -> Dict[str, str]:
        """Get authentication header for Wazuh API"""
        if not self.token:
            # Fetch token if not already authenticated
            self._authenticate()
            
        return {"Authorization": f"Bearer {self.token}"}
    
    def _authenticate(self) -> None:
        """Authenticate with Wazuh API and get token"""
        if not self.api_url or not self.username:
            raise ValueError("Wazuh API URL and username must be configured")
            
        try:
            # Basic authentication header
            auth_str = f"{self.username}:{self.password}"
            auth_header = f"Basic {base64.b64encode(auth_str.encode()).decode()}"
            
            # Make authentication request
            response = requests.post(
                f"{self.api_url}/security/user/authenticate",
                headers={"Authorization": auth_header},
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            # Extract token
            self.token = response.json().get("data", {}).get("token")
            if not self.token:
                logger.error("Failed to get authentication token from Wazuh")
                raise ValueError("Authentication failed - no token received")
                
            logger.debug("Successfully authenticated with Wazuh API")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error authenticating with Wazuh API: {str(e)}")
            raise
    
    def get_agents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get list of Wazuh agents"""
        try:
            response = requests.get(
                f"{self.api_url}/agents",
                headers=self._get_auth_header(),
                params={"limit": limit},
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            return response.json().get("data", {}).get("affected_items", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting Wazuh agents: {str(e)}")
            return []
    
    def get_alerts(self, 
                   limit: int = 20, 
                   offset: int = 0,
                   search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get security alerts from Wazuh"""
        try:
            params = {
                "limit": limit,
                "offset": offset
            }
            
            if search:
                params["q"] = search
                
            response = requests.get(
                f"{self.api_url}/sca",  # Security Configuration Assessment
                headers=self._get_auth_header(),
                params=params,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            return response.json().get("data", {}).get("affected_items", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting Wazuh alerts: {str(e)}")
            return []
    
    def get_vulnerabilities(self, 
                           agent_id: str,
                           limit: int = 20, 
                           offset: int = 0) -> List[Dict[str, Any]]:
        """Get vulnerabilities detected by Wazuh for a specific agent"""
        try:
            params = {
                "limit": limit,
                "offset": offset
            }
                
            response = requests.get(
                f"{self.api_url}/vulnerability/{agent_id}",
                headers=self._get_auth_header(),
                params=params,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            return response.json().get("data", {}).get("affected_items", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting vulnerabilities for agent {agent_id}: {str(e)}")
            return []
    
    def get_system_info(self, agent_id: str) -> Dict[str, Any]:
        """Get system information for a specific agent"""
        try:
            response = requests.get(
                f"{self.api_url}/syscollector/{agent_id}/hardware",
                headers=self._get_auth_header(),
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            return response.json().get("data", {}).get("affected_items", [{}])[0]
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting system info for agent {agent_id}: {str(e)}")
            return {}
    
    def format_alert_for_llm(self, alert: Dict[str, Any]) -> str:
        """Format a Wazuh alert for LLM processing"""
        # Extract relevant information
        alert_id = alert.get("id", "Unknown")
        description = alert.get("description", "No description")
        level = alert.get("level", 0)
        agent = alert.get("agent", {}).get("name", "Unknown agent")
        timestamp = alert.get("timestamp", "Unknown time")
        
        # Format the alert
        formatted_alert = (
            f"Alert ID: {alert_id}\n"
            f"Description: {description}\n"
            f"Severity Level: {level}/15\n"
            f"Agent: {agent}\n"
            f"Timestamp: {timestamp}\n"
        )
        
        # Add rule information if available
        if "rule" in alert:
            rule = alert["rule"]
            formatted_alert += (
                f"Rule ID: {rule.get('id', 'N/A')}\n"
                f"Rule Description: {rule.get('description', 'N/A')}\n"
                f"Rule Groups: {', '.join(rule.get('groups', []))}\n"
            )
        
        return formatted_alert
    
    def get_formatted_alerts(self, 
                            limit: int = 5, 
                            search: Optional[str] = None) -> str:
        """Get recent alerts formatted for LLM analysis"""
        alerts = self.get_alerts(limit=limit, search=search)
        
        if not alerts:
            return "No alerts found."
        
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append(self.format_alert_for_llm(alert))
        
        return "\n\n".join(formatted_alerts)
    
    def health_check(self) -> bool:
        """Check if Wazuh API is accessible and properly configured"""
        try:
            if not self.api_url or not self.username:
                return False
                
            response = requests.get(
                f"{self.api_url}/",
                verify=self.verify_ssl
            )
            return response.status_code == 200
        except:
            return False


# Helper function to get a singleton instance
def get_wazuh_client() -> WazuhClient:
    """Get singleton instance of WazuhClient"""
    return WazuhClient()


if __name__ == "__main__":
    # Simple test if called directly
    logging.basicConfig(level=logging.INFO)
    
    # Only attempt connection if configured
    if config["integrations"]["wazuh"]["enabled"]:
        client = WazuhClient()
        
        if client.health_check():
            print("Wazuh connection successful!")
            agents = client.get_agents(limit=5)
            print(f"Found {len(agents)} agents")
            for agent in agents:
                print(f"- {agent.get('name', 'Unknown')} (ID: {agent.get('id', 'Unknown')})")
        else:
            print("Wazuh connection failed. Check configuration and connectivity.")
    else:
        print("Wazuh integration is disabled in configuration.")