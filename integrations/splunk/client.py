import requests
import json
import logging
import time
from typing import Dict, List, Any, Optional, Union, Tuple
import sys
from pathlib import Path

# Import project config
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from config import config

# Set up logging
logger = logging.getLogger(__name__)

class SplunkClient:
    """Client for interacting with Splunk API"""
    
    def __init__(self, 
                 api_url: Optional[str] = None, 
                 token: Optional[str] = None):
        """Initialize the Splunk client with connection details"""
        self.api_url = api_url or config["integrations"]["splunk"]["api_url"]
        self.token = token or config["integrations"]["splunk"]["token"]
        self.verify_ssl = False  # Set to True in production with proper SSL certs
        
        if not self.api_url or not self.token:
            logger.warning("Splunk API URL or token not configured. Integration will be disabled.")
    
    def _get_auth_header(self) -> Dict[str, str]:
        """Get authentication header for Splunk API"""
        if not self.token:
            raise ValueError("Splunk token not configured")
            
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def run_search(self, 
                  search_query: str, 
                  earliest_time: Optional[str] = None,
                  latest_time: Optional[str] = None,
                  max_count: int = 100) -> List[Dict[str, Any]]:
        """Run a search query in Splunk and return results"""
        if not self.api_url or not self.token:
            logger.error("Splunk API URL and token must be configured")
            return []
            
        try:
            # Prepare search parameters
            search_params = {
                "search": search_query,
                "output_mode": "json",
                "count": max_count
            }
            
            if earliest_time:
                search_params["earliest_time"] = earliest_time
                
            if latest_time:
                search_params["latest_time"] = latest_time
            
            # Start search job
            response = requests.post(
                f"{self.api_url}/services/search/jobs",
                headers=self._get_auth_header(),
                data=search_params,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            # Get search job ID
            search_job_id = response.json().get("sid")
            if not search_job_id:
                logger.error("Failed to get search job ID from Splunk")
                return []
                
            # Wait for search to complete
            job_status = {"isDone": False}
            max_attempts = 10
            attempts = 0
            
            while not job_status.get("isDone", False) and attempts < max_attempts:
                attempts += 1
                time.sleep(2)  # Wait before checking status
                
                status_response = requests.get(
                    f"{self.api_url}/services/search/jobs/{search_job_id}",
                    headers=self._get_auth_header(),
                    params={"output_mode": "json"},
                    verify=self.verify_ssl
                )
                status_response.raise_for_status()
                job_status = status_response.json().get("entry", [{}])[0].get("content", {})
            
            if not job_status.get("isDone", False):
                logger.warning(f"Search job {search_job_id} did not complete in time")
            
            # Get search results
            results_response = requests.get(
                f"{self.api_url}/services/search/jobs/{search_job_id}/results",
                headers=self._get_auth_header(),
                params={"output_mode": "json", "count": max_count},
                verify=self.verify_ssl
            )
            results_response.raise_for_status()
            
            return results_response.json().get("results", [])
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error running Splunk search: {str(e)}")
            return []
    
    def get_security_events(self, 
                           hours_back: int = 24, 
                           max_count: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events from Splunk"""
        search_query = """
            search index=security OR index=windows OR sourcetype=WinEventLog 
            | eval severity=case(
                like(event_id, "%4624%"), "Low", 
                like(event_id, "%4625%"), "Medium", 
                like(event_id, "%4648%"), "Medium",
                like(event_id, "%4672%"), "High",
                like(event_id, "%4720%"), "High",
                like(event_id, "%4740%"), "High",
                1=1, "Informational")
            | stats count by host, event_id, severity, user, source
            | sort -count
        """
        
        earliest_time = f"-{hours_back}h"
        
        return self.run_search(
            search_query=search_query,
            earliest_time=earliest_time,
            max_count=max_count
        )
    
    def get_failed_logins(self, 
                         hours_back: int = 24, 
                         max_count: int = 50) -> List[Dict[str, Any]]:
        """Get failed login attempts from Splunk"""
        search_query = """
            search index=security (event_id=4625 OR event_id=4771) 
            | stats count as failures by src_ip, user, dest_host
            | where failures > 3
            | sort -failures
        """
        
        earliest_time = f"-{hours_back}h"
        
        return self.run_search(
            search_query=search_query,
            earliest_time=earliest_time,
            max_count=max_count
        )
    
    def get_alerts_by_severity(self, 
                              severity: str = "high", 
                              hours_back: int = 24) -> List[Dict[str, Any]]:
        """Get security alerts filtered by severity"""
        search_query = f"""
            search index=* severity={severity} OR level={severity} OR priority={severity}
            | stats count by source, host, event_name, severity
            | sort -count
        """
        
        earliest_time = f"-{hours_back}h"
        
        return self.run_search(
            search_query=search_query,
            earliest_time=earliest_time
        )
    
    def format_event_for_llm(self, event: Dict[str, Any]) -> str:
        """Format a Splunk event for LLM processing"""
        # Extract fields with reasonable defaults
        host = event.get("host", "Unknown host")
        source = event.get("source", "Unknown source")
        event_id = event.get("event_id", "Unknown ID")
        severity = event.get("severity", "Unknown")
        user = event.get("user", "Unknown user")
        count = event.get("count", "1")
        
        # Format the event
        formatted_event = (
            f"Event ID: {event_id}\n"
            f"Host: {host}\n"
            f"Source: {source}\n"
            f"Severity: {severity}\n"
            f"User: {user}\n"
            f"Count: {count}\n"
        )
        
        # Add any additional fields
        for key, value in event.items():
            if key not in ["host", "source", "event_id", "severity", "user", "count"]:
                formatted_event += f"{key}: {value}\n"
        
        return formatted_event
    
    def get_formatted_security_events(self, hours_back: int = 24, max_count: int = 10) -> str:
        """Get recent security events formatted for LLM analysis"""
        events = self.get_security_events(hours_back=hours_back, max_count=max_count)
        
        if not events:
            return "No security events found."
        
        formatted_events = []
        for event in events:
            formatted_events.append(self.format_event_for_llm(event))
        
        return "\n\n".join(formatted_events)
    
    def health_check(self) -> bool:
        """Check if Splunk API is accessible and properly configured"""
        try:
            if not self.api_url or not self.token:
                return False
                
            response = requests.get(
                f"{self.api_url}/services/server/info",
                headers=self._get_auth_header(),
                params={"output_mode": "json"},
                verify=self.verify_ssl
            )
            return response.status_code == 200
        except:
            return False


# Helper function to get a singleton instance
def get_splunk_client() -> SplunkClient:
    """Get singleton instance of SplunkClient"""
    return SplunkClient()


if __name__ == "__main__":
    # Simple test if called directly
    logging.basicConfig(level=logging.INFO)
    
    # Only attempt connection if configured
    if config["integrations"]["splunk"]["enabled"]:
        client = SplunkClient()
        
        if client.health_check():
            print("Splunk connection successful!")
            
            # Test getting some events
            events = client.get_security_events(hours_back=12, max_count=5)
            print(f"Found {len(events)} security events")
            
            for event in events:
                print(f"- {event.get('event_id', 'Unknown')} on {event.get('host', 'Unknown')}")
        else:
            print("Splunk connection failed. Check configuration and connectivity.")
    else:
        print("Splunk integration is disabled in configuration.")