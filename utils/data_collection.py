import requests
import json
import pandas as pd
import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import sys

# Import project config
sys.path.append(str(Path(__file__).parent.parent))
from config import DATA_DIR

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CybersecurityDataCollector:
    """Class to collect cybersecurity data for LLM training"""
    
    def __init__(self):
        self.data_dir = DATA_DIR
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        
        # Ensure directories exist
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
    
    def fetch_cve_data(self, year: int, max_retries: int = 3) -> List[Dict[str, Any]]:
        """Fetch CVE data for a specific year"""
        logger.info(f"Fetching CVE data for {year}...")
        url = f"https://cve.circl.lu/api/search/{year}"
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()  # Raise exception for HTTP errors
                return response.json()
            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt+1}/{max_retries} failed: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    logger.error(f"Failed to fetch CVE data for {year} after {max_retries} attempts")
                    return []
    
    def fetch_mitre_attack_data(self) -> Dict[str, Any]:
        """Fetch MITRE ATT&CK framework data"""
        logger.info("Fetching MITRE ATT&CK data...")
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching MITRE ATT&CK data: {str(e)}")
            return {}
    
    def collect_cve_data(self, start_year: int = 2020, end_year: int = 2024) -> str:
        """Collect and save CVE data for a range of years"""
        all_cves = []
        
        for year in range(start_year, end_year + 1):
            try:
                cves = self.fetch_cve_data(year)
                if cves:
                    all_cves.extend(cves)
                    logger.info(f"Retrieved {len(cves)} CVEs for {year}")
                else:
                    logger.warning(f"No CVEs retrieved for {year}")
            except Exception as e:
                logger.error(f"Error processing CVE data for {year}: {str(e)}")
        
        # Save to disk
        if all_cves:
            output_path = self.raw_dir / f"cve_data_{start_year}_{end_year}.csv"
            cve_df = pd.DataFrame(all_cves)
            cve_df.to_csv(output_path, index=False)
            logger.info(f"Saved {len(cve_df)} CVE records to {output_path}")
            return str(output_path)
        else:
            logger.warning("No CVE data was collected")
            return ""
    
    def collect_mitre_attack_data(self) -> str:
        """Collect and save MITRE ATT&CK data"""
        mitre_data = self.fetch_mitre_attack_data()
        
        if not mitre_data:
            logger.warning("No MITRE ATT&CK data was collected")
            return ""
            
        # Process the data to extract relevant information
        if "objects" in mitre_data:
            # Extract attack patterns
            attack_patterns = []
            for obj in mitre_data["objects"]:
                if obj.get("type") == "attack-pattern":
                    pattern = {
                        "id": obj.get("id", ""),
                        "name": obj.get("name", ""),
                        "type": obj.get("type", ""),
                        "description": obj.get("description", ""),
                        "kill_chain_phases": str(obj.get("kill_chain_phases", [])),
                        "external_references": str(obj.get("external_references", []))
                    }
                    attack_patterns.append(pattern)
            
            if attack_patterns:
                output_path = self.raw_dir / "mitre_attack_patterns.csv"
                patterns_df = pd.DataFrame(attack_patterns)
                patterns_df.to_csv(output_path, index=False)
                logger.info(f"Saved {len(patterns_df)} MITRE ATT&CK patterns to {output_path}")
                return str(output_path)
        
        logger.warning("No useful MITRE ATT&CK data was extracted")
        return ""
    
    def prepare_training_data(
        self, 
        cve_path: Optional[Union[str, Path]] = None,
        mitre_path: Optional[Union[str, Path]] = None
    ) -> str:
        """Prepare training data from collected cybersecurity information"""
        training_data = []
        
        # Process CVE data if available
        if cve_path:
            cve_path = Path(cve_path)
            if cve_path.exists():
                try:
                    cve_df = pd.read_csv(cve_path)
                    
                    # Create training examples from CVEs
                    for _, cve in cve_df.iterrows():
                        # Input: Description of vulnerability
                        # Output: Analysis and mitigation
                        
                        # Skip if missing essential fields
                        if pd.isna(cve.get('summary')):
                            continue
                            
                        input_text = f"Analyze this vulnerability: {cve.get('summary', '')}"
                        
                        # Create a reasonable output based on available information
                        output_parts = []
                        output_parts.append(f"This vulnerability ({cve.get('id', 'Unknown CVE')}) is classified as follows:")
                        
                        if not pd.isna(cve.get('cvss')):
                            severity = "critical" if float(cve.get('cvss', 0)) >= 9.0 else \
                                      "high" if float(cve.get('cvss', 0)) >= 7.0 else \
                                      "medium" if float(cve.get('cvss', 0)) >= 4.0 else "low"
                            output_parts.append(f"- Severity: {severity} (CVSS score: {cve.get('cvss', 'N/A')})")
                        
                        output_parts.append(f"- Description: {cve.get('summary', 'No description available')}")
                        
                        if not pd.isna(cve.get('references')):
                            output_parts.append("- Recommended action: Review and apply patches if available.")
                            output_parts.append(f"- References: {cve.get('references', 'No references available')}")
                        
                        output_text = "\n".join(output_parts)
                        
                        training_data.append({
                            "input": input_text,
                            "output": output_text
                        })
                    
                    logger.info(f"Created {len(training_data)} training examples from CVE data")
                except Exception as e:
                    logger.error(f"Error processing CVE data: {str(e)}")
        
        # Process MITRE ATT&CK data if available
        if mitre_path:
            mitre_path = Path(mitre_path)
            if mitre_path.exists():
                try:
                    mitre_df = pd.read_csv(mitre_path)
                    
                    # Create training examples from MITRE ATT&CK
                    for _, technique in mitre_df.iterrows():
                        # Skip if missing essential fields
                        if pd.isna(technique.get('description')) or pd.isna(technique.get('name')):
                            continue
                            
                        # Input: Attack technique identification
                        input_text = f"What is the '{technique.get('name', '')}' attack technique and how can it be mitigated?"
                        
                        # Output: Description and mitigation
                        output_parts = []
                        output_parts.append(f"The '{technique.get('name', '')}' attack technique ({technique.get('id', '')}) refers to:")
                        output_parts.append(f"{technique.get('description', 'No description available')}")
                        output_parts.append("\nPotential mitigations:")
                        output_parts.append("- Implement network segmentation and least privilege access")
                        output_parts.append("- Monitor for suspicious activity related to this technique")
                        output_parts.append("- Ensure systems are patched and up-to-date")
                        output_parts.append(f"- Refer to {technique.get('id', '')} in the MITRE ATT&CK framework for specific countermeasures")
                        
                        output_text = "\n".join(output_parts)
                        
                        training_data.append({
                            "input": input_text,
                            "output": output_text
                        })
                    
                    logger.info(f"Created {len(training_data) - len(training_data)} training examples from MITRE data")
                except Exception as e:
                    logger.error(f"Error processing MITRE data: {str(e)}")
        
        # Save the training data
        if training_data:
            # Save as CSV
            output_path = self.processed_dir / "cybersecurity_training_data.csv"
            training_df = pd.DataFrame(training_data)
            training_df.to_csv(output_path, index=False)
            logger.info(f"Saved {len(training_df)} training examples to {output_path}")
            
            # Also save as jsonl for easier loading with datasets library
            jsonl_path = self.processed_dir / "cybersecurity_training_data.jsonl"
            with open(jsonl_path, 'w') as f:
                for item in training_data:
                    f.write(json.dumps(item) + '\n')
            logger.info(f"Saved training data in JSONL format to {jsonl_path}")
            
            return str(output_path)
        else:
            logger.warning("No training data was created")
            return ""
    
    def run_full_collection(self) -> Dict[str, str]:
        """Run the full data collection pipeline"""
        results = {}
        
        # Collect CVE data
        logger.info("Starting CVE data collection...")
        cve_path = self.collect_cve_data()
        results['cve_path'] = cve_path
        
        # Collect MITRE ATT&CK data
        logger.info("Starting MITRE ATT&CK data collection...")
        mitre_path = self.collect_mitre_attack_data()
        results['mitre_path'] = mitre_path
        
        # Prepare training data
        logger.info("Preparing training data...")
        training_path = self.prepare_training_data(cve_path, mitre_path)
        results['training_path'] = training_path
        
        logger.info("Data collection complete!")
        return results


if __name__ == "__main__":
    collector = CybersecurityDataCollector()
    results = collector.run_full_collection()
    
    print("\nData Collection Summary:")
    print(f"CVE Data: {results.get('cve_path', 'Not collected')}")
    print(f"MITRE ATT&CK Data: {results.get('mitre_path', 'Not collected')}")
    print(f"Training Data: {results.get('training_path', 'Not prepared')}")