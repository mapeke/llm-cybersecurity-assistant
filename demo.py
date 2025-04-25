#!/usr/bin/env python3
"""
LLM-Powered Cybersecurity Assistant Demo Script

This script demonstrates the basic functionality of the cybersecurity assistant
without requiring a full setup of the integrated security tools.
"""

import logging
import json
import time
import argparse
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import project modules
from utils.threat_analyzer import get_threat_analyzer
from utils.data_collection import CybersecurityDataCollector

def demo_query():
    """Demonstrate basic cybersecurity queries"""
    analyzer = get_threat_analyzer()
    
    print("\n===== CYBERSECURITY QUERY DEMONSTRATION =====")
    
    queries = [
        "What are the most common indicators of a phishing attack?",
        "How can I secure my home Wi-Fi network?",
        "What is a zero-day vulnerability?",
        "What security measures should be implemented for cloud storage?"
    ]
    
    for i, query in enumerate(queries, 1):
        print(f"\n{i}. Query: {query}")
        response = analyzer.analyze_text_query(query)
        print(f"Answer: {response.get('answer', 'No answer generated')}")
        print(f"Confidence: {response.get('confidence', 0.0):.2f}")
        time.sleep(1)  # Pause between queries

def demo_alert_analysis():
    """Demonstrate security alert analysis"""
    analyzer = get_threat_analyzer()
    
    print("\n===== SECURITY ALERT ANALYSIS DEMONSTRATION =====")
    
    # Sample Wazuh alert
    wazuh_alert = {
        "id": "12345",
        "rule": {
            "id": "5715",
            "description": "Multiple failed login attempts using the same credentials."
        },
        "agent": {
            "name": "server01",
            "id": "001"
        },
        "timestamp": "2025-04-22T14:35:25.123Z",
        "location": "/var/log/auth.log",
        "data": {
            "srcip": "192.168.1.100",
            "user": "admin",
            "attempts": "5"
        }
    }
    
    print("\n1. Wazuh Alert Analysis:")
    print(f"Alert: {json.dumps(wazuh_alert, indent=2)}")
    response = analyzer.analyze_wazuh_alert(wazuh_alert)
    print(f"Analysis: {response.get('answer', 'No analysis generated')}")
    
    # Sample Splunk event
    splunk_event = {
        "event_id": "4625",
        "source": "WinEventLog:Security",
        "host": "workstation05",
        "user": "jsmith",
        "severity": "high",
        "count": "12",
        "message": "An account failed to log on. Subject: Security ID: S-1-0-0 Account Name: - Account Domain: - Logon ID: 0x0 Logon Type: 3 Account For Which Logon Failed: Security ID: S-1-0-0 Account Name: jsmith Account Domain: CORP Failure Information: Failure Reason: Unknown user name or bad password. Status: 0xc000006d Sub Status: 0xc000006a Process Information: Caller Process ID: 0x0 Caller Process Name: - Network Information: Workstation Name: - Source Network Address: 10.0.0.15 Source Port: 49532"
    }
    
    print("\n2. Splunk Event Analysis:")
    print(f"Event: {json.dumps(splunk_event, indent=2)}")
    response = analyzer.analyze_splunk_event(splunk_event)
    print(f"Analysis: {response.get('answer', 'No analysis generated')}")

def demo_policy_generation():
    """Demonstrate security policy generation"""
    analyzer = get_threat_analyzer()
    
    print("\n===== SECURITY POLICY GENERATION DEMONSTRATION =====")
    
    policy_types = ["password", "remote_work", "byod"]
    
    for i, policy_type in enumerate(policy_types, 1):
        print(f"\n{i}. Generating {policy_type} policy:")
        policy = analyzer.generate_security_policy(policy_type)
        
        # Print just the first few lines for demo purposes
        content = policy.get("policy_content", "")
        content_preview = "\n".join(content.split("\n")[:10]) + "\n... (content continues)"
        
        print(f"Policy Content Preview:\n{content_preview}")
        print(f"Confidence: {policy.get('confidence', 0.0):.2f}")
        time.sleep(1)  # Pause between generations

def demo_remediation():
    """Demonstrate remediation steps generation"""
    analyzer = get_threat_analyzer()
    
    print("\n===== REMEDIATION STEPS DEMONSTRATION =====")
    
    threat_types = ["ransomware", "data breach", "phishing", "insider threat"]
    
    for i, threat_type in enumerate(threat_types, 1):
        print(f"\n{i}. Remediation steps for {threat_type}:")
        steps = analyzer.generate_remediation_steps(threat_type)
        
        for j, step in enumerate(steps[:5], 1):  # Show first 5 steps only
            print(f"  Step {j}: {step}")
        
        if len(steps) > 5:
            print(f"  ... ({len(steps) - 5} more steps)")
        
        time.sleep(1)  # Pause between generations

def demo_data_collection():
    """Demonstrate data collection process"""
    print("\n===== DATA COLLECTION DEMONSTRATION =====")
    print("Note: This will make API calls to collect cybersecurity data. It may take some time.")
    
    collector = CybersecurityDataCollector()
    
    # Demo CVE data collection (limit to just 2023 for demo purposes)
    print("\nCollecting CVE data for 2023...")
    cve_path = collector.collect_cve_data(start_year=2023, end_year=2023)
    
    if cve_path:
        print(f"Successfully collected CVE data: {cve_path}")
    else:
        print("Failed to collect CVE data")
    
    # Demo MITRE ATT&CK data collection
    print("\nCollecting MITRE ATT&CK data...")
    mitre_path = collector.collect_mitre_attack_data()
    
    if mitre_path:
        print(f"Successfully collected MITRE ATT&CK data: {mitre_path}")
    else:
        print("Failed to collect MITRE ATT&CK data")
    
    # Prepare training data if both data sources were collected
    if cve_path and mitre_path:
        print("\nPreparing training data from collected sources...")
        training_path = collector.prepare_training_data(cve_path, mitre_path)
        
        if training_path:
            print(f"Successfully prepared training data: {training_path}")
            
            # Show sample of training data
            import pandas as pd
            try:
                df = pd.read_csv(training_path)
                print(f"\nTraining data contains {len(df)} examples")
                if len(df) > 0:
                    print("\nSample training example:")
                    sample = df.iloc[0]
                    print(f"Input: {sample['input']}")
                    print(f"Output: {sample['output'][:200]}... (truncated)")
            except Exception as e:
                print(f"Error reading training data: {str(e)}")
        else:
            print("Failed to prepare training data")

def demo_security_education():
    """Demonstrate employee security education Q&A"""
    analyzer = get_threat_analyzer()
    
    print("\n===== SECURITY EDUCATION DEMONSTRATION =====")
    
    questions = [
        "Is it safe to use public Wi-Fi for banking?",
        "How often should I change my passwords?",
        "What should I do if I suspect my email has been hacked?",
        "Is it okay to share my work credentials with team members?"
    ]
    
    for i, question in enumerate(questions, 1):
        print(f"\n{i}. Employee Question: {question}")
        answer = analyzer.answer_security_question(question)
        print(f"Answer: {answer}")
        time.sleep(1)  # Pause between questions

def main():
    """Main demo function"""
    parser = argparse.ArgumentParser(description="LLM-Powered Cybersecurity Assistant Demo")
    parser.add_argument("--all", action="store_true", help="Run all demos")
    parser.add_argument("--query", action="store_true", help="Run cybersecurity query demo")
    parser.add_argument("--alert", action="store_true", help="Run alert analysis demo")
    parser.add_argument("--policy", action="store_true", help="Run policy generation demo")
    parser.add_argument("--remediation", action="store_true", help="Run remediation steps demo")
    parser.add_argument("--data", action="store_true", help="Run data collection demo")
    parser.add_argument("--education", action="store_true", help="Run security education demo")
    
    args = parser.parse_args()
    
    # If no specific demos are selected, run all
    run_all = args.all or not (args.query or args.alert or args.policy or args.remediation or args.data or args.education)
    
    print("=" * 60)
    print("LLM-POWERED CYBERSECURITY ASSISTANT DEMO")
    print("=" * 60)
    print("This demonstration shows the capabilities of the LLM-powered")
    print("cybersecurity assistant without requiring full security tool integration.")
    
    # Run selected demos
    if args.query or run_all:
        demo_query()
    
    if args.alert or run_all:
        demo_alert_analysis()
    
    if args.policy or run_all:
        demo_policy_generation()
    
    if args.remediation or run_all:
        demo_remediation()
    
    if args.education or run_all:
        demo_security_education()
    
    if args.data or run_all:
        demo_data_collection()
    
    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()