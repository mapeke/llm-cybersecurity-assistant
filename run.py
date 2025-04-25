#!/usr/bin/env python3
"""
LLM-Powered Cybersecurity Assistant Runner Script

This script provides a convenient way to start the application
and perform associated tasks like data collection and model training.
"""

import os
import sys
import argparse
import logging
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_app():
    """Run the FastAPI application"""
    logger.info("Starting the LLM-Powered Cybersecurity Assistant API...")
    os.system("python app.py")

def collect_data():
    """Run the data collection process"""
    logger.info("Starting data collection process...")
    try:
        from utils.data_collection import CybersecurityDataCollector
        collector = CybersecurityDataCollector()
        results = collector.run_full_collection()
        
        logger.info("Data collection complete!")
        logger.info(f"CVE Data: {results.get('cve_path', 'Not collected')}")
        logger.info(f"MITRE ATT&CK Data: {results.get('mitre_path', 'Not collected')}")
        logger.info(f"Training Data: {results.get('training_path', 'Not prepared')}")
        
        return results.get('training_path')
    except Exception as e:
        logger.error(f"Error during data collection: {str(e)}")
        return None

def train_model(dataset_path=None):
    """Fine-tune the LLM on cybersecurity data"""
    if not dataset_path:
        logger.warning("No dataset path provided for training. Looking for existing datasets...")
        # Try to find the most recent training dataset
        data_dir = Path(__file__).parent / "data" / "processed"
        training_files = list(data_dir.glob("cybersecurity_training_data.*"))
        
        if not training_files:
            logger.error("No training datasets found. Run data collection first.")
            return False
        
        # Sort by modification time and get the most recent
        dataset_path = str(sorted(training_files, key=lambda f: f.stat().st_mtime, reverse=True)[0])
        logger.info(f"Using most recent dataset: {dataset_path}")
    
    logger.info(f"Starting LLM fine-tuning with dataset: {dataset_path}")
    try:
        from utils.llm_module import get_llm_instance
        llm = get_llm_instance()
        
        # Fine-tune with minimal epochs for demo purposes
        llm.fine_tune(
            dataset_path=dataset_path,
            epochs=1,  # Minimal training for demo, increase for real use
            batch_size=4,
            learning_rate=3e-5
        )
        
        logger.info("LLM fine-tuning complete!")
        return True
    except Exception as e:
        logger.error(f"Error during model training: {str(e)}")
        return False

def run_tests():
    """Run the test suite"""
    logger.info("Running tests...")
    test_dir = Path(__file__).parent / "tests"
    
    if not test_dir.exists():
        logger.error(f"Test directory not found: {test_dir}")
        return False
    
    try:
        result = subprocess.run(["python", "-m", "unittest", "discover", "-s", "tests"], 
                                capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("All tests passed!")
            logger.info(result.stdout)
            return True
        else:
            logger.error(f"Tests failed with return code {result.returncode}")
            logger.error(result.stderr)
            return False
    except Exception as e:
        logger.error(f"Error running tests: {str(e)}")
        return False

def run_demo():
    """Run the demonstration script"""
    logger.info("Running demonstration...")
    try:
        result = subprocess.run(["python", "demo.py"], capture_output=False)
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Error running demo: {str(e)}")
        return False

def setup_environment():
    """Ensure the environment is properly set up"""
    logger.info("Setting up environment...")
    
    # Ensure required directories exist
    dirs = [
        "data", "data/raw", "data/processed", "data/training",
        "models", "models/base_model", "models/fine_tuned",
        "logs", "integrations", "tests"
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(exist_ok=True)
    
    # Check Python dependencies
    logger.info("Checking Python dependencies...")
    try:
        subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                       capture_output=True, check=True)
        logger.info("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error installing dependencies: {e.stderr.decode()}")
        return False
    except Exception as e:
        logger.error(f"Error setting up environment: {str(e)}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="LLM-Powered Cybersecurity Assistant Runner")
    parser.add_argument("--setup", action="store_true", help="Set up the environment")
    parser.add_argument("--collect", action="store_true", help="Collect cybersecurity data")
    parser.add_argument("--train", action="store_true", help="Train the LLM on collected data")
    parser.add_argument("--test", action="store_true", help="Run the test suite")
    parser.add_argument("--demo", action="store_true", help="Run the demonstration")
    parser.add_argument("--run", action="store_true", help="Run the API application")
    parser.add_argument("--all", action="store_true", help="Run all steps (setup, collect, train, test, run)")
    
    args = parser.parse_args()
    
    # Default to running the app if no arguments are provided
    if not any(vars(args).values()):
        args.run = True
    
    # Run all steps if --all is specified
    if args.all:
        args.setup = args.collect = args.train = args.test = args.run = True
    
    # Run the selected steps
    if args.setup:
        if not setup_environment():
            logger.error("Environment setup failed. Exiting.")
            sys.exit(1)
    
    training_data_path = None
    if args.collect:
        training_data_path = collect_data()
    
    if args.train:
        if not train_model(training_data_path):
            logger.warning("Model training encountered issues. Continuing with other steps.")
    
    if args.test:
        if not run_tests():
            logger.warning("Tests failed. Continuing with other steps.")
    
    if args.demo:
        if not run_demo():
            logger.warning("Demo encountered issues. Continuing with other steps.")
    
    if args.run:
        run_app()

if __name__ == "__main__":
    main()