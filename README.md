# LLM-Powered Cybersecurity Assistant

An AI-driven solution for information security that automates threat detection, provides real-time recommendations, and educates employees.

## Project Overview

This project implements an LLM-powered cybersecurity assistant to help organizations:

- Detect and analyze security threats in real-time
- Generate security policies tailored to organizational needs
- Provide incident response guidance
- Educate employees on cybersecurity best practices

## Key Features

- **Threat Detection**: Analyze logs and alerts in real-time
- **Policy Generation**: Create security policies based on organizational needs
- **Incident Response**: Provide step-by-step guidance during security incidents
- **Employee Education**: Answer questions about cybersecurity best practices

## Project Timeline

- **Start Date**: April 15, 2025
- **End Date**: July 15, 2025

## Technology Stack

- **LLM Framework**: Hugging Face Transformers
- **Backend**: FastAPI, Python
- **Data Processing**: Pandas, NumPy, scikit-learn
- **Security Tool Integration**: Wazuh, Splunk (Free Tier)
- **Testing**: Pytest

## Getting Started

### Prerequisites

- Python 3.9+
- Git
- (Optional) Wazuh and Splunk installations for full functionality

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/llm-cybersecurity-assistant.git
   cd llm-cybersecurity-assistant
   ```

2. Set up the environment:
   ```bash
   # Create and activate a virtual environment
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   
   # Install dependencies
   python run.py --setup
   ```

3. Collect cybersecurity data for training (optional but recommended):
   ```bash
   python run.py --collect
   ```

4. Fine-tune the LLM on collected data (optional but recommended):
   ```bash
   python run.py --train
   ```

5. Run the application:
   ```bash
   python run.py --run
   ```

6. Access the API at http://localhost:8000 and API documentation at http://localhost:8000/docs

### Quick Demo

To see the system in action without setting up integrations:

```bash
python demo.py
```

For specific demos:

```bash
# Run only the query demo
python demo.py --query

# Run only the policy generation demo
python demo.py --policy

# See all available demo options
python demo.py --help
```

### Configuration

The application can be configured by editing `config.json` in the root directory. See `config.py` for all available options.

Example configuration:

```json
{
  "development": {
    "debug": true,
    "llm": {
      "base_model": "google/flan-t5-base",
      "temperature": 0.7
    },
    "integrations": {
      "wazuh": {
        "enabled": false
      },
      "splunk": {
        "enabled": false
      }
    }
  }
}
```

## API Endpoints

The following API endpoints are available:

- `GET /health` - Check API health status
- `POST /api/query` - Process cybersecurity text queries
- `POST /api/alert/analyze` - Analyze security alerts
- `POST /api/remediation` - Get remediation steps for threats
- `POST /api/policy/generate` - Generate security policies
- `GET /api/insights` - Get security insights from integrated tools
- `GET /api/education/answer` - Answer employee security questions

## Project Structure

```
llm-cybersecurity-assistant/
├── api/                # API endpoints and middleware
│   └── routes.py       # API route definitions
├── data/               # Data for training and testing
│   ├── raw/            # Raw data sources (CVE, MITRE, etc.)
│   ├── processed/      # Processed data ready for training
│   └── training/       # Training datasets
├── integrations/       # Integration with security tools
│   ├── wazuh/          # Wazuh integration
│   │   └── client.py   # Wazuh API client
│   └── splunk/         # Splunk integration
│       └── client.py   # Splunk API client
├── models/             # LLM models
│   ├── base_model/     # Base model files
│   └── fine_tuned/     # Fine-tuned model files
├── tests/              # Test files
│   ├── unit/           # Unit tests
│   └── integration/    # Integration tests
├── utils/              # Utility functions
│   ├── data_collection.py  # Data collection utilities
│   ├── llm_module.py       # LLM integration
│   └── threat_analyzer.py  # Threat analysis logic
├── app.py              # Main application
├── config.py           # Configuration
├── demo.py             # Demonstration script
├── run.py              # Runner script
└── requirements.txt    # Python dependencies
```

## Team

- Adil Mukhametbek: LLM training and fine-tuning
- Dias Baltabaev: Integration with security tools (Wazuh, Splunk)
- Batyikhan Mukhituly: Testing and documentation

## Kanban Board

We use a Kanban board to track project progress with the following columns:
- **To Do**: Tasks that have not yet been started
- **In Progress**: Tasks currently being worked on
- **Testing**: Tasks that are being tested
- **Done**: Completed tasks

Key metrics we track:
- Lead Time: Average time from task creation to completion
- Cycle Time: Average time from starting work to completion
- Throughput: Number of tasks completed per week
- WIP: Number of tasks currently in progress

## License

[MIT License](LICENSE)