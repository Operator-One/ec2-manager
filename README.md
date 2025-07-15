# AWS Resource Manager (ec2-manager)

A Command-Line Interface (CLI) tool designed to simplify the management of AWS resources, including EC2 instances, Auto Scaling Groups (ASGs), and Load Balancer Target Groups. Built with Python, `boto3`, and the `rich` and `questionary` libraries for a modern and interactive user experience.

## ✨ Features

- **Interactive UI**: A user-friendly, menu-driven interface for managing complex AWS resources.
- **EC2 Instance Management**:
    - View all instances in a selected region.
    - Create new EC2 instances through a guided workflow.
    - Start, stop, reboot, and terminate existing instances.
    - Enable or disable termination protection.
    - Search for instances by tag.
- **Auto Scaling Group (ASG) Management**:
    - View all ASGs in a selected region.
    - Update the min, max, and desired capacity of an ASG.
    - View instances attached to a specific ASG.
    - Initiate a rolling instance refresh with a real-time progress bar.
    - Search for ASGs by tag.
- **Load Balancing Management**:
    - View all Target Groups.
    - Search for Target Groups by tag.
- **Secure Credential Handling**: Automatically uses credentials from your environment or prompts for manual entry if none are found.

## ⚙️ Installation

[cite_start]Ensure you have Python 3.6+ installed[cite: 3].

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Operator-One/ec2_manager.git](https://github.com/Operator-One/ec2_manager.git)
    cd ec2_manager
    ```

2.  **Install dependencies:**
    It is recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

## 🚀 Usage

Run the tool from the command line:

```bash
python ec2_manager/main.py