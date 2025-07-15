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
```
## Running Example Pictures
Instance Creation:
<img width="1232" height="785" alt="image" src="https://github.com/user-attachments/assets/86587f32-7bc5-4788-9e13-786c4d4ce247" />
View All Instances:
<img width="1558" height="505" alt="image" src="https://github.com/user-attachments/assets/d574492d-4ff1-4cb9-9b76-3fc1a7632526" />
Search Instances by Tag:
<img width="1518" height="422" alt="image" src="https://github.com/user-attachments/assets/66065c24-df4f-4fbb-a1f0-3b54b32f7c95" />
Modify Instance Termination Protection:
<img width="1097" height="219" alt="image" src="https://github.com/user-attachments/assets/9573b7f2-68a3-4468-b046-291dd46cda97" />
Instance Start/Stop/Terminate/Reboot:
<img width="886" height="265" alt="image" src="https://github.com/user-attachments/assets/d4f1947e-16e0-4c79-9265-2eba165ee7cb" />
Target Group Viewer:
<img width="1254" height="406" alt="image" src="https://github.com/user-attachments/assets/ad53c8bd-450c-4242-9870-d3ecbf20d790" />
View Auto Scaling Groups:
<img width="1094" height="467" alt="image" src="https://github.com/user-attachments/assets/dc5df535-4667-48bb-9a8b-0cfbb1ee7495" />
Modify ASG Scalar Values:
<img width="877" height="334" alt="image" src="https://github.com/user-attachments/assets/ae88d665-ae7e-4036-9354-3b7f3f924969" />







