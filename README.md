# AWS EC2 & ASG Manager

A modern, interactive Command-Line Interface (CLI) for managing AWS EC2 instances and Auto Scaling Groups (ASGs). This tool provides a user-friendly, menu-driven experience, eliminating the need to memorize complex AWS CLI commands.

![EC2 & ASG Manager Demo](https://placehold.co/800x400/2d3748/ffffff?text=EC2+%26+ASG+Manager+CLI)

## Features

- **Interactive Menus**: Navigate through options using your keyboard. No need to type long commands.
- **Rich Visuals**: Utilizes the `rich` library to display information in beautifully formatted tables, panels, and spinners.
- **EC2 Instance Management**:
    - View all instances with their current status.
    - Start, stop, reboot, and terminate instances by selecting them from a list.
- **Auto Scaling Group (ASG) Management**:
    - View all ASGs with their desired, min, and max capacities.
    - Set the desired capacity for an ASG.
    - Initiate a rolling instance refresh with real-time status updates.
- **Credential Management**: Automatically uses existing AWS credentials or prompts for them if not found.
- **Region Selection**: Easily select the AWS region you want to work in.

## Installation

Follow these steps to get the EC2 & ASG Manager up and running on your local machine.

### Prerequisites

- Python 3.6 or higher
- `pip` and `venv`

### 1. Clone the Repository

First, clone this repository to your local machine:

```bash
git clone [https://github.com/cullenwerks/ec2_manager.git](https://github.com/cullenwerks/ec2_manager.git)
cd ec2_manager
```

### 2. Create a Virtual Environment

It is highly recommended to use a virtual environment to manage dependencies and avoid conflicts with other projects.

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate
```
*(On Windows, use `venv\Scripts\activate`)*

### 3. Install Dependencies

Install all the required packages using the `requirements.txt` file.

```bash
pip install -r requirements.txt
```

### 4. Install the Tool

Install the package in editable mode. This will create the `ec2-manager` command-line script and link it to your source code.

```bash
pip install -e .
```

## Usage

Once installed, you can run the tool by simply typing its name in your terminal.

```bash
ec2-manager
```

### AWS Credentials

The tool will automatically detect AWS credentials set up via environment variables or the `~/.aws/credentials` file.

If no credentials are found, it will prompt you to enter your **AWS Access Key ID** and **Secret Access Key** manually.

### Navigating the Interface

- Use the **arrow keys** to move up and down in selection menus.
- Press **Enter** to confirm a selection.
- Follow the on-screen prompts to manage your resources.

### Example Workflow: Performing a Rolling Refresh

1.  Run `ec2-manager`.
2.  Select your desired AWS Region.
3.  From the main menu, choose **"Manage an Auto Scaling Group"**.
4.  Select the target ASG from the list.
5.  Choose the **"Perform Rolling Refresh"** action.
6.  Confirm the action.
7.  Watch the real-time status updates as the refresh progresses.

```
$ ec2-manager
┌──────────────────────────────────────┐
│ AWS EC2 & ASG Manager v2.0           │
└──────────────────────────────────────┘
✅ Logged in as arn:aws:iam::123456789012:user/cullen
? Select AWS Region: us-east-1
? What would you like to do?: Manage an Auto Scaling Group
? Select an Auto Scaling Group: my-production-asg (Running: 5)
? Choose an action for my-production-asg: Perform Rolling Refresh
? Start a rolling instance refresh for my-production-asg? Yes
⠧ Monitoring refresh i-0123456789abcdef0... Refresh status for my-production-asg: InProgress
```

## Contributing

Contributions are welcome! If you have a suggestion or find a bug, please open an issue or submit a pull request.

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/YourFeature`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some feature'`).
5.  Push to the branch (`git push origin feature/YourFeature`).
6.  Open a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
