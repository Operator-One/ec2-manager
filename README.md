# AWS CLI Tool

A command-line interface (CLI) tool to manage and view AWS EC2 instances and Auto Scaling Groups using Python and Boto3.

## Features
- List EC2 instances with dynamic filtering (e.g., by state, instance type, tags).
- View Auto Scaling Group details.
- Control EC2 instance states (start, stop, terminate).
- Prevent termination of ASG instances, with option to refresh via ASG.
- ASG control panel to modify properties (min/max/desired capacity) or refresh instances with status checking.
- Interactive prompt menu with autocompletion.
- Prompt for AWS credentials (Access Key ID, Secret Access Key, Session Token) if not preconfigured.
- Support for special AWS regions (e.g., GovCloud for classified environments).

## Installation
1. Install the package using pip:
   ```bash
   pip install ec2-manager
