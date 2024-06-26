# Ec2Manager

Ec2Manager is a command-line tool for managing AWS EC2 instances. It allows users to create, list, terminate, stop, and start EC2 instances directly from the terminal. This tool is built using Python and utilizes Boto3 for interacting with AWS services.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Linux operating system
- Python 3.10 or higher
- pip (Python package installer)
- AWS account and AWS CLI configured with access and secret keys

## Installation

To install Ec2Manager, follow these steps:

1. Clone the repository to your local machine (or download the ZIP file and extract it):

```bash
git clone https://github.com/Operator-One/ec2-manager.git
cd ec2-manager
```
2. Install the package 
```bash
pip install .
```
3. Either export your credentials or use the configuration tool AWS CLI has. 
```bash
aws configure
```

## Usage

1. To use EC2 manager, you can run it without options for a menu, or call specifically what you want to use. 
Some examples:

List all EC2 instances:
```bash
ec2-manager list
```

Create a new EC2 instance:
```bash
ec2-manager create
```

Terminate an EC2 instance:
```bash
ec2-manager terminate
```

Stop an EC2 instance:
```bash
ec2-manager stop
```

Start an EC2 instance:
```bash
ec2-manager start
```
