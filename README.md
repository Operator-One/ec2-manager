# EC2 Manager CLI Tool 🚀

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![AWS](https://img.shields.io/badge/AWS-EC2%20%26%20ASG-orange.svg)

A command-line interface (CLI) tool built with Python and Boto3 to manage AWS EC2 instances and Auto Scaling Groups (ASGs). It features a keyboard-navigable, list-based menu powered by InquirerPy, supporting dynamic instance searching, creation, modification, and ASG management, optimized for classified environments (e.g., AWS GovCloud).

## ✨ Features

- **EC2 Management**:
  - 📋 View all running instances (including those without Name tags).
  - 🔍 Search running instances by Name tag or private IP (partial matches).
  - 🆕 Create new EC2 instances with customizable parameters.
  - ✏️ Modify instance attributes (tags, security groups).
  - 🔄 Control instance states: start, stop, terminate (ASG instances protected).
- **Auto Scaling Group Management**:
  - 📋 View all ASGs or search by name.
  - ⚙️ Modify ASG properties (min/max/desired capacity) or refresh instances.
- **Security & Compliance**:
  - 🔐 Prompt for AWS credentials if not preconfigured.
  - 🌍 Support for special regions (e.g., GovCloud: `us-gov-west-1`).
  - 🛡️ Validates Python 3.6+ and AWS credentials.
- **User Experience**:
  - 🖥️ Interactive list-based menu (navigate with arrow keys, select with Enter).
  - 📜 Clear error messages and status updates.

> **Note**: This tool does **not** include `apply`, `destroy`, `init`, or `set-secrets` commands, which are associated with Terraform. See [Terraform Integration](#-terraform-integration).

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Permissions](#-permissions)
- [Terraform Integration](#-terraform-integration)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)
- [Development](#-development)
- [License](#-license)

## 📋 Prerequisites

| Requirement | Description |
|-------------|-------------|
| **Python** | 3.6 or higher (`python3 --version`). |
| **AWS Credentials** | Access Key ID, Secret Access Key, optional Session Token from STS or IAM. |
| **AWS Permissions** | `sts:GetCallerIdentity`, `ec2:Describe*`, `ec2:RunInstances`, `ec2:CreateTags`, `ec2:ModifyInstanceAttribute`, `ec2:StartInstances`, `ec2:StopInstances`, `ec2:TerminateInstances`, `autoscaling:Describe*`, `autoscaling:UpdateAutoScalingGroup`, `autoscaling:StartInstanceRefresh`, `autoscaling:DescribeInstanceRefreshes`. |
| **Git** | Optional, for cloning (`sudo apt install git` on Ubuntu). |
| **pip** | Python package manager. |

## 📦 Installation

### Option 1: Install via pip
```bash
pip install ec2-manager