import sys
import boto3
import json
import time
import re
from botocore.exceptions import ClientError, NoCredentialsError, InvalidClientTokenId
from inquirerpy import inquirer
from inquirerpy.base.control import Choice
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML

# Valid AWS regions (including GovCloud)
VALID_AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'us-gov-west-1', 'us-gov-east-1',
    'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
    'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3',
    'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1'
]

def check_python_version():
    """Ensure Python version is 3.6 or higher."""
    required_version = (3, 6)
    if sys.version_info < required_version:
        print(f"Error: This tool requires Python 3.6 or higher. You are using Python {sys.version_info.major}.{sys.version_info.minor}.")
        sys.exit(1)

def prompt_for_credentials():
    """Prompt user for AWS credentials using prompt_toolkit."""
    session = PromptSession(multiline=False)
    print("Please enter your AWS credentials (obtained from your STS portal).")
    access_key = session.prompt(HTML('<ansiblue>AWS Access Key ID:</ansiblue> ')).strip()
    secret_key = session.prompt(HTML('<ansiblue>AWS Secret Access Key:</ansiblue> '), is_password=True).strip()
    session_token = session.prompt(HTML('<ansiblue>AWS Session Token (optional, press Enter to skip):</ansiblue> ')).strip()
    region = prompt_for_region()
    return access_key, secret_key, session_token or None, region

def prompt_for_region():
    """Prompt user for AWS region with validation using inquirerpy."""
    region = inquirer.select(
        message="Select AWS region:",
        choices=VALID_AWS_REGIONS,
        default='us-east-1'
    ).execute()
    return region

def validate_aws_credentials(access_key, secret_key, session_token, region):
    """Validate AWS credentials and connectivity using STS."""
    try:
        boto3_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region
        )
        sts_client = boto3_session.client('sts')
        response = sts_client.get_caller_identity()
        print(f"AWS credentials validated. Connected as: {response['Arn']} in region {region}")
        return boto3_session
    except NoCredentialsError:
        print("Error: No valid AWS credentials provided.")
        return None
    except InvalidClientTokenId:
        print("Error: Invalid AWS Access Key ID or Secret Access Key.")
        return None
    except ClientError as e:
        if 'ExpiredToken' in str(e):
            print("Error: AWS Session Token has expired. Please refresh your credentials via your STS portal.")
        else:
            print(f"Error validating AWS credentials: {e}")
        return None

def fetch_ec2_instances(ec2_client, filters=None):
    """Fetch EC2 instances with optional filters."""
    try:
        filter_list = []
        if filters:
            for key, value in filters.items():
                filter_list.append({'Name': key, 'Values': value if isinstance(value, list) else [value]})
        
        response = ec2_client.describe_instances(Filters=filter_list) if filter_list else ec2_client.describe_instances()
        instances = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_info = {
                    'InstanceId': instance.get('InstanceId', 'N/A'),
                    'InstanceType': instance.get('InstanceType', 'N/A'),
                    'State': instance.get('State', {}).get('Name', 'N/A'),
                    'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                    'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                    'LaunchTime': instance.get('LaunchTime', 'N/A').isoformat() if instance.get('LaunchTime') else 'N/A',
                    'Tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', []) if 'Key' in tag and 'Value' in tag},
                    'SecurityGroups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                    'SubnetId': instance.get('SubnetId', 'N/A'),
                    'VpcId': instance.get('VpcId', 'N/A')
                }
                instances.append(instance_info)
        
        return instances
    
    except ClientError as e:
        print(f"Error fetching EC2 instances: {e}")
        return []

def search_ec2_instances(ec2_client, search_term, search_by='tag:Name'):
    """Search running EC2 instances by Name tag or private IP."""
    try:
        filters = [{'Name': 'instance-state-name', 'Values': ['running']}]
        if search_by == 'tag:Name':
            filters.append({'Name': 'tag:Name', 'Values': [f'*{search_term}*']})
        elif search_by == 'private-ip-address':
            filters.append({'Name': 'private-ip-address', 'Values': [f'*{search_term}*']})
        
        return fetch_ec2_instances(ec2_client, filters)
    except ClientError as e:
        print(f"Error searching EC2 instances: {e}")
        return []

def fetch_asg_details(asg_client, asg_name=None):
    """Fetch all Auto Scaling Groups or a specific one."""
    try:
        if asg_name:
            response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        else:
            response = asg_client.describe_auto_scaling_groups()
        asgs = []
        
        for asg in response['AutoScalingGroups']:
            asg_info = {
                'AutoScalingGroupName': asg.get('AutoScalingGroupName', 'N/A'),
                'MinSize': asg.get('MinSize', 0),
                'MaxSize': asg.get('MaxSize', 0),
                'DesiredCapacity': asg.get('DesiredCapacity', 0),
                'Instances': [instance['InstanceId'] for instance in asg.get('Instances', [])],
                'Tags': {tag['Key']: tag['Value'] for tag in asg.get('Tags', []) if 'Key' in tag and 'Value' in tag}
            }
            asgs.append(asg_info)
        
        return asgs
    
    except ClientError as e:
        print(f"Error fetching ASG details: {e}")
        return []

def is_instance_in_asg(asg_client, instance_id):
    """Check if an EC2 instance is part of an Auto Scaling Group."""
    try:
        response = asg_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        if response['AutoScalingInstances']:
            return response['AutoScalingInstances'][0]['AutoScalingGroupName']
        return None
    except ClientError as e:
        print(f"Error checking ASG membership for instance {instance_id}: {e}")
        return None

def create_ec2_instance(ec2_client):
    """Create a new EC2 instance with user-specified parameters."""
    try:
        # Fetch available AMIs (latest Amazon Linux 2 as default)
        response = ec2_client.describe_images(
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*']},
                {'Name': 'architecture', 'Values': ['x86_64']}
            ],
            Owners=['amazon']
        )
        amis = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
        ami_choices = [Choice(ami['ImageId'], name=f"{ami['Name']} ({ami['ImageId']})") for ami in amis[:5]]
        ami_id = inquirer.select(
            message="Select AMI:",
            choices=ami_choices
        ).execute()

        # Fetch instance types
        instance_types = ['t2.micro', 't3.micro', 't3.small', 'm5.large']
        instance_type = inquirer.select(
            message="Select instance type:",
            choices=instance_types,
            default='t2.micro'
        ).execute()

        # Fetch key pairs
        response = ec2_client.describe_key_pairs()
        key_pairs = [kp['KeyName'] for kp in response['KeyPairs']]
        key_pair = inquirer.select(
            message="Select key pair (or skip):",
            choices=key_pairs + ['None'],
            default='None'
        ).execute()

        # Fetch security groups
        response = ec2_client.describe_security_groups()
        security_groups = [sg['GroupId'] for sg in response['SecurityGroups']]
        security_group = inquirer.select(
            message="Select security group:",
            choices=security_groups
        ).execute()

        # Fetch subnets
        response = ec2_client.describe_subnets()
        subnets = [subnet['SubnetId'] for subnet in response['Subnets']]
        subnet_id = inquirer.select(
            message="Select subnet:",
            choices=subnets
        ).execute()

        # Optional Name tag
        name_tag = inquirer.text(
            message="Enter instance Name tag (optional, press Enter to skip):"
        ).execute().strip()

        # Create instance
        instance_params = {
            'ImageId': ami_id,
            'InstanceType': instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'SubnetId': subnet_id,
            'SecurityGroupIds': [security_group]
        }
        if key_pair != 'None':
            instance_params['KeyName'] = key_pair
        if name_tag:
            instance_params['TagSpecifications'] = [
                {
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': name_tag}]
                }
            ]

        response = ec2_client.run_instances(**instance_params)
        instance_id = response['Instances'][0]['InstanceId']
        print(f"Creating instance {instance_id}...")
        ec2_client.get_waiter('instance_running').wait(InstanceIds=[instance_id])
        print(f"Instance {instance_id} created and running.")
        return instance_id
    except ClientError as e:
        print(f"Error creating EC2 instance: {e}")
        return None

def modify_ec2_instance(ec2_client, instance_id):
    """Modify EC2 instance attributes (tags, security groups)."""
    try:
        # Fetch current instance details
        instances = fetch_ec2_instances(ec2_client, {'instance-id': [instance_id]})
        if not instances:
            print(f"Instance {instance_id} not found.")
            return
        instance = instances[0]

        action = inquirer.select(
            message=f"Modify instance {instance_id}:",
            choices=[
                Choice("tags", name="Modify Tags"),
                Choice("security_groups", name="Modify Security Groups"),
                Choice("return", name="Return")
            ]
        ).execute()

        if action == "tags":
            current_tags = instance['Tags']
            print(f"Current tags: {current_tags}")
            new_name = inquirer.text(
                message="Enter new Name tag (press Enter to keep current):",
                default=current_tags.get('Name', '')
            ).execute().strip()
            if new_name:
                ec2_client.create_tags(
                    Resources=[instance_id],
                    Tags=[{'Key': 'Name', 'Value': new_name}]
                )
                print(f"Updated Name tag for {instance_id} to '{new_name}'.")
            else:
                print("No changes made to tags.")

        elif action == "security_groups":
            # Fetch available security groups
            response = ec2_client.describe_security_groups()
            security_groups = [sg['GroupId'] for sg in response['SecurityGroups']]
            new_sg = inquirer.select(
                message="Select new security group:",
                choices=security_groups
            ).execute()
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                SecurityGroups=[new_sg]
            )
            print(f"Updated security group for {instance_id} to {new_sg}.")

        elif action == "return":
            print("No modifications made.")
    except ClientError as e:
        print(f"Error modifying instance {instance_id}: {e}")

def control_ec2_instance(ec2_client, asg_client, instance_id):
    """Control EC2 instance state (start, stop, terminate)."""
    asg_name = is_instance_in_asg(asg_client, instance_id)
    if asg_name:
        print(f"Instance {instance_id} is part of Auto Scaling Group '{asg_name}'.")
        action = inquirer.select(
            message="Choose action:",
            choices=[
                Choice("start", name="Start Instance"),
                Choice("stop", name="Stop Instance"),
                Choice("refresh", name="Refresh in ASG"),
                Choice("return", name="Return")
            ]
        ).execute()
    else:
        action = inquirer.select(
            message="Choose action:",
            choices=[
                Choice("start", name="Start Instance"),
                Choice("stop", name="Stop Instance"),
                Choice("terminate", name="Terminate Instance"),
                Choice("return", name="Return")
            ]
        ).execute()
    
    if action == "return":
        return None
    
    try:
        if action == "start":
            ec2_client.start_instances(InstanceIds=[instance_id])
            print(f"Starting instance {instance_id}...")
            ec2_client.get_waiter('instance_running').wait(InstanceIds=[instance_id])
            print(f"Instance {instance_id} is now running.")
        elif action == "stop":
            ec2_client.stop_instances(InstanceIds=[instance_id])
            print(f"Stopping instance {instance_id}...")
            ec2_client.get_waiter('instance_stopped').wait(InstanceIds=[instance_id])
            print(f"Instance {instance_id} is now stopped.")
        elif action == "terminate" and not asg_name:
            confirm = inquirer.confirm(
                message=f"Confirm termination of {instance_id}?",
                default=False
            ).execute()
            if confirm:
                ec2_client.terminate_instances(InstanceIds=[instance_id])
                print(f"Terminating instance {instance_id}...")
                ec2_client.get_waiter('instance_terminated').wait(InstanceIds=[instance_id])
                print(f"Instance {instance_id} is now terminated.")
            else:
                print("Termination cancelled.")
        elif action == "refresh" and asg_name:
            return asg_name
        else:
            print("Invalid action or termination not allowed for ASG instances.")
    except ClientError as e:
        print(f"Error performing action on instance {instance_id}: {e}")
    return None

def modify_asg_properties(asg_client, asg_name):
    """Modify ASG properties (min/max/desired capacity)."""
    try:
        min_size = inquirer.number(
            message="Enter new Min Size:",
            min_allowed=0,
            validate=lambda x: x >= 0
        ).execute()
        max_size = inquirer.number(
            message="Enter new Max Size:",
            min_allowed=min_size,
            validate=lambda x: x >= min_size
        ).execute()
        desired_capacity = inquirer.number(
            message="Enter new Desired Capacity:",
            min_allowed=min_size,
            max_allowed=max_size,
            validate=lambda x: min_size <= x <= max_size
        ).execute()
        
        asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            MinSize=int(min_size),
            MaxSize=int(max_size),
            DesiredCapacity=int(desired_capacity)
        )
        print(f"Successfully updated ASG {asg_name} with Min: {min_size}, Max: {max_size}, Desired: {desired_capacity}")
    except (ValueError, ClientError) as e:
        print(f"Error modifying ASG {asg_name}: {e}")

def refresh_asg_instance(asg_client, asg_name):
    """Start an instance refresh for an Auto Scaling Group."""
    try:
        response = asg_client.start_instance_refresh(
            AutoScalingGroupName=asg_name,
            Strategy='Rolling',
            Preferences={
                'MinHealthyPercentage': 90,
                'InstanceWarmup': 300
            }
        )
        refresh_id = response['InstanceRefreshId']
        print(f"Started instance refresh for ASG {asg_name}. Refresh ID: {refresh_id}")
        
        while True:
            response = asg_client.describe_instance_refreshes(
                AutoScalingGroupName=asg_name,
                InstanceRefreshIds=[refresh_id]
            )
            refresh = response['InstanceRefreshes'][0]
            status = refresh['Status']
            print(f"Refresh Status: {status}")
            if status in ['Successful', 'Failed', 'Cancelling', 'Cancelled']:
                print(f"Instance refresh {status} for ASG {asg_name}")
                break
            time.sleep(10)
    except ClientError as e:
        print(f"Error refreshing instances in ASG {asg_name}: {e}")

def display_instances(instances):
    """Display EC2 instances in a formatted manner."""
    if not instances:
        print("No instances found.")
        return
    for instance in instances:
        print(f"Instance ID: {instance['InstanceId']}")
        print(f"  Type: {instance['InstanceType']}")
        print(f"  State: {instance['State']}")
        print(f"  Private IP: {instance['PrivateIpAddress']}")
        print(f"  Public IP: {instance['PublicIpAddress']}")
        print(f"  Launch Time: {instance['LaunchTime']}")
        print(f"  Tags: {instance['Tags']}")
        print(f"  Security Groups: {instance['SecurityGroups']}")
        print(f"  Subnet: {instance['SubnetId']}")
        print(f"  VPC: {instance['VpcId']}")
        print("-" * 50)

def display_asgs(asgs):
    """Display Auto Scaling Groups in a formatted manner."""
    if not asgs:
        print("No Auto Scaling Groups found.")
        return
    for asg in asgs:
        print(f"ASG Name: {asg['AutoScalingGroupName']}")
        print(f"  Min Size: {asg['MinSize']}")
        print(f"  Max Size: {asg['MaxSize']}")
        print(f"  Desired Capacity: {asg['DesiredCapacity']}")
        print(f"  Instances: {asg['Instances']}")
        print(f"  Tags: {asg['Tags']}")
        print("-" * 50)

def asg_control_panel(asg_client, preselected_asg=None):
    """ASG control panel for viewing, searching, or modifying ASGs."""
    if preselected_asg:
        asgs = fetch_asg_details(asg_client, preselected_asg)
        if not asgs:
            print(f"ASG {preselected_asg} not found.")
            return
        selected_asg = asgs[0]
    else:
        action = inquirer.select(
            message="Auto Scaling Group Menu:",
            choices=[
                Choice("view_all", name="View All ASGs"),
                Choice("search", name="Search ASG by Name"),
                Choice("return", name="Return")
            ]
        ).execute()

        if action == "view_all":
            asgs = fetch_asg_details(asg_client)
            display_asgs(asgs)
            if not asgs:
                return
            asg_choices = [Choice(asg['AutoScalingGroupName'], name=f"{asg['AutoScalingGroupName']} (Instances: {len(asg['Instances'])})") for asg in asgs]
            asg_choices.append(Choice("return", name="Return"))
            selected_asg_name = inquirer.select(
                message="Select ASG to modify (or return):",
                choices=asg_choices
            ).execute()
            if selected_asg_name == "return":
                return
            selected_asg = next(asg for asg in asgs if asg['AutoScalingGroupName'] == selected_asg_name)

        elif action == "search":
            asg_name = inquirer.text(
                message="Enter ASG name (partial match):"
            ).execute().strip()
            asgs = fetch_asg_details(asg_client)
            matching_asgs = [asg for asg in asgs if asg_name.lower() in asg['AutoScalingGroupName'].lower()]
            if not matching_asgs:
                print(f"No ASGs found matching '{asg_name}'.")
                return
            display_asgs(matching_asgs)
            asg_choices = [Choice(asg['AutoScalingGroupName'], name=f"{asg['AutoScalingGroupName']} (Instances: {len(asg['Instances'])})") for asg in matching_asgs]
            asg_choices.append(Choice("return", name="Return"))
            selected_asg_name = inquirer.select(
                message="Select ASG to modify (or return):",
                choices=asg_choices
            ).execute()
            if selected_asg_name == "return":
                return
            selected_asg = next(asg for asg in matching_asgs if asg['AutoScalingGroupName'] == selected_asg_name)

        elif action == "return":
            return

    asg_name = selected_asg['AutoScalingGroupName']
    
    while True:
        action = inquirer.select(
            message=f"ASG Control Panel: {asg_name}",
            choices=[
                Choice("modify", name="Modify ASG Properties"),
                Choice("refresh", name="Refresh Instances"),
                Choice("return", name="Return")
            ]
        ).execute()
        
        if action == "modify":
            modify_asg_properties(asg_client, asg_name)
        elif action == "refresh":
            refresh_asg_instance(asg_client, asg_name)
        elif action == "return":
            break

def refresh_asg_menu(asg_client):
    """Menu to search for an ASG and initiate an instance refresh."""
    asg_name = inquirer.text(
        message="Enter ASG name (partial match):"
    ).execute().strip()
    asgs = fetch_asg_details(asg_client)
    matching_asgs = [asg for asg in asgs if asg_name.lower() in asg['AutoScalingGroupName'].lower()]
    if not matching_asgs:
        print(f"No ASGs found matching '{asg_name}'.")
        return
    
    asg_choices = [Choice(asg['AutoScalingGroupName'], name=f"{asg['AutoScalingGroupName']} (Instances: {len(asg['Instances'])})") for asg in matching_asgs]
    selected_asg_name = inquirer.select(
        message="Select ASG to refresh:",
        choices=asg_choices
    ).execute()
    
    confirm = inquirer.confirm(
        message=f"Start instance refresh for ASG {selected_asg_name}?",
        default=True
    ).execute()
    if confirm:
        refresh_asg_instance(asg_client, selected_asg_name)
    else:
        print("Refresh cancelled.")

def main():
    # Check Python version
    check_python_version()
    
    # Try default credentials first
    boto3_session = None
    try:
        boto3_session = boto3.Session()
        sts_client = boto3_session.client('sts')
        response = sts_client.get_caller_identity()
        region = prompt_for_region()
        boto3_session = boto3.Session(region_name=region)
        print(f"AWS credentials validated. Connected as: {response['Arn']} in region {region}")
    except (NoCredentialsError, InvalidClientTokenId, ClientError):
        print("No valid AWS credentials found. Prompting for credentials...")
        access_key, secret_key, session_token, region = prompt_for_credentials()
        boto3_session = validate_aws_credentials(access_key, secret_key, session_token, region)
        if not boto3_session:
            print("Exiting due to invalid credentials.")
            sys.exit(1)
    
    # Initialize Boto3 clients
    ec2_client = boto3_session.client('ec2')
    asg_client = boto3_session.client('autoscaling')
    
    while True:
        action = inquirer.select(
            message="EC2 Manager CLI",
            choices=[
                Choice("view_running", name="View All Running Instances"),
                Choice("search_running", name="Search Running Instances"),
                Choice("create_ec2", name="Create EC2 Instance"),
                Choice("modify_ec2", name="Modify EC2 Instance"),
                Choice("modify_state", name="Modify Instance State"),
                Choice("auto_scaling", name="Auto Scaling"),
                Choice("refresh_asg", name="Refresh Instances"),
                Choice("exit", name="Exit")
            ]
        ).execute()
        
        if action == "view_running":
            print("\nFetching all running EC2 instances...")
            instances = fetch_ec2_instances(ec2_client, {'instance-state-name': 'running'})
            display_instances(instances)
        
        elif action == "search_running":
            search_by = inquirer.select(
                message="Search by:",
                choices=[
                    Choice("tag:Name", name="Name Tag"),
                    Choice("private-ip-address", name="Private IP Address")
                ]
            ).execute()
            search_term = inquirer.text(
                message=f"Enter {search_by.replace('tag:', '')} (partial match):"
            ).execute().strip()
            print(f"\nSearching for running instances matching '{search_term}'...")
            instances = search_ec2_instances(ec2_client, search_term, search_by)
            display_instances(instances)
        
        elif action == "create_ec2":
            create_ec2_instance(ec2_client)
        
        elif action == "modify_ec2":
            instance_id = inquirer.text(message="Enter EC2 Instance ID:").execute().strip()
            modify_ec2_instance(ec2_client, instance_id)
        
        elif action == "modify_state":
            instance_id = inquirer.text(message="Enter EC2 Instance ID:").execute().strip()
            asg_name = control_ec2_instance(ec2_client, asg_client, instance_id)
            if asg_name:
                asg_control_panel(asg_client, preselected_asg=asg_name)
        
        elif action == "auto_scaling":
            asg_control_panel(asg_client)
        
        elif action == "refresh_asg":
            refresh_asg_menu(asg_client)
        
        elif action == "exit":
            print("Exiting...")
            break

if __name__ == "__main__":
    main()