import sys
import boto3
import json
import time
from botocore.exceptions import ClientError, NoCredentialsError, InvalidClientTokenId
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import HTML

# List of valid AWS regions (including standard and GovCloud)
VALID_AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'us-gov-west-1', 'us-gov-east-1',  # GovCloud regions
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

def prompt_for_credentials(session):
    """Prompt user for AWS credentials and region."""
    print("Please enter your AWS credentials (obtained from your STS portal).")
    access_key = session.prompt(HTML('<ansiblue>AWS Access Key ID:</ansiblue> ')).strip()
    secret_key = session.prompt(HTML('<ansiblue>AWS Secret Access Key:</ansiblue> '), is_password=True).strip()
    session_token = session.prompt(HTML('<ansiblue>AWS Session Token (optional, press Enter to skip):</ansiblue> ')).strip()
    region = prompt_for_region(session)
    return access_key, secret_key, session_token or None, region

def prompt_for_region(session):
    """Prompt user for AWS region with validation."""
    region_completer = WordCompleter(VALID_AWS_REGIONS, ignore_case=True)
    while True:
        region = session.prompt(
            HTML('<ansiblue>Enter AWS region (e.g., us-east-1, us-gov-west-1):</ansiblue> '),
            completer=region_completer
        ).strip()
        if region in VALID_AWS_REGIONS:
            return region
        print(f"Invalid region. Please choose from: {', '.join(VALID_AWS_REGIONS)}")

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
                    'InstanceId': instance.get('InstanceId'),
                    'InstanceType': instance.get('InstanceType'),
                    'State': instance.get('State', {}).get('Name'),
                    'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                    'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                    'LaunchTime': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else 'N/A',
                    'Tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                    'SecurityGroups': [sg['GroupName'] for sg in instance.get('SecurityGroups', [])],
                    'SubnetId': instance.get('SubnetId', 'N/A'),
                    'VpcId': instance.get('VpcId', 'N/A')
                }
                instances.append(instance_info)
        
        return instances
    
    except ClientError as e:
        print(f"Error fetching EC2 instances: {e}")
        return []

def fetch_asg_details(asg_client):
    """Fetch all Auto Scaling Groups."""
    try:
        response = asg_client.describe_auto_scaling_groups()
        asgs = []
        
        for asg in response['AutoScalingGroups']:
            asg_info = {
                'AutoScalingGroupName': asg.get('AutoScalingGroupName'),
                'MinSize': asg.get('MinSize'),
                'MaxSize': asg.get('MaxSize'),
                'DesiredCapacity': asg.get('DesiredCapacity'),
                'Instances': [instance['InstanceId'] for instance in asg.get('Instances', [])],
                # FIX: Corrected a syntax error here. Removed the extra ']' at the end of the line.
                'Tags': {tag['Key']: tag['Value'] for tag in asg.get('Tags', [])}
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

def control_ec2_instance(ec2_client, asg_client, session):
    """Control EC2 instance state (start, stop, terminate)."""
    instance_id = session.prompt(HTML('<ansiblue>Enter EC2 Instance ID:</ansiblue> ')).strip()
    
    # Check if instance is in an ASG
    asg_name = is_instance_in_asg(asg_client, instance_id)
    if asg_name:
        print(f"Instance {instance_id} is part of Auto Scaling Group '{asg_name}'.")
        action = session.prompt(HTML('<ansiblue>Choose action (start/stop/refresh in ASG/return):</ansiblue> ')).lower()
    else:
        action = session.prompt(HTML('<ansiblue>Choose action (start/stop/terminate/return):</ansiblue> ')).lower()
    
    if action == 'return':
        return
    
    try:
        if action == 'start':
            ec2_client.start_instances(InstanceIds=[instance_id])
            print(f"Starting instance {instance_id}...")
            ec2_client.get_waiter('instance_running').wait(InstanceIds=[instance_id])
            print(f"Instance {instance_id} is now running.")
        
        elif action == 'stop':
            ec2_client.stop_instances(InstanceIds=[instance_id])
            print(f"Stopping instance {instance_id}...")
            # FIX: Corrected the waiter name from 'instance_stopEchoes of Eternity stopped' to 'instance_stopped'.
            ec2_client.get_waiter('instance_stopped').wait(InstanceIds=[instance_id])
            print(f"Instance {instance_id} is now stopped.")
        
        elif action == 'terminate' and not asg_name:
            # FIX: Corrected the prompt to use an f-string so the instance_id is displayed.
            confirm = session.prompt(HTML(f'<ansiblue>Confirm termination of {instance_id} (yes/no):</ansiblue> ')).lower()
            if confirm == 'yes':
                ec2_client.terminate_instances(InstanceIds=[instance_id])
                print(f"Terminating instance {instance_id}...")
                ec2_client.get_waiter('instance_terminated').wait(InstanceIds=[instance_id])
                print(f"Instance {instance_id} is now terminated.")
            else:
                print("Termination cancelled.")
        
        elif action == 'refresh' and asg_name:
            print(f"Redirecting to ASG control panel for instance refresh in {asg_name}...")
            # ASG refresh handled in ASG control panel
            return asg_name
        else:
            print("Invalid action or termination not allowed for ASG instances.")
    
    except ClientError as e:
        print(f"Error performing action on instance {instance_id}: {e}")

def update_asg_capacity(asg_client, asg_name, desired_capacity):
    """Update the desired capacity of an Auto Scaling Group."""
    try:
        asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            DesiredCapacity=desired_capacity
        )
        print(f"Successfully updated {asg_name} desired capacity to {desired_capacity}")
    except ClientError as e:
        print(f"Error updating ASG {asg_name}: {e}")

def modify_asg_properties(asg_client, session, asg_name):
    """Modify ASG properties (min/max/desired capacity)."""
    print(f"Modifying Auto Scaling Group: {asg_name}")
    try:
        min_size = int(session.prompt(HTML('<ansiblue>Enter new Min Size:</ansiblue> ')))
        max_size = int(session.prompt(HTML('<ansiblue>Enter new Max Size:</ansiblue> ')))
        desired_capacity = int(session.prompt(HTML('<ansiblue>Enter new Desired Capacity:</ansiblue> ')))
        
        asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            MinSize=min_size,
            MaxSize=max_size,
            DesiredCapacity=desired_capacity
        )
        print(f"Successfully updated ASG {asg_name} with Min: {min_size}, Max: {max_size}, Desired: {desired_capacity}")
    except (ValueError, ClientError) as e:
        print(f"Error modifying ASG {asg_name}: {e}")

def refresh_asg_instance(asg_client, session, asg_name):
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
        
        # Monitor refresh status
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

def asg_control_panel(asg_client, session, preselected_asg=None):
    """ASG control panel for managing Auto Scaling Groups."""
    asgs = fetch_asg_details(asg_client)
    if not asgs:
        print("No Auto Scaling Groups found.")
        return
    
    if preselected_asg:
        selected_asg = next((asg for asg in asgs if asg['AutoScalingGroupName'] == preselected_asg), None)
        if not selected_asg:
            print(f"ASG {preselected_asg} not found.")
            return
    else:
        print("\nAvailable Auto Scaling Groups:")
        for i, asg in enumerate(asgs, 1):
            print(f"{i}. {asg['AutoScalingGroupName']}")
        choice = session.prompt(HTML('<ansiblue>Select ASG number or name (or "return"):</ansiblue> ')).strip()
        if choice.lower() == 'return':
            return
        try:
            index = int(choice) - 1
            selected_asg = asgs[index]
        except (ValueError, IndexError):
            selected_asg = next((asg for asg in asgs if asg['AutoScalingGroupName'] == choice), None)
            if not selected_asg:
                print("Invalid ASG selection.")
                return
    
    asg_name = selected_asg['AutoScalingGroupName']
    
    asg_options = ['Modify ASG Properties', 'Refresh Instances', 'Return']
    asg_completer = WordCompleter(asg_options, ignore_case=True)
    
    while True:
        print(f"\n=== ASG Control Panel: {asg_name} ===")
        for i, option in enumerate(asg_options, 1):
            print(f"{i}. {option}")
        
        choice = session.prompt(HTML('<ansigreen>Select an option (1-3 or type option):</ansigreen> '), completer=asg_completer)
        
        if choice == '1' or choice.lower() == 'modify asg properties':
            modify_asg_properties(asg_client, session, asg_name)
        elif choice == '2' or choice.lower() == 'refresh instances':
            refresh_asg_instance(asg_client, session, asg_name)
        elif choice == '3' or choice.lower() == 'return':
            break
        else:
            print("Invalid option. Please select 1-3 or type the option name.")

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
        print(f"  Tags: {json.dumps(instance['Tags'])}")
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
        print(f"  Tags: {json.dumps(asg['Tags'])}")
        print("-" * 50)

def get_ec2_filters(ec2_client):
    """Return a dictionary of common EC2 filter names and example values."""
    return {
        'instance-state-name': ['running', 'stopped', 'pending', 'shutting-down', 'terminated', 'stopping'],
        'instance-type': ['t2.micro', 't3.micro', 'm5.large', 'c5.xlarge'],
        'tag:Name': ['*'],
        'vpc-id': ['*'],
        'subnet-id': ['*'],
        'availability-zone': ['us-east-1a', 'us-east-1b', 'us-west-2a']
    }

def prompt_for_filters(session, filter_options):
    """Prompt user to input filters for EC2 instances."""
    filters = {}
    print("Enter filters (e.g., 'instance-state-name: running' or leave blank to skip). Type 'done' when finished.")
    
    while True:
        filter_input = session.prompt(HTML('<ansiblue>Filter (name:value or done):</ansiblue> '))
        if filter_input.lower() == 'done':
            break
        if ':' not in filter_input:
            print("Invalid format. Use 'filter-name:value' (e.g., 'instance-state-name:running').")
            continue
        name, value = filter_input.split(':', 1)
        name = name.strip()
        value = value.strip()
        if name in filter_options:
            filters[name] = value.split(',') if ',' in value else value
        else:
            print(f"Invalid filter name. Choose from: {list(filter_options.keys())}")
    
    return filters

def main():
    # Check Python version
    check_python_version()
    
    # Set up prompt session with key bindings
    bindings = KeyBindings()
    session = PromptSession(multiline=False, key_bindings=bindings)
    
    # Try default credentials first
    boto3_session = None
    try:
        boto3_session = boto3.Session()
        sts_client = boto3_session.client('sts')
        response = sts_client.get_caller_identity()
        region = prompt_for_region(session)
        boto3_session = boto3.Session(region_name=region)
        print(f"AWS credentials validated. Connected as: {response['Arn']} in region {region}")
    except (NoCredentialsError, InvalidClientTokenId, ClientError):
        print("No valid AWS credentials found. Prompting for credentials...")
        access_key, secret_key, session_token, region = prompt_for_credentials(session)
        boto3_session = validate_aws_credentials(access_key, secret_key, session_token, region)
        if not boto3_session:
            print("Exiting due to invalid credentials.")
            sys.exit(1)
    
    # Initialize Boto3 clients
    ec2_client = boto3_session.client('ec2')
    asg_client = boto3_session.client('autoscaling')
    
    # Common EC2 filter options for user guidance
    filter_options = get_ec2_filters(ec2_client)
    
    # Main menu options
    menu_options = ['List EC2 Instances', 'List Auto Scaling Groups', 'Control EC2 Instance', 'ASG Control Panel', 'Exit']
    completer = WordCompleter(menu_options, ignore_case=True)
    
    while True:
        print("\n=== AWS CLI Tool ===")
        for i, option in enumerate(menu_options, 1):
            print(f"{i}. {option}")
        
        choice = session.prompt(HTML('<ansigreen>Select an option (1-5 or type option):</ansigreen> '), completer=completer)
        
        if choice == '1' or choice.lower() == 'list ec2 instances':
            print("\nFetching EC2 instances...")
            filters = prompt_for_filters(session, filter_options)
            instances = fetch_ec2_instances(ec2_client, filters)
            display_instances(instances)
        
        elif choice == '2' or choice.lower() == 'list auto scaling groups':
            print("\nFetching Auto Scaling Groups...")
            asgs = fetch_asg_details(asg_client)
            display_asgs(asgs)
        
        elif choice == '3' or choice.lower() == 'control ec2 instance':
            asg_name = control_ec2_instance(ec2_client, asg_client, session)
            if asg_name:
                asg_control_panel(asg_client, session, preselected_asg=asg_name)
        
        elif choice == '4' or choice.lower() == 'asg control panel':
            asg_control_panel(asg_client, session)
        
        elif choice == '5' or choice.lower() == 'exit':
            print("Exiting...")
            break
        
        else:
            print("Invalid option. Please select 1-5 or type the option name.")

if __name__ == "__main__":
    main()