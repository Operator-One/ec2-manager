import sys
import boto3
import time
from botocore.exceptions import ClientError, NoCredentialsError
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text

# --- Initialize Console ---
console = Console()

# --- Region Descriptions ---
REGION_DESCRIPTIONS = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "af-south-1": "Africa (Cape Town)",
    "ap-east-1": "Asia Pacific (Hong Kong)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ca-central-1": "Canada (Central)",
    "eu-central-1": "Europe (Frankfurt)",
    "eu-west-1": "Europe (Ireland)",
    "eu-west-2": "Europe (London)",
    "eu-west-3": "Europe (Paris)",
    "eu-south-1": "Europe (Milan)",
    "eu-north-1": "Europe (Stockholm)",
    "me-south-1": "Middle East (Bahrain)",
    "sa-east-1": "South America (São Paulo)",
    "us-gov-east-1": "AWS GovCloud (US-East)",
    "us-gov-west-1": "AWS GovCloud (US-West)",
}


# --- Main Application Logic ---

def check_python_version():
    """Ensure Python version is 3.6 or higher."""
    if sys.version_info < (3, 6):
        console.print("[bold red]Error: This tool requires Python 3.6 or higher.[/bold red]")
        sys.exit(1)

def get_boto_session():
    """Establish and validate a boto3 session."""
    try:
        session = boto3.Session()
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        console.print(f"✅ Logged in as [bold cyan]{identity['Arn']}[/bold cyan]")
        return session
    except (NoCredentialsError, ClientError):
        console.print("[yellow]AWS credentials not found. Please enter them manually.[/yellow]")
        access_key = questionary.text("AWS Access Key ID:").ask()
        secret_key = questionary.password("AWS Secret Access Key:").ask()
        if not access_key or not secret_key:
            console.print("[bold red]Credentials cannot be empty.[/bold red]")
            return None
        try:
            session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            console.print(f"✅ Logged in as [bold cyan]{identity['Arn']}[/bold cyan]")
            return session
        except ClientError as e:
            console.print(f"[bold red]Login failed: {e}[/bold red]")
            return None

def select_aws_region(session):
    """Prompt user to select an AWS region or enter one manually."""
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        choices = [
            questionary.Choice(title=f"{REGION_DESCRIPTIONS.get(region, region)}", value=region)
            for region in sorted(regions)
        ]
        choices.extend([questionary.Separator(), questionary.Choice(title="[ Manually Enter a Region ]", value="__manual__")])
        selected_option = questionary.select("Select AWS Region:", choices=choices, use_indicator=True).ask()
        if selected_option == "__manual__":
            return questionary.text("Enter the custom region code:", validate=lambda t: len(t.strip()) > 0).ask()
        return selected_option
    except ClientError as e:
        console.print(f"[bold red]Could not fetch public AWS regions: {e}[/bold red]")
        return questionary.text("Enter your custom region code:", validate=lambda t: len(t.strip()) > 0).ask()

# --- Generic Helper Functions ---

def fetch_data(client, method_name, resource_key, message="Fetching data...", params=None):
    """Generic fetcher with a spinner that supports filters and pagination."""
    if params is None:
        params = {}
    with console.status(f"[bold green]{message}[/bold green]"):
        try:
            method_to_call = getattr(client, method_name)
            if client.can_paginate(method_name):
                paginator = client.get_paginator(method_name)
                pages = paginator.paginate(**params)
                return [item for page in pages for item in page.get(resource_key, [])]
            else:
                response = method_to_call(**params)
                return response.get(resource_key, [])
        except ClientError as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
            return []

def get_name_tag(resource):
    """Get the 'Name' tag from any resource that has a 'Tags' key."""
    for tag in resource.get('Tags', []):
        if tag['Key'] == 'Name':
            return tag['Value']
    return 'N/A'

def select_instance(ec2_client, state='*'):
    """Display a list of instances for the user to select from."""
    params = {}
    if state != '*':
        params['Filters'] = [{'Name': 'instance-state-name', 'Values': [state]}]
    
    reservations = fetch_data(
        ec2_client, 'describe_instances', 'Reservations',
        f"Fetching {state if state != '*' else 'all'} instances...",
        params=params
    )
    
    flat_instances = [inst for res in reservations for inst in res['Instances']]
    if not flat_instances:
        console.print(f"[yellow]No {state if state != '*' else ''} instances to select.[/yellow]")
        return None
        
    choices = [
        questionary.Choice(
            title=f"{inst['InstanceId']} ({get_name_tag(inst)}) - {inst['InstanceType']} - [{inst['State']['Name']}]",
            value=inst['InstanceId']
        ) for inst in flat_instances
    ]
    
    return questionary.select("Select an instance:", choices=choices, use_indicator=True).ask()

# --- Display Functions ---
def display_instances(instances):
    """Display EC2 instances in a rich table."""
    if not instances:
        console.print("[yellow]No instances found.[/yellow]")
        return
    table = Table(title="EC2 Instances", style="cyan", title_style="bold magenta", header_style="bold blue")
    table.add_column("Instance ID")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("State")
    table.add_column("Private IP")
    table.add_column("Public IP")
    
    for inst in instances:
        inst['NameTag'] = get_name_tag(inst)
        state_name = inst.get('State', {}).get('Name', 'N/A')
        style = "green" if state_name == "running" else "red" if state_name == "stopped" else "yellow"
        table.add_row(
            inst.get('InstanceId', 'N/A'),
            inst.get('NameTag', 'N/A'),
            inst.get('InstanceType', 'N/A'),
            Text(state_name, style=style),
            inst.get('PrivateIpAddress', 'N/A'),
            inst.get('PublicIpAddress', 'N/A')
        )
    console.print(table)

def display_asgs(asgs):
    """Display Auto Scaling Groups in a rich table."""
    if not asgs:
        console.print("[yellow]No Auto Scaling Groups found.[/yellow]")
        return
    table = Table(title="Auto Scaling Groups", style="cyan", title_style="bold magenta", header_style="bold blue")
    table.add_column("ASG Name")
    table.add_column("Min")
    table.add_column("Max")
    table.add_column("Desired")
    table.add_column("Instances")
    for asg in asgs:
        table.add_row(
            asg['AutoScalingGroupName'],
            str(asg['MinSize']),
            str(asg['MaxSize']),
            str(asg['DesiredCapacity']),
            str(len(asg.get('Instances', [])))
        )
    console.print(table)


# --- EC2 Management ---
def create_ec2_instance(ec2_client):
    """A guided workflow to create a new EC2 instance."""
    console.clear()
    console.print(Panel("[bold]Create New EC2 Instance[/bold]", expand=False, border_style="green"))
    try:
        # AMI Selection
        amis = fetch_data(ec2_client, 'describe_images', 'Images', "Fetching AMIs...", params={'Owners': ['amazon'], 'Filters': [{'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']}]})
        if not amis: return
        ami_choices = [questionary.Choice(f"{ami['Name']}", value=ami['ImageId']) for ami in sorted(amis, key=lambda x: x['CreationDate'], reverse=True)[:10]]
        ami_id = questionary.select("Select an Amazon Machine Image (AMI):", choices=ami_choices).ask()
        if not ami_id: return

        # Instance Type
        instance_type = questionary.select("Select an instance type:", choices=["t2.micro", "t3.small", "m5.large"], default="t2.micro").ask()
        if not instance_type: return

        # Key Pair
        key_pairs = fetch_data(ec2_client, 'describe_key_pairs', 'KeyPairs', "Fetching Key Pairs...")
        kp_choices = [kp['KeyName'] for kp in key_pairs] + ["[ No Key Pair ]"]
        key_name = questionary.select("Select a key pair:", choices=kp_choices).ask()
        if not key_name: return

        # Networking
        vpcs = fetch_data(ec2_client, 'describe_vpcs', 'Vpcs', "Fetching VPCs...")
        if not vpcs: return
        vpc_choices = [questionary.Choice(f"{vpc['VpcId']} ({get_name_tag(vpc)})", value=vpc['VpcId']) for vpc in vpcs]
        vpc_id = questionary.select("Select a VPC:", choices=vpc_choices).ask()
        if not vpc_id: return

        subnets = fetch_data(ec2_client, 'describe_subnets', 'Subnets', "Fetching Subnets...", params={'Filters': [{'Name': 'vpc-id', 'Values': [vpc_id]}]})
        if not subnets: return
        subnet_choices = [questionary.Choice(f"{sn['SubnetId']} ({sn['AvailabilityZone']})", value=sn['SubnetId']) for sn in subnets]
        subnet_id = questionary.select("Select a Subnet:", choices=subnet_choices).ask()
        if not subnet_id: return

        sgs = fetch_data(ec2_client, 'describe_security_groups', 'SecurityGroups', "Fetching Security Groups...", params={'Filters': [{'Name': 'vpc-id', 'Values': [vpc_id]}]})
        if not sgs: return
        sg_choices = [questionary.Choice(f"{sg['GroupName']} ({sg['GroupId']})", value=sg['GroupId']) for sg in sgs]
        security_group_ids = questionary.checkbox("Select Security Groups:", choices=sg_choices).ask()
        if not security_group_ids: return

        # Tagging
        tags = []
        name_tag = questionary.text("Enter a 'Name' tag for the instance:").ask()
        if name_tag is None: return
        tags.append({'Key': 'Name', 'Value': name_tag})

        while questionary.confirm("Add another tag?", default=False).ask():
            key = questionary.text("Tag Key:").ask()
            if not key: continue
            value = questionary.text(f"Tag Value for '{key}':").ask()
            if value is None: continue
            tags.append({'Key': key, 'Value': value})

        # Launch
        run_params = {
            'ImageId': ami_id, 'InstanceType': instance_type, 'SubnetId': subnet_id,
            'SecurityGroupIds': security_group_ids, 'MinCount': 1, 'MaxCount': 1,
            'TagSpecifications': [{'ResourceType': 'instance', 'Tags': tags}]
        }
        if key_name != "[ No Key Pair ]": run_params['KeyName'] = key_name

        with console.status("[bold yellow]Submitting instance launch request...[/bold yellow]"):
            instance = ec2_client.run_instances(**run_params)['Instances'][0]
            instance_id = instance['InstanceId']
        
        console.print(f"✅ Instance launch request submitted. ID: [bold cyan]{instance_id}[/bold cyan]")
        
        with console.status(f"[bold yellow]Waiting for instance {instance_id} to enter 'running' state...[/bold yellow]"):
            waiter = ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id])

        console.print(f"✅ [bold green]Instance {instance_id} is now running.[/bold green]")
        console.print("[bold]Fetching final instance details...[/bold]")
        
        # Final validation display
        reservations = fetch_data(ec2_client, 'describe_instances', 'Reservations', params={'InstanceIds': [instance_id]})
        final_instance = [inst for res in reservations for inst in res['Instances']]
        display_instances(final_instance)
        questionary.press_any_key_to_continue("Press any key to return to the menu...").ask()

    except ClientError as e:
        console.print(f"[bold red]Error creating instance: {e}[/bold red]")

def manage_single_instance(ec2_client, instance_id):
    """Provide a menu of management options for a selected EC2 instance."""
    while True:
        console.clear()
        console.print(Panel(f"Managing Instance: {instance_id}", expand=False, border_style="yellow"))
        action = questionary.select(
            "Select an action:",
            choices=["Change State (Start/Stop/Reboot...)", "Back"]
        ).ask()
        if action == "Back" or action is None: break
        elif action == "Change State (Start/Stop/Reboot...)":
            control_instance_state(ec2_client, instance_id)

def control_instance_state(ec2_client, instance_id):
    """Handles Start, Stop, Reboot, Terminate actions."""
    action = questionary.select(
        f"Choose a state change for {instance_id}:",
        choices=["start", "stop", "reboot", "terminate", "Back"]
    ).ask()

    if not action or action == "Back": return

    if action == "terminate" and not questionary.confirm(f"Are you sure you want to terminate {instance_id}?", default=False).ask():
        console.print("[yellow]Termination cancelled.[/yellow]")
        return
    try:
        with console.status(f"[bold yellow]Performing '{action}' on {instance_id}...[/bold yellow]"):
            if action == 'start':
                ec2_client.start_instances(InstanceIds=[instance_id])
                ec2_client.get_waiter('instance_running').wait(InstanceIds=[instance_id])
            elif action == 'stop':
                ec2_client.stop_instances(InstanceIds=[instance_id])
                ec2_client.get_waiter('instance_stopped').wait(InstanceIds=[instance_id])
            elif action == 'reboot':
                ec2_client.reboot_instances(InstanceIds=[instance_id])
            elif action == 'terminate':
                ec2_client.terminate_instances(InstanceIds=[instance_id])
                ec2_client.get_waiter('instance_terminated').wait(InstanceIds=[instance_id])
        console.print(f"✅ [bold green]Instance {instance_id} {action}ed successfully.[/bold green]")
    except ClientError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

def search_instances_by_tag(ec2_client):
    """Search for EC2 instances by a specific tag, using a 'contains' match."""
    tag_key = questionary.text("Enter the tag key to search for:").ask()
    if not tag_key: return
    
    tag_value = questionary.text(f"Enter the partial value for tag '{tag_key}':").ask()
    if tag_value is None: return

    search_pattern = f'*{tag_value}*'
    filters = [{'Name': f'tag:{tag_key}', 'Values': [search_pattern]}]
    
    reservations = fetch_data(ec2_client, 'describe_instances', 'Reservations', f"Searching for instances with tag '{tag_key}' containing '{tag_value}'...", params={'Filters': filters})
    instances = [inst for res in reservations for inst in res['Instances']]
    display_instances(instances)
    questionary.press_any_key_to_continue("Press any key to return to the menu...").ask()

def manage_ec2(ec2_client):
    """Main menu for EC2 instance management."""
    while True:
        console.clear()
        console.print(Panel("EC2 Instance Management", expand=False, border_style="green"))
        action = questionary.select(
            "Select an option:",
            choices=["View All Instances", "Search Instances by Tag", "Create New Instance", "Manage Existing Instance", "Back"],
            use_indicator=True
        ).ask()
        if action == "Back" or action is None: break
        elif action == "View All Instances":
            reservations = fetch_data(ec2_client, 'describe_instances', 'Reservations')
            instances = [inst for res in reservations for inst in res['Instances']]
            display_instances(instances)
            questionary.press_any_key_to_continue("Press any key to return to the menu...").ask()
        elif action == "Search Instances by Tag":
            search_instances_by_tag(ec2_client)
        elif action == "Create New Instance":
            create_ec2_instance(ec2_client)
        elif action == "Manage Existing Instance":
            instance_id = select_instance(ec2_client, state='*')
            if instance_id:
                manage_single_instance(ec2_client, instance_id)


# --- ASG Management ---
def manage_asg(asg_client):
    """Main menu for Auto Scaling Group management."""
    while True:
        console.clear()
        console.print(Panel("Auto Scaling Group Management", expand=False, border_style="green"))
        action = questionary.select(
            "Select an option:",
            choices=["View All ASGs", "Manage Existing ASG", "Back"],
            use_indicator=True
        ).ask()
        if action == "Back" or action is None: break
        elif action == "View All ASGs":
            asgs = fetch_data(asg_client, 'describe_auto_scaling_groups', 'AutoScalingGroups')
            display_asgs(asgs)
            questionary.press_any_key_to_continue("Press any key to return to the menu...").ask()
        elif action == "Manage Existing ASG":
            manage_single_asg(asg_client)

def manage_single_asg(asg_client):
    """Manage a specific, selected Auto Scaling Group."""
    asgs = fetch_data(asg_client, 'describe_auto_scaling_groups', 'AutoScalingGroups')
    if not asgs: return
    
    asg_choices = [questionary.Choice(title=f"{asg['AutoScalingGroupName']} ({asg['DesiredCapacity']} instances)", value=asg['AutoScalingGroupName']) for asg in asgs]
    asg_name = questionary.select("Select an ASG to manage:", choices=asg_choices).ask()
    if not asg_name: return

    while True:
        console.clear()
        console.print(Panel(f"Managing ASG: {asg_name}", expand=False, border_style="yellow"))
        action = questionary.select(
            "Select an action:",
            choices=["Set Desired Capacity", "Perform Rolling Refresh", "Back"],
            use_indicator=True
        ).ask()

        if action == "Back" or action is None: break
        elif action == "Set Desired Capacity":
            set_asg_desired_capacity(asg_client, asg_name)
        elif action == "Perform Rolling Refresh":
            perform_asg_refresh(asg_client, asg_name)

def set_asg_desired_capacity(asg_client, asg_name):
    """Set the desired capacity for a given ASG."""
    desired_str = questionary.text("Enter new desired capacity:").ask()
    if desired_str is None: return
    try:
        desired = int(desired_str)
        with console.status(f"[bold yellow]Setting desired capacity to {desired}...[/bold yellow]"):
            asg_client.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=desired)
        console.print("✅ [bold green]Desired capacity updated.[/bold green]")
    except (ValueError, TypeError):
        console.print("[bold red]Invalid number.[/bold red]")
    except ClientError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

def perform_asg_refresh(asg_client, asg_name):
    """Perform a rolling instance refresh on an ASG with a progress bar."""
    if not questionary.confirm(f"Start a rolling instance refresh for {asg_name}?", default=True).ask():
        console.print("[yellow]Refresh cancelled.[/yellow]")
        return

    skip_matching = questionary.confirm(
        "Enable 'Skip Matching'? (This will ignore instances that don't use the latest launch template)",
        default=False
    ).ask()
    if skip_matching is None:
        console.print("[yellow]Refresh cancelled.[/yellow]")
        return
        
    try:
        preferences = {
            'MinHealthyPercentage': 90,
            'SkipMatching': skip_matching
        }
        with console.status(f"[bold yellow]Initiating instance refresh...[/bold yellow]"):
            response = asg_client.start_instance_refresh(
                AutoScalingGroupName=asg_name,
                Strategy='Rolling',
                Preferences=preferences
            )
            refresh_id = response['InstanceRefreshId']
        
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        )
        
        with progress:
            task = progress.add_task(f"Refreshing {asg_name}", total=100)
            final_status = ""
            while not progress.finished:
                res = asg_client.describe_instance_refreshes(AutoScalingGroupName=asg_name, InstanceRefreshIds=[refresh_id])
                refresh_details = res['InstanceRefreshes'][0]
                status = refresh_details['Status']
                percentage = refresh_details.get('PercentageComplete', 0)
                status_reason = refresh_details.get('StatusReason', '')

                progress.update(task, completed=percentage, description=f"Status: [bold cyan]{status}[/bold cyan] - {status_reason}")

                if status in ['Successful', 'Failed', 'Cancelled', 'Cancelling']:
                    final_status = status
                    if status == 'Successful':
                        progress.update(task, completed=100)
                    break
                time.sleep(10)

        console.print(f"✅ [bold green]Instance refresh completed with status: {final_status}[/bold green]")
    except ClientError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")


# --- Main Loop ---
def main():
    """Main function to run the CLI tool."""
    check_python_version()
    
    console.clear()
    console.print(Panel("[bold magenta]AWS Resource Manager[/bold magenta] v3.9", expand=False, border_style="blue"))

    session = get_boto_session()
    if not session: sys.exit(1)

    console.clear()
    console.print(Panel("[bold magenta]AWS Resource Manager[/bold magenta] v3.9", expand=False, border_style="blue"))
    region = select_aws_region(session)
    if not region: sys.exit(1)

    # Initialize clients
    ec2 = session.client('ec2', region_name=region)
    asg = session.client('autoscaling', region_name=region)

    while True:
        console.clear()
        console.print(Panel("[bold magenta]AWS Resource Manager[/bold magenta] v3.9", expand=False, border_style="blue"))
        category = questionary.select(
            "Select a service category to manage:",
            choices=[
                "Compute (EC2 & ASG)",
                "Exit"
            ],
            use_indicator=True
        ).ask()

        if category == "Exit" or category is None: break
        
        if category == "Compute (EC2 & ASG)":
            console.clear()
            console.print(Panel("Compute Management", expand=False, border_style="blue"))
            compute_action = questionary.select(
                "Select a compute service:",
                choices=["EC2 Instances", "Auto Scaling Groups", "Back"]
            ).ask()
            if compute_action == "EC2 Instances":
                manage_ec2(ec2)
            elif compute_action == "Auto Scaling Groups":
                manage_asg(asg)
            
    console.clear()
    console.print("[bold cyan]Goodbye![/bold cyan]")

if __name__ == "__main__":
    main()