import sys
import boto3
import time
from botocore.exceptions import ClientError, NoCredentialsError
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

# --- Initialize Console ---
console = Console()

# --- Region Descriptions ---
# A mapping of region codes to more descriptive, user-friendly names.
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
        # Try to use existing credentials from environment
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
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            console.print(f"✅ Logged in as [bold cyan]{identity['Arn']}[/bold cyan]")
            return session
        except ClientError as e:
            console.print(f"[bold red]Login failed: {e}[/bold red]")
            return None

def select_aws_region(session):
    """Prompt user to select an AWS region from a descriptive list."""
    try:
        # A default region is required to make the initial call to describe_regions
        ec2_client = session.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        # Create a list of choices with descriptive names for the user
        choices = [
            questionary.Choice(
                # Show a friendly name, falling back to the code if not in our map
                title=f"{REGION_DESCRIPTIONS.get(region, region)}",
                value=region  # The actual value passed back is the region code
            ) for region in sorted(regions)
        ]

        selected_region = questionary.select(
            "Select AWS Region:",
            choices=choices,
            use_indicator=True
        ).ask()
        return selected_region
    except ClientError as e:
        console.print(f"[bold red]Could not fetch AWS regions: {e}[/bold red]")
        return None

# --- Display Functions ---

def display_instances(instances):
    """Display EC2 instances in a rich table."""
    if not instances:
        console.print("[yellow]No instances found.[/yellow]")
        return

    table = Table(title="EC2 Instances", style="cyan", title_style="bold magenta", header_style="bold blue")
    table.add_column("Instance ID", style="dim", width=20)
    table.add_column("Name Tag")
    table.add_column("Type", style="green")
    table.add_column("State", justify="center")
    table.add_column("Private IP")
    table.add_column("Public IP")

    for inst in instances:
        state = inst.get('State', {}).get('Name', 'N/A')
        style = "green" if state == "running" else "red" if state == "stopped" else "yellow"
        name = get_instance_name(inst)
        table.add_row(
            inst['InstanceId'],
            name,
            inst['InstanceType'],
            Text(state, style=style),
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
    table.add_column("ASG Name", style="bold")
    table.add_column("Min", justify="right")
    table.add_column("Max", justify="right")
    table.add_column("Desired", justify="right")
    table.add_column("Instances", justify="right")

    for asg in asgs:
        table.add_row(
            asg['AutoScalingGroupName'],
            str(asg['MinSize']),
            str(asg['MaxSize']),
            str(asg['DesiredCapacity']),
            str(len(asg.get('Instances', [])))
        )
    console.print(table)

# --- Helper Functions ---

def fetch_data(client_method, resource_key, message="Fetching data..."):
    """Generic fetcher with a spinner to show activity."""
    with console.status(f"[bold green]{message}[/bold green]"):
        try:
            # The client_method is a lambda that makes the actual boto3 call
            response = client_method()
            return response.get(resource_key, [])
        except ClientError as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
            return []

def get_instance_name(instance):
    """Helper to get the Name tag from an instance's tag set."""
    for tag in instance.get('Tags', []):
        if tag['Key'] == 'Name':
            return tag['Value']
    return 'N/A'

def select_instance(ec2_client, state='*'):
    """Display a list of instances for the user to select from."""
    # The state filter can be 'running', 'stopped', or '*' for all
    filters = []
    if state != '*':
        filters.append({'Name': 'instance-state-name', 'Values': [state]})
    
    # Use the fetch_data helper to show a spinner
    reservations = fetch_data(
        lambda: ec2_client.describe_instances(Filters=filters),
        'Reservations',
        f"Fetching {state if state != '*' else 'all'} instances..."
    )
    
    flat_instances = [inst for res in reservations for inst in res['Instances']]
    if not flat_instances:
        console.print(f"[yellow]No {state if state != '*' else ''} instances to select.[/yellow]")
        return None
        
    choices = [
        questionary.Choice(
            title=f"{inst['InstanceId']} ({get_instance_name(inst)}) - {inst['InstanceType']} - [{inst['State']['Name']}]",
            value=inst['InstanceId']
        ) for inst in flat_instances
    ]
    
    instance_id = questionary.select(
        "Select an instance:",
        choices=choices,
        use_indicator=True
    ).ask()
    return instance_id

def select_asg(asg_client):
    """Display a list of ASGs for the user to select from."""
    asgs = fetch_data(asg_client.describe_auto_scaling_groups, 'AutoScalingGroups', "Fetching Auto Scaling Groups...")
    if not asgs:
        console.print("[yellow]No Auto Scaling Groups to select.[/yellow]")
        return None
        
    choices = [
        questionary.Choice(
            title=f"{asg['AutoScalingGroupName']} (Running: {asg['DesiredCapacity']})",
            value=asg['AutoScalingGroupName']
        ) for asg in asgs
    ]
    
    asg_name = questionary.select(
        "Select an Auto Scaling Group:",
        choices=choices,
        use_indicator=True
    ).ask()
    return asg_name

# --- Core Functionality ---

def view_all_instances(ec2_client):
    """View all instances, regardless of state."""
    reservations = fetch_data(ec2_client.describe_instances, 'Reservations', "Fetching all instances...")
    instances = [inst for res in reservations for inst in res['Instances']]
    display_instances(instances)

def control_instance_state(ec2_client):
    """Start, Stop, Reboot, or Terminate an instance selected from a list."""
    instance_id = select_instance(ec2_client, state='*') # Select from any state
    if not instance_id:
        return

    action = questionary.select(
        f"Choose an action for {instance_id}:",
        choices=["start", "stop", "reboot", "terminate"]
    ).ask()

    if not action:
        return

    if action == "terminate":
        if not questionary.confirm(f"Are you sure you want to terminate {instance_id}?", default=False).ask():
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
                # Reboot doesn't have a waiter, but it's very fast.
                time.sleep(2)
            elif action == 'terminate':
                ec2_client.terminate_instances(InstanceIds=[instance_id])
                ec2_client.get_waiter('instance_terminated').wait(InstanceIds=[instance_id])
        console.print(f"✅ [bold green]Instance {instance_id} {action}ed successfully.[/bold green]")
    except ClientError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")


def manage_asg(asg_client):
    """Manage an Auto Scaling Group selected from a list."""
    asg_name = select_asg(asg_client)
    if not asg_name:
        return

    action = questionary.select(
        f"Choose an action for [bold cyan]{asg_name}[/bold cyan]:",
        choices=["View Details", "Set Desired Capacity", "Perform Rolling Refresh"]
    ).ask()

    if not action:
        return

    if action == "View Details":
        asgs = fetch_data(lambda: asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name]), 'AutoScalingGroups')
        display_asgs(asgs)
    
    elif action == "Set Desired Capacity":
        desired_str = questionary.text("Enter new desired capacity:").ask()
        try:
            desired = int(desired_str)
            with console.status(f"[bold yellow]Setting desired capacity to {desired}...[/bold yellow]"):
                asg_client.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=desired)
            console.print("✅ [bold green]Desired capacity updated.[/bold green]")
        except (ValueError, TypeError):
            console.print("[bold red]Invalid number.[/bold red]")
        except ClientError as e:
            console.print(f"[bold red]Error: {e}[/bold red]")

    elif action == "Perform Rolling Refresh":
        if not questionary.confirm(f"Start a rolling instance refresh for {asg_name}?", default=True).ask():
            console.print("[yellow]Refresh cancelled.[/yellow]")
            return
        try:
            with console.status(f"[bold yellow]Initiating instance refresh for {asg_name}...[/bold yellow]"):
                response = asg_client.start_instance_refresh(AutoScalingGroupName=asg_name, Strategy='Rolling')
                refresh_id = response['InstanceRefreshId']
            
            # Use Rich's Live feature to show the refresh status updating in real-time
            with Live(Spinner("bouncingBar", text=f"Monitoring refresh {refresh_id}..."), console=console, auto_refresh=False) as live:
                while True:
                    res = asg_client.describe_instance_refreshes(AutoScalingGroupName=asg_name, InstanceRefreshIds=[refresh_id])
                    status = res['InstanceRefreshes'][0]['Status']
                    live.update(Text(f"Refresh status for {asg_name}: [bold cyan]{status}[/bold cyan]"), refresh=True)
                    if status in ['Successful', 'Failed', 'Cancelled', 'Cancelling']:
                        break
                    time.sleep(15)
            console.print(f"✅ [bold green]Instance refresh completed with status: {status}[/bold green]")

        except ClientError as e:
            console.print(f"[bold red]Error: {e}[/bold red]")

# --- Main Loop ---

def main():
    """Main function to run the CLI tool."""
    check_python_version()
    
    console.print(Panel("[bold magenta]AWS EC2 & ASG Manager[/bold magenta] v2.0", expand=False, border_style="blue"))

    session = get_boto_session()
    if not session:
        sys.exit(1)

    region = select_aws_region(session)
    if not region:
        sys.exit(1)

    ec2 = session.client('ec2', region_name=region)
    asg = session.client('autoscaling', region_name=region)

    while True:
        action = questionary.select(
            "What would you like to do?",
            choices=[
                questionary.Separator("--- EC2 ---"),
                "View All Instances",
                "Start/Stop/Reboot/Terminate an Instance",
                questionary.Separator("--- Auto Scaling ---"),
                "View All Auto Scaling Groups",
                "Manage an Auto Scaling Group",
                questionary.Separator(),
                "Exit"
            ],
            use_indicator=True
        ).ask()

        if action == "Exit" or action is None:
            break
        
        elif action == "View All Instances":
            view_all_instances(ec2)
        
        elif action == "Start/Stop/Reboot/Terminate an Instance":
            control_instance_state(ec2)

        elif action == "View All Auto Scaling Groups":
            asgs = fetch_data(asg.describe_auto_scaling_groups, 'AutoScalingGroups', "Fetching ASGs...")
            display_asgs(asgs)

        elif action == "Manage an Auto Scaling Group":
            manage_asg(asg)
            
        console.print("\n" + "="*50 + "\n")

    console.print("[bold cyan]Goodbye![/bold cyan]")

if __name__ == "__main__":
    main()