import boto3
import inquirer
import os
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from .api import fetch_security_groups, fetch_subnets, fetch_vpcs

def create_instance():
    try:
        # Fetch options for security groups, VPCs
        security_groups = fetch_security_groups()
        vpcs = fetch_vpcs()

        questions = [
            inquirer.List('security_group',
                          message="Choose a security group",
                          choices=security_groups,
                          ),
            inquirer.List('vpc',
                          message="Choose a VPC",
                          choices=vpcs,
                          ),
        ]
        answers = inquirer.prompt(questions)

        # Fetch subnets for the selected VPC
        subnets = fetch_subnets(answers['vpc'])
        subnet_question = [
            inquirer.List('subnet',
                          message="Choose a subnet",
                          choices=subnets,
                          )
        ]
        subnet_answer = inquirer.prompt(subnet_question)

        ec2 = boto3.resource('ec2')
        instance = ec2.create_instances(
            ImageId='ami-0abcdef1234567890',  # Example AMI ID
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',
            SecurityGroupIds=[answers['security_group']],
            SubnetId=subnet_answer['subnet'],
        )
        print("Instance created:", instance[0].id)
    except NoCredentialsError:
        print("Credentials not available.")
    except ClientError as e:
        print(f"Failed to create instance: {e}")
    except EndpointConnectionError:
        print("Could not connect to the endpoint. Please check your network.")

def list_instances():
    try:
        ec2 = boto3.client('ec2')
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                # Instance ID
                instance_id = instance['InstanceId']

                # Private IP address
                private_ip = instance.get('PrivateIpAddress', 'N/A')

                # Instance State
                instance_state = instance['State']['Name']

                # Name tag - Not all instances have a 'Name' tag, so provide a default value
                name = 'No Name'
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                
                print(f"Instance ID: {instance_id}, Name: {name}, Private IP: {private_ip}, State: {instance_state}")
    except NoCredentialsError:
        print("Credentials not available.")
    except ClientError as e:
        print(f"Failed to list instances: {e}")
    except EndpointConnectionError:
        print("Could not connect to the endpoint. Please check your network.")

def terminate_instance():
    try:
        ec2 = boto3.client('ec2')
        instance_id = input("Enter the instance ID to terminate: ")
        ec2.terminate_instances(InstanceIds=[instance_id])
        print("Instance terminated:", instance_id)
    except NoCredentialsError:
        print("Credentials not available.")
    except ClientError as e:
        print(f"Failed to terminate instance: {e}")
    except EndpointConnectionError:
        print("Could not connect to the endpoint. Please check your network.")

def stop_instance():
    try:
        ec2 = boto3.client('ec2')
        instance_id = input("Enter the instance ID to stop: ")
        ec2.stop_instances(InstanceIds=[instance_id])
        print("Instance stopped:", instance_id)
    except NoCredentialsError:
        print("Credentials not available.")
    except ClientError as e:
        print(f"Failed to stop instance: {e}")
    except EndpointConnectionError:
        print("Could not connect to the endpoint. Please check your network.")

def start_instance():
    try:
        ec2 = boto3.client('ec2')
        instance_id = input("Enter the instance ID to start: ")
        ec2.start_instances(InstanceIds=[instance_id])
        print("Instance started:", instance_id)
    except NoCredentialsError:
        print("Credentials not available.")
    except ClientError as e:
        print(f"Failed to start instance: {e}")
    except EndpointConnectionError:
        print("Could not connect to the endpoint. Please check your network.")
        
def check_credentials():
    """Check if AWS credentials are exported in the environment."""
    access_key = os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    if not access_key or not secret_key:
        return False
    return True