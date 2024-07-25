import boto3

def fetch_security_groups():
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()
    security_groups = [(sg['GroupId'], sg['GroupName']) for sg in response['SecurityGroups']]
    return security_groups

def fetch_vpcs():
    ec2 = boto3.client('ec2')
    response = ec2.describe_vpcs()
    vpcs = [(vpc['VpcId'], vpc['VpcId']) for vpc in response['Vpcs']]
    return vpcs

def fetch_subnets(vpc_id):
    ec2 = boto3.client('ec2')
    response = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    subnets = [(subnet['SubnetId'], subnet['SubnetId']) for subnet in response['Subnets']]
    return subnets