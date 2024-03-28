import boto3
import inquirer
from actions import *


def main():
    if not check_credentials():
        print("AWS credentials are not set. Please export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, then restart script")
        exit

    questions = [
        inquirer.List('action',
                      message="Select an action you would like to take...",
                      choices=['Create', 'List', 'Terminate', 'Stop', 'Start'],
                      ),
    ]
    try:
        answers = inquirer.prompt(questions)
        action = answers['action']

        if action == 'Create':
            create_instance()
        elif action == 'List':
            list_instances()
        elif action == 'Terminate':
            terminate_instance()
        elif action == 'Stop':
            stop_instance()
        elif action == 'Start':
            start_instance()
    except TypeError:
        print("Operation was cancelled or an invalid option was selected.")

if __name__ == "__main__":
    main()