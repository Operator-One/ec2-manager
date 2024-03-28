import inquirer
import sys
from .actions import create_instance, list_instances, terminate_instance, stop_instance, start_instance, check_credentials


def main():
    if not check_credentials():
        print("AWS credentials are not set. Please export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, then restart script")
        sys.exit(1)

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
            print('=======================================================================')
            list_instances()
            print('=======================================================================')
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