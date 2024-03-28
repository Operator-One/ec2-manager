from setuptools import setup, find_packages

setup(
    name='Ec2Manager',
    version='0.1.0',
    author='Operator-One',
    author_email='cullen.guimond@guinet.us',
    description='Allows you to manage and create resources in AWS EC2',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Operator-One/Ec2Manager',
    packages=find_packages(),
    install_requires=[
        'boto3>=1.17',
        'inquirer>=2.7.0',
    ],
entry_points={
    'console_scripts': [
        'ec2-manager=ec2_manager.main:main',
    ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.10',
        'Operating System :: OS Independent',
    ],
)