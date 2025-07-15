from setuptools import setup, find_packages

setup(
    name="ec2-manager",
    version="1.12.0",
    description="A CLI tool to manage and view AWS EC2 instances and Auto Scaling Groups",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Cullen Guimond",
    author_email="cullen.guimond@proton.me",
    url="https://github.com/cullenwerks/ec2_manager",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.34.0",
        "prompt_toolkit>=3.0.0",
        "setuptools>=65.5.0",
        "inquirerpy>=0.3.4",
    ],
    entry_points={
        "console_scripts": [
            "ec2-manager=ec2_manager.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)