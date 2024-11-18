from setuptools import setup, find_packages

setup(
    name="seyzo_tool",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",  # Add any other dependencies here
    ],
    entry_points={
        "console_scripts": [
            "seyzo-tool = main:main",  # Make the tool runnable from the command line
        ],
    },
)
