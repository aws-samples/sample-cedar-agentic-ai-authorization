# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from setuptools import setup, find_packages

setup(
    name="cedar-deputy-guard",
    version="0.1.0",
    description="Least-privilege authorization for multi-agent AI with Cedar on AWS",
    python_requires=">=3.12",
    packages=find_packages(),
    install_requires=[
        "aws-cdk-lib>=2.150.0",
        "constructs>=10.0.0",
        "cedarpy>=4.0.0",
        "pydantic>=2.0.0",
        "jsonschema>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "hypothesis>=6.0.0",
            "moto>=5.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
)
