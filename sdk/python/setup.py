"""
AuthMaster Python SDK - Package Setup
=====================================
"""
from setuptools import find_packages, setup

setup(
    name="authmaster",
    version="1.0.0",
    description="Official Python SDK for AuthMaster authentication and authorization API",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="AuthMaster Team",
    author_email="support@authmaster.example.com",
    url="https://github.com/authmaster/python-sdk",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "aiohttp>=3.8.0",
    ],
    extras_require={
        "async": ["aiohttp>=3.8.0"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP :: Session",
    ],
    keywords="authmaster authentication authorization IAM SDK",
)
