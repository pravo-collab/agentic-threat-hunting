"""Setup script for the Threat Hunting and Incident Response System."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="threat-hunting-ir",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Agentic MultiStage Threat Hunting and Incident Response System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/threat-hunting-ir",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "threat-hunt=src.main:main",
        ],
    },
)
