from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="detrisk",
    version="2.0.0",
    author="Harsh Shrivastava",
    author_email="harsh.shrivastava@outlook.com",
    description="AI-powered risk assessment engine for threats and vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/harsh02/Determinstic-risk-assessment",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.10",
    install_requires=[
        "pyyaml>=6.0",
        "spacy>=3.7.0",
        "sentence-transformers>=2.2.0",
        "numpy>=1.24.0",
        "requests>=2.31.0",
        "tqdm>=4.65.0",
    ],
    entry_points={
        "console_scripts": [
            "detrisk=src.utils.risk_chat:main",
        ],
    },
)
