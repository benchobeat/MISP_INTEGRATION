from setuptools import setup, find_packages

setup(
    name="misp-siem-integration",
    version="1.0.0",
    description="Automated IoC integration from SIEMs (QRadar, FortiSIEM, RSA NetWitness) to MISP",
    author="Security Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
    install_requires=[
        "pymisp>=2.4.187",
        "requests>=2.31.0",
        "PyYAML>=6.0.1",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "misp-integration=main:main",
        ],
    },
)
