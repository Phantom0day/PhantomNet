from setuptools import setup, find_packages
from src.common.constants import APP_VERSION

setup(
    name="PhantomSocket",
    version=APP_VERSION,
    packages=find_packages(),
    description="A modular SOCKS5 proxy implementation",
    author="Phantom0day",
    author_email="phantomnet001@gmail.com",
    python_requires=">=3.6",
    install_requires=[
        "pyyaml",  # For YAML config support
        "dnspython",  # For improved DNS resolution
    ],
)
