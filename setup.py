from setuptools import setup, find_packages

setup(
    name="PhantomSocket",
    version="0.1.1",
    packages=find_packages(),
    description="A modular SOCKS5 proxy implementation",
    author="Phantom0day",
    author_email="phantomnet001@gmail.com",
    python_requires=">=3.6",
    install_requires=[
        "pyyaml",    # For YAML config support
        "dnspython", # For improved DNS resolution  
    ],
)
