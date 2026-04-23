from setuptools import find_packages, setup


setup(
    name="aegis-tunnel-x",
    version="0.1.0",
    description="Post-quantum encrypted UDP tunnel with morphic traffic shaping.",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "cryptography>=42.0",
        "liboqs-python>=0.10.0",
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-asyncio>=0.23",
        ],
    },
    entry_points={
        "console_scripts": [
            "aegis=aegis.cli:main",
        ],
    },
)
