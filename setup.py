from setuptools import setup, find_packages

setup(
    name="kamui",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        # Add dependencies here
    ],
    entry_points={
        'console_scripts': [
            'kamui=kamui.cli:main',
        ],
    },
)