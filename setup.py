from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="port2ctree",
    version="1.0",
    packages=["port2ctree"],
    entry_points={
        "console_scripts": [
            "port2ctree=port2ctree:main",
        ],
    },

    author="kyssK00l",
    description="Convert Nmap or Rustscan results into a Cherrytree (.ctd) file.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",

    ],
)

