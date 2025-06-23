from setuptools import setup

setup(
    name='port2ctree',
    version='1.0',
    py_modules=['port2ctree'],
    entry_points={
        'console_scripts': [
            'port2ctree=port2ctree:main',
        ],
    },
    author='kyssK00l',
    description='Convertit un scan Nmap/Rustscan en .ctd pour Cherrytree',
)

