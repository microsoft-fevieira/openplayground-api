import setuptools
from pathlib import Path

base_path = Path(__file__).parent
long_description = (base_path / "README.md").read_text()

setuptools.setup(
  name="openplayground",
  version="0.5",
  author="microsoft-fevieira",
  license="GPLv3",
  description=" A reverse engineered API wrapper for OpenPlayground (nat.dev)",
  long_description=long_description,
  long_description_content_type="text/markdown",
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: GNU General Public License (GPL)",
    "Operating System :: OS Independent"
  ],
  python_requires=">=3.6",
  packages=setuptools.find_packages(include=['openplayground']),
  install_requires=[
    "pycryptodome"
  ],
  url="https://github.com/microsoft-fevieira/openplayground-api"
)