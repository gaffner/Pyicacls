import setuptools

with open( "README.md", "r", encoding="utf-8" ) as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyicacls",
    version="1.1.2",
    author="Gaffner",
    author_email="gefen102@gmail.com",
    url="https://github.com/gaffner/Pyicacls",
    description="A package to show and set windows files permissions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=["pyicacls", "pyicacls.examples"],
    install_requires=[
        'impacket~=0.9.23'
    ],
)
