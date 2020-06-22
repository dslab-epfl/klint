#!/bin/sh
# tested on Ubuntu 18.04

# GCC 9 (optional; TODO move to normal gcc)
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install gcc-9

# Virtual env for angr
sudo apt install python3-pip
pip3 install virtualenv
pip3 install virtualenvwrapper
VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3 . ~/.local/bin/virtualenvwrapper.sh
VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3 VIRTUALENVWRAPPER_VIRTUALENV=~/.local/bin/virtualenv mkvirtualenv angr
pip install -r requirements.txt

# note: make sure you don't have some random z3 in your path, like one from Vigor, or it will fail
