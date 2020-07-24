# tested on Ubuntu 18.04
# THIS SCRIPT SHOULD BE SOURCED NOT RAN

# Virtual env for angr using pypy for python3
sudo snap install --classic pypy3
pypy3 -m ensurepip
pypy3 -m pip install virtualenv virtualenvwrapper
mkdir "$HOME/.virtualenvs"
export WORKON_HOME="$HOME/.virtualenvs"
export VIRTUALENVWRAPPER_PYTHON="$(which pypy3)"
export VIRTUALENVWRAPPER_VIRTUALENV="$HOME/.local/bin/virtualenv"
. "$HOME/.local/bin/virtualenvwrapper.sh"
mkvirtualenv angr
pip install -r requirements.txt

