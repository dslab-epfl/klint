# tested on Ubuntu 18.04
# THIS SCRIPT SHOULD BE SOURCED NOT RAN

if [ ! -d "$HOME/.virtualenvs/angr" ]; then
  # Virtual env for angr using python3
  python3 -m ensurepip --upgrade
  python3 -m pip install virtualenv virtualenvwrapper
  mkdir -p "$HOME/.virtualenvs"
fi

export WORKON_HOME="$HOME/.virtualenvs"
export VIRTUALENVWRAPPER_PYTHON="$(which pypy3)"
export VIRTUALENVWRAPPER_VIRTUALENV="$HOME/.local/bin/virtualenv"
. "$HOME/.local/bin/virtualenvwrapper.sh"

if [ -d "$HOME/.virtualenvs/angr" ]; then
  workon angr
else
  mkvirtualenv angr
  pip install -r requirements.txt
fi
