# tested on Ubuntu 18.04 and 20.04
# THIS SCRIPT SHOULD BE SOURCED NOT RAN

if [ ! -d "$HOME/.virtualenvs/angr" ]; then
  # Virtual env for angr using python3
  sudo apt install -y python3 python3-pip
  python3 -m pip install virtualenv virtualenvwrapper
  mkdir -p "$HOME/.virtualenvs"
fi

export WORKON_HOME="$HOME/.virtualenvs"
export VIRTUALENVWRAPPER_PYTHON="$(which python3)"
export VIRTUALENVWRAPPER_VIRTUALENV="$HOME/.local/bin/virtualenv"
. "$HOME/.local/bin/virtualenvwrapper.sh"

if [ -d "$HOME/.virtualenvs/angr" ]; then
  workon angr
else
  mkvirtualenv angr
  pip install -r requirements.txt
fi
