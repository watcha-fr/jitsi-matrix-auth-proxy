# Jitsi Matrix Auth Proxy

**Proxy to convert on the fly Matrix custom JWT for Jitsi to standard JWT**

- install Pyenv (optional)

```sh
export PYENV_ROOT='/opt/pyenv'
curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | sudo -E bash
```

- install Python (optional)

```sh
export PYTHON_CONFIGURE_OPTS='--enable-optimizations --with-lto'
export PYTHON_CFLAGS='-march=native -mtune=native'
export PROFILE_TASK='-m test.regrtest --pgo -j0'
sudo -E $PYENV_ROOT/bin/pyenv install 3.10
```

- install Poetry

```sh
export POETRY_HOME='/opt/poetry'
curl -sSL https://install.python-poetry.org | sudo -E python3 -
```

- install app

```sh
cd /opt
sudo git clone https://github.com/watcha-fr/jitsi-matrix-auth-proxy
cd jitsi-matrix-auth-proxy
export POETRY_VIRTUALENVS_IN_PROJECT='true'

sudo -E $PYENV_ROOT/bin/pyenv local 3.10 # optional
sudo -E $POETRY_HOME/bin/poetry env use $($PYENV_ROOT/bin/pyenv which python3.10) # optional

sudo -E $POETRY_HOME/bin/poetry install
```
