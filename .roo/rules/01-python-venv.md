# 01-python-venv

When executing python, always use a virtual environment in `.venv`. 
If it does not exist, create it and install all requirements.
Do not try to activate it, but use it explicitely by calling `.venv/bin/python`
Do not use `source` for activating the environment, because you are using /bin/sh and not bash. Use direct calls instead.