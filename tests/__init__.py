# Makes tests/ a regular package. Without it, the stray top-level "tests"
# package that textfsm (a netmiko dependency) installs into site-packages
# shadows this folder and every "from tests.xxx import ..." fails in CI.
