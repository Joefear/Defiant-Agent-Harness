"""Temporary S1 negative control; remove before opening the release PR."""

import os


def test_windows_ci_failure_propagation():
    assert os.name != "nt", "S1 intentional Windows CI failure propagation probe"
