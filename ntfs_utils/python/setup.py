"""
Module: ntfs_utils.python.setup
Purpose: Package the Python NTFS utility bindings.
Created: 2026-10-01
Architecture: Python installations load the ctypes adapter backed by libntfs_utils.
"""

from setuptools import Distribution, setup
from wheel.bdist_wheel import bdist_wheel


class NativeDistribution(Distribution):
    def has_ext_modules(self):
        return True


class PlatformWheel(bdist_wheel):
    def get_tag(self):
        _, _, platform = super().get_tag()
        return "py3", "none", platform


setup(distclass=NativeDistribution, cmdclass={"bdist_wheel": PlatformWheel})
