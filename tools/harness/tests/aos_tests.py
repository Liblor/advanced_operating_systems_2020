##########################################################################
# Copyright (c) 2009, ETH Zurich.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.
# If you do not find this file, copies can be found by writing to:
# ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
##########################################################################

import re, tests, barrelfish
from common import TestCommon
from results import PassFailResult

@tests.add_test
class AosTest(TestCommon):
    '''Base class for AOS tests'''
    name = "aos_test"

    def get_modules(self, build, machine):
        m = barrelfish.BootModules(self, prefix="armv8/sbin/")
        m.set_boot_driver("boot_armv8_generic")
        m.set_cpu_driver("cpu_imx8x")
        m.add_module("init", ["g:ira0=4096"])
        return m

    def get_finish_string(self):
        return "<grading> TEST"

    def process_data(self, testdir, rawiter):
        # the test passed iff the last line is the finish string
        lastline = ''
        for line in rawiter:
            if re.match("<grading>\s*TEST\s*ira\s*PASSED", line):
                return PassFailResult(True)
        return PassFailResult(False)
