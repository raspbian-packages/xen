#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; If not, see <http://www.gnu.org/licenses/>.
#============================================================================
# Copyright (C) 2009 flonatel GmbH & Co. KG
#============================================================================

import unittest

suite = unittest.TestSuite([])

if __name__ == "__main__":
    testresult = unittest.TextTestRunner(verbosity=3).run(suite)

