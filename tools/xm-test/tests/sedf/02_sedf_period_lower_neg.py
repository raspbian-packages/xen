#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>
# Author: Ryan Harper <ryanh@us.ibm.com>
#
# Test if sched-sedf <dom> -p <period> handles lower bound 

from XmTestLib import *

def get_sedf_params(domain):
    status, output = traceCommand("xm sched-sedf %s" %(domain.getName()))
    return (status, output.split('\n')[1].split())


domain = XmTestDomain(extraConfig = {"sched":"sedf"})

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# pick bogus period
period = "-1"

# NB: setting period requires non-zero slice 
# scale current period in half
slice  = "5"

opts = "%s -p %s -s %s" %(domain.getName(), period, slice)
(status, output) = traceCommand("xm sched-sedf %s" %(opts))

# we should see this output from xm 
eyecatcher = "Failed to set sedf parameters"

# check for failure
if output.find(eyecatcher) >= 0:
    FAIL("sched-sedf let me set bogus period (%s)" %(period))

# Stop the domain (nice shutdown)
domain.stop()
