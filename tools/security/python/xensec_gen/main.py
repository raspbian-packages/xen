#!/usr/bin/python
#
# The Initial Developer of the Original Code is International
# Business Machines Corporation. Portions created by IBM
# Corporation are Copyright (C) 2005 International Business
# Machines Corporation. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""Xen security policy generation aid
"""

import os
import pwd
import grp
import sys
import getopt
import BaseHTTPServer
import CGIHTTPServer


gHttpPort = 7777
gHttpDir  = '/var/lib/xensec_gen'
gLogFile  = '/var/log/xen/xensec_gen.log'
gUser     = 'nobody'
gGroup    = 'nobody'

def usage( ):
    print >>sys.stderr, 'Usage:  ' + sys.argv[0] + ' [OPTIONS]'
    print >>sys.stderr, '  OPTIONS:'
    print >>sys.stderr, '  -p, --httpport'
    print >>sys.stderr, '     The port on which the http server is to listen'
    print >>sys.stderr, '     (default: ' + str( gHttpPort ) + ')'
    print >>sys.stderr, '  -d, --httpdir'
    print >>sys.stderr, '     The directory where the http server is to serve pages from'
    print >>sys.stderr, '     (default: ' + gHttpDir + ')'
    print >>sys.stderr, '  -l, --logfile'
    print >>sys.stderr, '     The file in which to log messages generated by this command'
    print >>sys.stderr, '     (default: ' + gLogFile + ')'
    print >>sys.stderr, '  -u, --user'
    print >>sys.stderr, '     The user under which this command is to run.  This parameter'
    print >>sys.stderr, '     is only used when invoked under the "root" user'
    print >>sys.stderr, '     (default: ' + gUser + ')'
    print >>sys.stderr, '  -g, --group'
    print >>sys.stderr, '     The group under which this command is to run.  This parameter'
    print >>sys.stderr, '     is only used when invoked under the "root" user'
    print >>sys.stderr, '     (default: ' + gGroup + ')'
    print >>sys.stderr, '  -f'
    print >>sys.stderr, '     Run the command in the foreground.  The logfile option will be'
    print >>sys.stderr, '     ignored and all output will be directed to stdout and stderr.'
    print >>sys.stderr, '  -h, --help'
    print >>sys.stderr, '     Display the command usage information'

def runServer( aServerPort,
               aServerClass  = BaseHTTPServer.HTTPServer,
               aHandlerClass = CGIHTTPServer.CGIHTTPRequestHandler ):
    serverAddress = ( '', aServerPort )
    httpd = aServerClass( serverAddress, aHandlerClass )
    httpd.serve_forever( )

def daemonize( aHttpDir, aLogFile, aUser, aGroup, aFork = 'true' ):
    # Do some pre-daemon activities
    os.umask( 027 )
    if os.getuid( ) == 0:
        # If we are running as root, we will change that
        uid = pwd.getpwnam( aUser )[2]
        gid = grp.getgrnam( aGroup )[2]

        if aFork == 'true':
            # Change the owner of the log file to the user/group
            #   under which the daemon is to run
            flog = open( aLogFile, 'a' )
            flog.close( )
            os.chown( aLogFile, uid, gid )

        # Change the uid/gid of the process
        os.setgid( gid )
        os.setuid( uid )

    # Change to the HTTP directory
    os.chdir( aHttpDir )

    if aFork == 'true':
        # Do first fork
        try:
            pid = os.fork( )
            if pid:
            # Parent process
                return pid

        except OSError, e:
            raise Exception, e

        # First child process, create a new session
        os.setsid( )

        # Do second fork
        try:
            pid = os.fork( )
            if pid:
                # Parent process
                os._exit( 0 )

        except OSError, e:
            raise Exception, e

        # Reset stdin/stdout/stderr
        fin  = open( '/dev/null',  'r' )
        flog = open( aLogFile, 'a' )
        os.dup2( fin.fileno( ),  sys.stdin.fileno( ) )
        os.dup2( flog.fileno( ), sys.stdout.fileno( ) )
        os.dup2( flog.fileno( ), sys.stderr.fileno( ) )

def main( ):
    httpPort = gHttpPort
    httpDir  = gHttpDir
    logFile  = gLogFile
    user     = gUser
    group    = gGroup
    doFork   = 'true'

    shortOpts = 'd:p:l:u:g:fh'
    longOpts  = [ 'httpdir=', 'httpport=', 'logfile=', 'user=', 'group=', 'help' ]
    try:
        opts, args = getopt.getopt( sys.argv[1:], shortOpts, longOpts )

    except getopt.GetoptError, e:
        print >>sys.stderr, e
        usage( )
        sys.exit( )

    if len( args ) != 0:
        print >>sys.stderr, 'Error: command arguments are not supported'
        usage( )
        sys.exit( )

    for opt, opt_value in opts:
        if opt in ( '-h', '--help' ):
            usage( )
            sys.exit( )

        if opt in ( '-d', '--httpdir' ):
            httpDir = opt_value

        if opt in ( '-p', '--httpport' ):
            try:
                httpPort = int( opt_value )
            except:
                print >>sys.stderr, 'Error: HTTP port is not valid'
                usage( )
                sys.exit( )

        if opt in ( '-l', '--logfile' ):
            logFile = opt_value

        if opt in ( '-u', '--user' ):
            user = opt_value

        if opt in ( '-g', '--group' ):
            group = opt_value

        if opt in ( '-f' ):
            doFork = 'false'

    pid = daemonize( httpDir, logFile, user, group, doFork )
    if pid > 0:
        sys.exit( )

    runServer( httpPort )

if __name__ == '__main__':
    main( )
