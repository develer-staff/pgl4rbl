#!/usr/bin/env python
# Copyright (c) 2010, Develer Srl
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Directory where to store the greylist DB
GREYLIST_DB = "/tmp/pgl4rbl"

# Minimum time (in seconds) before an entry in the DB is allowed
# to resend a message
MIN_GREYLIST_TIME = 5*60

# Activate/disactivate logging (through syslog)
LOGGING = True

# Facility to send logging to
SYSLOG_FACILITY = 'LOG_MAIL'

# RBLs to check
RBLS = [
    "xbl.spamhaus.org",
    "pbl.spamhaus.org",
    "dnsbl.njabl.org",
    "dnsbl.sorbs.net",
]

# HELO FQDN enforcement checks
CHECK_BAD_HELO = True

########################################################################################
# Program begins here
########################################################################################

import sys
import socket
import syslog
import signal
import os
import re
import stat
import time

def log(s):
    syslog.syslog(syslog.LOG_INFO, s)

def error(s):
    syslog.syslog(syslog.LOG_ERR, s)

def query_rbl(ip, rbl_root):
    addr_parts = list(reversed(ip.split('.'))) + [rbl_root]
    check_name = ".".join(addr_parts)
    log("Querying: %s" % check_name)
    try:
        return socket.gethostbyname(check_name)
    except socket.error:
        return None

def check_rbls(ip):
    """True if the IP is listed in RBLs"""
    return any(query_rbl(ip, r) for r in RBLS)

rxIP = re.compile(r"\[(\d+)\.(\d+)\.(\d+)\.(\d+)\]")
def check_badhelo(helo):
    """True if the HELO string violates the RFC"""
    if not CHECK_BAD_HELO:
        return False

    if helo.startswith('['):
        m = rxIP.match(helo)
        if m is not None:
            octs = map(int, (m.group(1), m.group(2), m.group(3), m.group(4)))
            if max(octs) < 256:
                return False
        log("HELO string begins with '[' but does not contain a valid IPv4 address")
        return True

    if '.' not in helo:
        log("HELO string does not look like a FQDN")
        return True

    return False

def check_db(ip):
    """
    Check if ip is in the GL database.
    Returns -1 if not present, or the number of seconds
    since it has been added.
    """
    fn = GREYLIST_DB + '/' + ip
    try:
        s = os.stat(fn)
    except OSError:
        return -1
    return time.time() - s.st_mtime

def add_db(ip):
    """Add the specified IP to the GL database"""
    open(GREYLIST_DB + '/' + ip, "w").close()

def clean_db(ip):
    os.remove(GREYLIST_DB + '/' + ip)

def process_ip(ip, helo):
    if not check_rbls(ip) and not check_badhelo(helo):
        return "ok You are cleared to land"

    t = check_db(ip)
    if t < 0:
        log("%s not in greylist DB, adding it" % ip)
        add_db(ip)
        return "defer Are you a spammer? If not, just retry!"
    elif t < MIN_GREYLIST_TIME:
        log("%s too young in greylist DB" % ip)
        return "defer Are you a spammer? If not, just retry!"
    else:
        log("%s already present greylist DB" % ip)
        return "ok Greylisting OK"


def process_one():
    d = {}
    while 1:
        L = sys.stdin.readline()
        L = L.strip()
        if not L: break
        try:
            k,v = L.split('=',1)
        except ValueError:
            error("invalid input line: %r" % L)
            sys.exit(2)
        d[k.strip()] = v.strip()

    try:
        ip = d['client_address']
        helo = d['helo_name']
    except KeyError:
        error("client_address/helo_name field not found in input data, aborting")
        sys.exit(2)

    if not ip:
        error("client_address empty in input data, aborting")
        sys.exit(2)

    log("Processing client: S:%s H:%s" % (ip, helo))
    action = process_ip(ip, helo)

    log("Action for IP %s: %s" % (ip, action))
    sys.stdout.write('action=%s\n\n' % action)

if __name__ == "__main__":

    # Allow SIGPIPE to kill our program
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    # Configure syslog support
    syslog.openlog("gl4rbl", syslog.LOG_PID, getattr(syslog, SYSLOG_FACILITY))

    # Check that we can access the DB directory
    if not os.path.isdir(GREYLIST_DB):
        error("DB directory does not exist: " + GREYLIST_DB)
        sys.exit(2)

    # Check that permissions allow access to the DB directory
    try:
        test_fn = ".test.%s" % os.getpid()
        add_db(test_fn)
        check_db(test_fn)
        clean_db(test_fn)
    except (OSError,IOError):
        error("Wrong permissions for DB directory: " + GREYLIST_DB)
        sys.exit(2)

    while 1:
        process_one()

