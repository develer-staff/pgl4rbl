#!/usr/bin/env python

# RBL to check
RBLS = [
    "xbl.spamhaus.org",
    "pbl.spamhaus.org",
    "dnsbl.njabl.org",
    "dnsbl.sorbs.net",
]

# Directory where to store the greylist DB
GREYLIST_DB = '/tmp/gl4rbl'

# Minimum time (in seconds) before an entry in the DB is allowed
# to resend a message
MIN_GREYLIST_TIME = 5*60

# Activate/disactivate logging (through syslog)
LOGGING = True

# Facility to send logging to
SYSLOG_FACILITY = 'LOG_MAIL'



########################################################################################
# Program begins here
########################################################################################

import sys
import socket
import syslog
import signal
import os
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

def process_ip(ip):
    if not check_rbls(ip):
        return "permit Not in RBL"
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
        return "permit Greylisting OK"


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
    except KeyError:
        error("client_address field not found in input data, aborting")
        sys.exit(2)

    if not ip:
        error("client_address empty in input data, aborting")
        sys.exit(2)

    log("Processing client IP: %s" % ip)
    action = process_ip(ip)
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
    except OSError:
        error("Wrong permissions for DB directory: " + GREYLIST_DB)
        sys.exit(2)

    while 1:
        process_one()
