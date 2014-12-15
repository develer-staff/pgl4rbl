#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Copyright (c) 2010-2014 Develer S.r.L
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
#

import argparse
import os
import os.path
import re
import signal
import socket
import stat
import sys
import syslog
import time


RE_IP = re.compile(r"\[(\d+)\.(\d+)\.(\d+)\.(\d+)\]")


def main():
    # Allow SIGPIPE to kill our program
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    args = parse_args()

    load_config_file(args.config)

    # Configure syslog support
    syslog.openlog("pgl4rbl", syslog.LOG_PID, getattr(syslog, SYSLOG_FACILITY))

    sanity_check()

    if args.clean:
        os.system("find '%s' -type f -mmin +%d -delete" %
                  (GREYLIST_DB, MAX_GREYLIST_TIME))
    else:
        process_one()


def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", "--config", type=str, default="/etc/pgl4rbl.conf", help="path to the configuration file")
    arg_parser.add_argument("-d", "--clean", action="store_true", help="clean the greylist db")

    return arg_parser.parse_args()


def load_config_file(config):
    try:
        execfile(config, globals())
    except Exception, e:
        # We can't use die() here
        syslog.openlog("pgl4rbl", syslog.LOG_PID)
        error("Error parsing configuration: %s" % e)
        sys.exit(2)


def sanity_check():
    # Check that we can access the DB directory
    if not os.path.isdir(GREYLIST_DB):
        die("DB directory does not exist: " + GREYLIST_DB)

    # Check that permissions allow access to the DB directory
    try:
        test_fn = ".test.%s" % os.getpid()

        add_db(test_fn)
        check_db(test_fn)
        clean_db(test_fn)
    except (OSError, IOError):
        die("Wrong permissions for DB directory: " + GREYLIST_DB)


def log(s):
    syslog.syslog(syslog.LOG_INFO, s)


def die(s):
    error(s)
    sys.exit(2)


def error(s):
    syslog.syslog(syslog.LOG_ERR, s)


def process_one():
    d = {}

    while 1:
        L = sys.stdin.readline()
        L = L.strip()

        if not L:
            break
        try:
            k, v = L.split('=', 1)
        except ValueError:
            die("invalid input line: %r" % L)

        d[k.strip()] = v.strip()

    try:
        ip = d['client_address']
        helo = d['helo_name']
    except KeyError:
        die("client_address/helo_name field not found in input data, aborting")

    if not ip:
        die("client_address empty in input data, aborting")

    log("Processing client: S:%s H:%s" % (ip, helo))

    action = process_ip(ip, helo)

    log("Action for IP %s: %s" % (ip, action))
    sys.stdout.write('action=%s\n\n' % action)


def process_ip(ip, helo):
    if not check_rbls(ip) and not check_badhelo(helo):
        return "ok You are cleared to land"

    if STRIP_LAST_BYTE:
      ip1 = ip
      ip = ".".join(ip.split('.')[0:3] + ['0'])
      log("%s stripped to %s" % (ip1, ip))

    t = check_db(ip)

    if t < 0:
        log("%s not in greylist DB, adding it" % ip)

        add_db(ip)

        return "defer Are you a spammer? If not, just retry!"
    elif t < MIN_GREYLIST_TIME * 60:
        log("%s too young in greylist DB" % ip)

        return "defer Are you a spammer? If not, just retry!"
    else:
        log("%s already present greylist DB" % ip)

        return "ok Greylisting OK"


def check_rbls(ip):
    """True if the IP is listed in RBLs"""
    return any(query_rbl(ip, r) for r in RBLS)


def query_rbl(ip, rbl_root):
    addr_parts = list(reversed(ip.split('.'))) + [rbl_root]
    check_name = ".".join(addr_parts)

    try:
        ip = socket.gethostbyname(check_name)
    except socket.error:
        return None
    else:
        log("Found in blacklist %s (resolved to %s)" % (rbl_root, ip))

        return ip


def check_badhelo(helo):
    """True if the HELO string violates the RFC"""
    if not CHECK_BAD_HELO:
        return False

    if helo.startswith('['):
        m = RE_IP.match(helo)

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
    fn = os.path.join(GREYLIST_DB, ip)

    try:
        s = os.stat(fn)
    except OSError:
        return -1

    return time.time() - s.st_mtime


def add_db(ip):
    """Add the specified IP to the GL database"""
    open(os.path.join(GREYLIST_DB, ip), "w").close()


def clean_db(ip):
    os.remove(os.path.join(GREYLIST_DB, ip))


if __name__ == "__main__":
    main()
