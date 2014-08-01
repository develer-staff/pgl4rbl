#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Copyright (c) 2014 Develer S.r.L
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

import StringIO
import sys

import pytest

import pgl4rbl

#
# Ugly hack to "configure" pgl4rbl
#

execfile("pgl4rbl.conf")
setattr(pgl4rbl, "CHECK_BAD_HELO", CHECK_BAD_HELO)
setattr(pgl4rbl, "MAX_GREYLIST_TIME", MAX_GREYLIST_TIME)
setattr(pgl4rbl, "MIN_GREYLIST_TIME", MIN_GREYLIST_TIME)
setattr(pgl4rbl, "RBLS", RBLS)

#
# Tests
#

EXPECT_OK = "action=ok You are cleared to land\n\n"
EXPECT_FAIL = "action=defer Are you a spammer? If not, just retry!\n\n"


@pytest.mark.parametrize("triplet", [
    ( "89.97.188.34", "trinity.develer.com", EXPECT_OK),
    ( "8.8.8.8", "dns1.google.com", EXPECT_OK),
    ( "8.8.8.8", "google", EXPECT_FAIL),
    ( "89.97.188.34", "[ciao]", EXPECT_FAIL),
    ( "89.97.188.34", "[255.256.1024.12]", EXPECT_FAIL),
])
def test_helo(capsys, monkeypatch, tmpdir, triplet):
    # Prepare
    setattr(pgl4rbl, "GREYLIST_DB", str(tmpdir))

    client_address, helo_name, expected = triplet
    mock_data = "client_address=%s\nhelo_name=%s" % (client_address, helo_name)

    monkeypatch.setattr('sys.stdin', StringIO.StringIO(mock_data))

    # Test
    pgl4rbl.process_one()

    # Assert
    assert capsys.readouterr()[0] == expected
