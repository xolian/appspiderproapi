#!/usr/bin/env python
# -*- coding: utf-8 -*-

def f(name):
    print("Hello {}".format(name))


def test_f(capfd):
    f("AppSpiderProApi")

    out, err = capfd.readouterr()
    assert out == "Hello AppSpiderProApi\n"