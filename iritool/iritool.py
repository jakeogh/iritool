#!/usr/bin/env python3
# -*- coding: utf8 -*-

# flake8: noqa           # flake8 has no per file settings :(
# pylint: disable=C0111  # docstrings are always outdated and wrong
# pylint: disable=W0511  # todo is encouraged
# pylint: disable=C0301  # line too long
# pylint: disable=R0902  # too many instance attributes
# pylint: disable=C0302  # too many lines in module
# pylint: disable=C0103  # single letter var names, func name too descriptive
# pylint: disable=R0911  # too many return statements
# pylint: disable=R0912  # too many branches
# pylint: disable=R0915  # too many statements
# pylint: disable=R0913  # too many arguments
# pylint: disable=R1702  # too many nested blocks
# pylint: disable=R0914  # too many local variables
# pylint: disable=R0903  # too few public methods
# pylint: disable=E1101  # no member for base
# pylint: disable=W0201  # attribute defined outside __init__
# pylint: disable=R0916  # Too many boolean expressions in if statement
# pylint: disable=C0305  # Trailing newlines editor should fix automatically, pointless warning

import os
import sys
import time
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click

signal(SIGPIPE,SIG_DFL)
from pathlib import Path
from typing import ByteString
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple
from urllib.parse import urldefrag
from urllib.parse import urlparse
from urllib.parse import urlsplit

from asserttool import nevd
from enumerate_input import enumerate_input
from iridb.tld import tldextract
from reify import reify
from retry_on_exception import retry_on_exception
from uhashfs.utils import verify
from urltool import extract_psl_domain


def eprint(*args, **kwargs):
    if 'file' in kwargs.keys():
        kwargs.pop('file')
    print(*args, file=sys.stderr, **kwargs)


try:
    from icecream import ic  # https://github.com/gruns/icecream
    from icecream import icr  # https://github.com/jakeogh/icecream
except ImportError:
    ic = eprint
    icr = eprint


def get_timestamp():
    timestamp = str("%.22f" % time.time())
    return timestamp


def validate_slice(slice_syntax):
    assert isinstance(slice_syntax, str)
    for c in slice_syntax:
        if c not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '[', ']', ':']:
            raise ValueError(slice_syntax)
    return slice_syntax


class IriBase():

    def __str__(self):
        return self.iri

    def __contains__(self, match):
        if match in str(self.iri):
            return True
        return False

    def __len__(self):
        return len(str(self.iri))

    def __getitem__(self, key):
        return self.iri.__getitem__(key)

    def startswith(self, match):
        if self.iri.startswith(match):
            return True
        return False

    def endswith(self, match):
        if self.iri.endswith(match):
            return True
        return False

    def split(self, match):
        return self.iri.split(match)

    def replace(self, match, replacement):
        return self.iri.replace(match, replacement)

    def lower(self):
        return self.iri.lower()

    @reify
    def domain_tld(self):
        tld = tldextract(self.iri).suffix
        return tld

    @reify
    def domain_psl(self):
        domain_psl = extract_psl_domain(self.domain)
        return domain_psl

    @reify
    def domain_sld(self):
        tld = tldextract(self.iri).domain
        return tld

    def is_internal(self, root_iri):
        #assert isinstance(root_iri, Iri)  # nawh, it could be a UrlparseResult
        if self.domain_psl == root_iri.domain_psl:
            return True
        return False


class UrlsplitResult(IriBase):
    def __init__(self,
                 iri: str,
                 verbose: bool,
                 debug: bool,
                 link_text: str = None,):
        try:
            verify(isinstance(iri, str))
        except ValueError:
            msg = "iri: {} must be type str, not type {}".format(iri, type(iri))
            raise ValueError(msg)
        self.verbose = verbose
        self.debug = debug

        self.urlsplit = urlsplit(iri)
        self.iri, _ = urldefrag(iri)
        self.link_text = link_text
        self.geturl = self.urlsplit.geturl()
        self.scheme = self.urlsplit.scheme
        self.netloc = self.urlsplit.netloc
        self.domain = self.urlsplit.netloc  # alias for netloc
        self.path = self.urlsplit.path
        self.query = self.urlsplit.query
        self.fragment = self.urlsplit.fragment
        self.username = self.urlsplit.username
        self.password = self.urlsplit.password
        self.hostname = self.urlsplit.hostname
        try:
            self.port = self.urlsplit.port
        except ValueError as e:  # if there was an invalid port
            self.port = None
        #self.params = self.urlsplit.params  # urlsplit does not split out params, they are associated with each path element
        #verify(self.scheme, msg="scheme:// is required")

    def __repr__(self):
        return '<iridb.atoms.UrlsplitResult ' + str(self) + '>'


class UrlparseResult(IriBase):
    def __init__(self, iri: str,
                 verbose: bool,
                 debug: bool,
                 link_text: str = None,):
        try:
            verify(isinstance(iri, str))
        except ValueError:
            msg = "iri: {} must be type str, not type {}".format(iri, type(iri))
            raise ValueError(msg)
        self.verbose = verbose
        self.debug = debug
        self.urlparse = urlparse(iri)
        self.iri, _ = urldefrag(iri)
        self.link_text = link_text
        self.fragment = self.urlparse.fragment
        self.geturl = self.urlparse.geturl()
        self.hostname = self.urlparse.hostname
        self.netloc = self.urlparse.netloc
        self.params = self.urlparse.params
        self.password = self.urlparse.password
        self.path = self.urlparse.path
        self.scheme = self.urlparse.scheme
        try:
            self.port = self.urlparse.port
        except ValueError as e:
            self.port = None

        self.query = self.urlparse.query
        #verify(self.scheme, msg="scheme:// is required")
        self.username = self.urlparse.username
        self.domain = self.urlparse.netloc

    def __repr__(self):
        return '<iridb.atoms.UrlparseResult ' + str(self) + '>'


@click.command()
@click.argument("iris", type=str, nargs=-1)
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.pass_context
def cli(ctx,
        iris: Optional[Iterable[str]],
        verbose: bool,
        debug: bool,
        ):

    ctx.ensure_object(dict)
    null, end, verbose, debug = nevd(ctx=ctx,
                                     printn=False,
                                     ipython=False,
                                     verbose=verbose,
                                     debug=debug,)

    iterator = iris

    index = 0
    for index, iri in enumerate_input(iterator=iterator,
                                      dont_decode=False,  # iris are unicode
                                      null=null,
                                      progress=False,
                                      skip=None,
                                      head=None,
                                      tail=None,
                                      debug=debug,
                                      verbose=verbose,):

        if verbose:
            ic(index, iri)

        iri = UrlparseResult(iri=iri,
                             verbose=verbose,
                             debug=debug,)

        print(iri, end=end)
