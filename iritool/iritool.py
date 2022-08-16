#!/usr/bin/env python3
# -*- coding: utf8 -*-

# pylint: disable=missing-docstring               # [C0111] docstrings are always outdated and wrong
# pylint: disable=fixme                           # [W0511] todo is encouraged
# pylint: disable=line-too-long                   # [C0301]
# pylint: disable=too-many-instance-attributes    # [R0902]
# pylint: disable=too-many-lines                  # [C0302] too many lines in module
# pylint: disable=invalid-name                    # [C0103] single letter var names, name too descriptive
# pylint: disable=too-many-return-statements      # [R0911]
# pylint: disable=too-many-branches               # [R0912]
# pylint: disable=too-many-statements             # [R0915]
# pylint: disable=too-many-arguments              # [R0913]
# pylint: disable=too-many-nested-blocks          # [R1702]
# pylint: disable=too-many-locals                 # [R0914]
# pylint: disable=too-few-public-methods          # [R0903]
# pylint: disable=no-member                       # [E1101] no member for base
# pylint: disable=attribute-defined-outside-init  # [W0201]
# pylint: disable=too-many-boolean-expressions    # [R0916] in if statement
from __future__ import annotations

from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal
from typing import Iterable
from urllib.parse import urldefrag
from urllib.parse import urlparse
from urllib.parse import urlsplit

import click
from asserttool import ic
from asserttool import increment_debug
from clicktool import click_add_options
from clicktool import click_global_options
from clicktool import tv
from hashtool import Digest
from iridb.tld import tldextract
from mptool import output
from reify import reify
from unmp import unmp
from urltool import extract_psl_domain

signal(SIGPIPE, SIG_DFL)


class UrlMissingSchemeError(ValueError):
    pass


class IriBase:
    # iri: ParseResult | SplitResult  # X | Y syntax for unions requires Python 3.10  [misc]
    # iri: Union[ParseResult, SplitResult]
    iri: str
    domain: str
    verbose: bool | int | float

    def __str__(self):
        # import IPython; IPython.embed()
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

    @reify
    def digest(self):
        digest = Digest(
            preimage=self.iri.encode("utf8"),
            algorithm="sha3_256",
            verbose=self.verbose,
        )
        return digest

    def is_internal(self, root_iri):
        # assert isinstance(root_iri, Iri)  # nawh, it could be a UrlparseResult
        if self.domain_psl == root_iri.domain_psl:
            return True
        return False


class UrlsplitResult(IriBase):
    @increment_debug
    def __init__(
        self,
        iri: str,
        verbose: bool | int | float,
        link_text: None | str = None,
    ):
        try:
            assert isinstance(iri, str)
        except AssertionError:
            msg = f"iri: {iri} must be type str, not type {type(iri)}"
            raise ValueError(msg)
        self.verbose = verbose

        self.urlsplit = urlsplit(iri)
        self.iri, _ = urldefrag(iri)
        self.iri = self.iri.strip()
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
        # self.params = self.urlsplit.params  # urlsplit does not split out params, they are associated with each path element
        # verify(self.scheme, msg="scheme:// is required")

    def __repr__(self):
        return f"<iridb.atoms.UrlsplitResult {str(self)}>"


class UrlparseResult(IriBase):
    @increment_debug
    def __init__(
        self,
        iri: str,
        verbose: bool | int | float,
        link_text: None | str = None,
        dont_allow_missing_scheme: bool = False,
    ):
        try:
            assert isinstance(iri, str)
        except AssertionError:
            msg = f"iri: {iri} must be type str, not type {type(iri)}"
            raise ValueError(msg)
        self.verbose = verbose
        self.dont_allow_missing_scheme = dont_allow_missing_scheme
        self.urlparse = urlparse(iri)
        self.iri, _ = urldefrag(iri)
        self.iri = self.iri.strip()
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
        # verify(self.scheme, msg="scheme:// is required")
        self.username = self.urlparse.username
        self.domain = self.urlparse.netloc

        # ic(self.scheme)
        if self.scheme == "":
            ic("missing scheme!", len(iri), iri)
            ic(self.urlparse)
            if self.dont_allow_missing_scheme:
                raise UrlMissingSchemeError(iri)
        if self.verbose:
            ic(
                self.urlparse,
                self.iri,
                self.link_text,
                self.fragment,
                self.geturl,
                self.hostname,
                self.netloc,
                self.params,
                self.password,
                self.path,
                self.scheme,
                self.query,
                self.username,
                self.domain,
                self.domain_tld,
                self.domain_psl,
                self.domain_sld,
            )

    def __repr__(self):
        return f"<iridb.atoms.UrlparseResult {str(self)}>"


@click.command()
@click.argument("iris", type=str, nargs=-1)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx,
    iris: None | Iterable[str],
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_input: bool,
):

    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )

    if iris:
        iterator = iris
    else:
        iterator = unmp(
            valid_types=[
                str,
            ],
            verbose=verbose,
        )

    index = 0
    for index, iri in enumerate(iterator):
        if verbose:
            ic(index, iri)

        iri = UrlparseResult(
            iri=iri,
            verbose=verbose,
        )

        output(iri, reason=None, verbose=verbose, tty=tty, dict_input=dict_input)


# def domain_set_to_sorted_list_grouped_by_tld(domains):
#    data = []
#    for x in domains:
#       d = x.strip().split('.')
#       d.reverse()
#       data.append(d)
#    data.sort()
#    for y in data:
#       y.reverse()
#       print('.'.join(y))
#
