#!/usr/bin/env python


from __future__ import absolute_import, division
from pprint import pprint as pp, pformat as pf

import uwsgi
import sys, os

import gevent
from gevent.fileobject import FileObjectPosix
from collections import deque

from uwsgidecorators import postfork
from functools import partial, total_ordering

import json
import time
import signal


def gpfork(fn):
    postfork(gevent.Greenlet(fn).start)


def pdict():
    from types import MethodType as _m
    from collections import defaultdict as _dd
    def _k2a(fx):
        def gx(*args, **kwds):
            try: return fx(*args, **kwds)
            except KeyError, e: raise AttributeError(*e.args)
        gx.__name__ = fx.__name__
        return gx
    _init = lambda s, *a, **k: super(_r, s).__init__(
            k.pop('__missing__', None), *a, **k)
    _copy = lambda s: _r(s)
    _dir = lambda s: sorted(set(s).union(*map(dir, _r.__mro__)))
    _r = type('pdict', (_dd,), dict())
    _r.__getattr__ = _m(_k2a(_dd.__getitem__), None, _r)
    _r.__setattr__ = _m(_k2a(_dd.__setitem__), None, _r)
    _r.__delattr__ = _m(_k2a(_dd.__delitem__), None, _r)
    _r.__init__ = _m(_init, None, _r)
    _r.__dir__ = _m(_dir, None, _r)
    _r.copy = _m(_copy, None, _r)
    return _r
pdict = pdict()


@total_ordering
class Gamer(object):

    STATIC = [
        '0\t0\t184.58.129.22\tcpe-184-58-129-22.wi.res.rr.com'
        '\t-88.0075\t43.0228\tMilwaukee, WI\tUnited States',
        '0\t0\t192.81.215.209\ttear.xtfx.net'
        '\t-73.9981\t40.7267\tNew York, NY\tUnited States',
        ]

    def __init__(self, game, pkt=None):
        self.game = game
        self.feat = pdict(__missing__=pdict)
        self.log = deque(maxlen=10)
        self.b = 0
        if pkt:
            self.welcome(pkt)

    def __repr__(self):
        return ('<%s.%s: %s>' % (
            self.__module__, self.__class__.__name__,
            ' '.join('%s=%r' % x for x in (
                ('addr', self.feat.properties.addr),
                ('rank', self.feat.properties.rank),
                ('bps', self.feat.properties.bps),
                ))))

    def __hash__(self):
        return int(self.feat.properties.addr.replace('.',''))

    def __eq__(self, other):
        return self.feat.properties.addr == other.feat.properties.addr

    def __lt__(self, other):
        #NOTE: purposefully "backwards"; higher bps ranks first
        return self.feat.properties.bps > other.feat.properties.bps

    def mavg(self):
        b, self.b = self.b, 0
        self.log.append(b)
        self.feat.properties.bps = round(sum(self.log)/(len(self.log) or 1), 2)
        return b

    @property
    def bps(self):
        return self.feat.properties.bps

    def welcome(self, pkt):
        f = self.feat

        f.type = 'Feature'
        f.geometry.type = 'Point'
        f.geometry.coordinates = (pkt.lon, pkt.lat)
        f.properties.me = pkt.addr in self.game.sta
        f.properties.mvp = False
        f.properties.bps = 0.0
        f.properties.rank = 0
        f.properties.addr = pkt.addr
        f.properties.host = pkt.host
        f.properties.map = ', '.join(filter(None,
            (pkt.city, pkt.country)
            ))

        if pkt.addr == pkt.host:
            del f.properties.host
        return self

    def __call__(self, pkt):
        if 'type' not in self.feat:
            self.welcome(pkt)
        if 'host' not in self.feat.properties:
            self.feat.properties.host = pkt.host

        self.b += pkt.len

        return self.b


class Leaderboard(object):

    def __init__(self):
        self.dyn = pdict(__missing__=partial(Gamer, game=self))
        self.sta = pdict(__missing__=partial(Gamer, game=self))
        for raw in Gamer.STATIC:
            pkt = Packet(raw)
            self.sta[pkt.addr].welcome(pkt)

    @property
    def leaders(self):
        finals = sorted(self.dyn.values())

        if finals:
            bps = False
            mvp = finals[0]
            me = self.sta['184.58.129.22']
            for rank, gamer in enumerate(finals, start=1):
                gamer.feat.properties.mvp = False
                gamer.feat.properties.rank = rank
                if rank in (1,):
                    bps = gamer.bps
                if rank in (2,3):
                    bps -= gamer.bps
            me.feat.properties.mvp = False
            if bps < 0:
                mvp = me
            mvp.feat.properties.mvp = True
            print '>>> MVP!!!', mvp

        for gamer in self.sta.values():
            yield gamer
        for gamer in finals:
            yield gamer

    def __call__(self, pkt):
        self.dyn[pkt.addr](pkt)


class Packet(pdict):

    _attrs = ('ts', 'len', 'addr', 'host', 'lon', 'lat', 'city', 'country')
    _casts = (float, int, str, str, float, float, str, str)

    def __init__(self, raw, offset=time.time(), seek=0.0):
        super(pdict, self).__init__(None,[
            (attr, cast(value))
            for (attr, cast, value) in zip(
                self._attrs,
                self._casts,
                raw.strip().split('\t'),
                )])
        self.ts = offset + round(self.ts - seek, 6)

    def __repr__(self):
        return ('<%s.%s: %s>' % (
            self.__module__, self.__class__.__name__,
            ' '.join('%s=%r' % x for x in (
                ('ts', self.ts),
                ('len', self.len),
                ('addr', self.addr),
                ))))


class GCtrl(object):

    running = True


_fd = os.fdopen(int(os.environ['TSHARK_FD']))
_lb = Leaderboard()


@gpfork
def _tshark(lb=_lb, fd=_fd, seek=0.0, hz=30.0):
    offset = now = time.time()
    for raw in FileObjectPosix(fd):
        if not GCtrl.running:
            break

        pkt = Packet(raw, offset, seek)
        if offset > pkt.ts:
            continue

        while GCtrl.running:
            now = time.time()
            if now > pkt.ts:
                gevent.spawn(lb, pkt)
                break
            gevent.sleep(1/hz)


@gpfork
def _stats(lb=_lb, interval=5):
    sep = '-'*79
    tpl = '%s\nLEADERS:\n%s\n\nGAMERS:\n%s\n%s'
    while GCtrl.running:
        gevent.sleep(interval)
        print tpl % (
                sep,
                pf(tuple(lb.leaders), indent=4),
                pf(tuple(lb.dyn.values()), indent=4),
                sep,
                )


@gpfork
def _mavg(lb=_lb, interval=1):
    while GCtrl.running:
        gevent.sleep(interval)
        for gamer in lb.dyn.itervalues():
            gamer.mavg()


@gpfork
def _bps(lb=_lb, interval=10):
    while GCtrl.running:
        gevent.sleep(interval)
        dead = tuple((
            addr
            for (addr, gamer) in lb.dyn.iteritems()
                if not gamer.bps
            ))

        print 'BOOTING...'
        pp(dead, indent=4)
        map(lb.dyn.pop, dead)


def _shutdown():
    GCtrl.running = False
gevent.signal(signal.SIGHUP, _shutdown)
gevent.signal(signal.SIGINT, _shutdown)
gevent.signal(signal.SIGTERM, _shutdown)


def jsonserver(environ, start_response, lb=_lb):
    start_response('200 OK', [
        ('Content-Type', 'application/json; charset=utf-8')
        ])
    return [json.dumps({
        'type': 'FeatureCollection',
        'features': [node.feat for node in lb.leaders],
        })]
