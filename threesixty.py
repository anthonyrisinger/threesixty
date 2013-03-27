#!/usr/bin/env python


from __future__ import absolute_import, division

import uwsgi
import sys, os

from threading import Thread
from subprocess import Popen, PIPE
from collections import deque
from pprint import pprint as pp, pformat as pf

from uwsgidecorators import timer, postfork
from functools import total_ordering
from itertools import chain

import json
import time


def pdict():
    from types import MethodType as _m
    def _k2a(fx):
        def gx(*args, **kwds):
            try: return fx(*args, **kwds)
            except KeyError, e: raise AttributeError(*e.args)
        gx.__name__ = fx.__name__
        return gx
    _copy = lambda s: _r(s)
    _dir = lambda s: sorted(set(s).union(*map(dir, _r.__mro__)))
    _r = type('record', (dict,), dict())
    _r.__getattr__ = _m(_k2a(dict.__getitem__), None, _r)
    _r.__setattr__ = _m(_k2a(dict.__setitem__), None, _r)
    _r.__delattr__ = _m(_k2a(dict.__delitem__), None, _r)
    _r.__dir__ = _m(_dir, None, _r)
    _r.copy = _m(_copy, None, _r)
    return _r
pdict = pdict()


_keys = ('addr', 'host', 'lon', 'lat', 'city', 'country', 'len')
_tshark = (
    'tshark',
        '-l',
        #'-r', '/root/pcap/vpn0.x360.0',
        '-i', 'vpn0',
    '-Tfields',
        '-eip.dst',
        '-eip.dst_host',
        '-eip.geoip.dst_lon',
        '-eip.geoip.dst_lat',
        '-eip.geoip.dst_city',
        '-eip.geoip.dst_country',
        '-eudp.length',
    '-R',
        'ip.geoip.dst_city != "Redmond, WA"',
    )


@total_ordering
class Gamer(object):

    ME = ((
        '184.58.129.22',
        'cpe-184-58-129-22.wi.res.rr.com',
        -88.0075,
        43.0228,
        'Milwaukee, WI',
        'United States',
        0,
        ))

    DO = ((
        '192.81.215.209',
        'tear.xtfx.net',
        -73.9981,
        40.7267,
        'New York, NY',
        'United States',
        0,
        ))

    def __init__(self, game, pkt, qlen=16, bmin=16):
        now = time.time()
        qlen = max(qlen, 4)
        bmin = max(bmin, 4)
        zeros = [pdict(len=0, ts=now-1)]*qlen
        self.key = pkt.addr
        self.atime = now
        self.game = game
        self.qlen = qlen
        self.bmin = bmin
        self.heat = 50.0
        self.log = deque(zeros, maxlen=qlen)
        self.out = self.noob(pkt)
        self.b = 0

    def __repr__(self):
        return ('<%s.%s: %s>' % (
            self.__module__, self.__class__.__name__,
            ' '.join('%s=%r' % x for x in (
                ('key', self.key),
                ('bps', self.out.properties.bps),
                ('rank', self.out.properties.rank),
                ))))

    def __hash__(self):
        return int(self.key.replace('.',''))

    def __eq__(self, other):
        return (self.key == other.key)

    def __lt__(self, other):
        #...purposefully "backwards"
        return self.out.properties.bps > other.out.properties.bps

    @property
    def bps(self):
        old = self.atime
        new = self.atime = time.time()
        bps = self.out.properties.bps = int(
                self.b/(new-self.log[0].ts)
                )
        dt = 10*(new-old)*cmp(bps, self.bmin)
        old_heat = self.heat
        new_heat = self.heat = min(self.heat+dt, 150)
        if old_heat < 100 < new_heat:
            self.game.promote(self)
        elif old_heat > 100 > new_heat:
            self.game.demote(self)
        if new_heat < 0:
            self.game.boot(self)
        return bps

    def noob(self, pkt=None):
        pkt = pkt or ptype(zip(_keys,
            ('0.0.0.0', '0.0.0.0', 0, 0, '', '', 0, 0),
            ))
        return pdict({
            'type': 'Feature',
            'geometry': pdict({
                'type': 'Point',
                'coordinates': (pkt.lon, pkt.lat)
                }),
            'properties': pdict({
                'me': pkt.addr == '184.58.129.22',
                'bps': 0,
                'rank': 0,
                'addr': pkt.addr,
                'host': pkt.host,
                'map': ', '.join(filter(None,
                    (pkt.city, pkt.country)
                    )),
                }),
            })

    def play(self, pkt):
        if pkt.host != self.key:
            self.out.properties.host = pkt.host
        self.b += pkt.len - self.log[0].len
        self.log.append(pkt)
        return self.bps, self.heat


class Leaderboard(object):

    def __init__(self):
        self.joe = pdict()
        self.pro = pdict()
        self.fix = pdict({
            Gamer.ME[0]: Gamer(
                self, pdict(zip(_keys, Gamer.ME)),
                ),
            Gamer.DO[0]: Gamer(
                self, pdict(zip(_keys, Gamer.DO)),
                ),
            })

    @property
    def leaders(self):
        for gamer in self.fix.values():
            yield gamer
        for rank, gamer in enumerate(sorted(self.pro.values())):
            gamer.out.properties.rank = rank+1
            yield gamer

    def promote(self, killa):
        print '>>> (joe => pro) ++++', killa
        self.pro[killa.key] = self.joe.pop(killa.key)
        return killa

    def demote(self, tryhard):
        print '>>> (pro => joe) ----', tryhard
        self.joe[tryhard.key] = self.pro.pop(tryhard.key)
        return tryhard

    def boot(self, wanker):
        print '>>> (no camping) xxxx', wanker
        self.joe.pop(wanker.key, None)
        return wanker

    def play(self, pkt):
        gamer = (self.joe.get(pkt.addr, None) or
                 self.pro.get(pkt.addr, None) or
                 self.fix.get(pkt.addr, None))
        if not gamer:
            gamer = Gamer(self, pkt)
            print '>>> new-gamer:', pf(gamer)
            self.joe[pkt.addr] = gamer
        return gamer.play(pkt)


_lb = Leaderboard()


def tshark(lb):
    source = Popen(_tshark, stdout=PIPE, stderr=open(os.devnull))
    for line in iter(source.stdout.readline, ''):
        pkt = pdict(zip(_keys, line.strip().split('\t')))
        pkt.lon = float(pkt.lon)
        pkt.lat = float(pkt.lat)
        pkt.len = float(pkt.len)
        pkt.addr = str(pkt.addr)
        pkt.ts = time.time()
        lb.play(pkt)


@postfork
def spawn(__cache=dict()):
    t = __cache.get(0)
    if t:
        if t.is_alive():
            return t
        t.join()
        __cache.clear()
    t = Thread(target=tshark, args=(_lb,))
    t.daemon = True
    t.start()
    __cache[0] = t
    return t


interval = 5
@timer(interval)
def anticamp(sig, lb=_lb):
    print '-'*79
    now = time.time()
    for gamer in chain(lb.pro.values(), lb.joe.values()):
        if now - gamer.atime > interval:
            for i in range(interval)[::-1]:
                ohnoes = gamer.log[-1].copy()
                ohnoes.update({'len': 0, 'ts': now})
                lb.play(ohnoes)
    print '\n\n%s\n\n' % (pf(list(lb.leaders)),)


def entry_json(environ, start_response, lb=_lb):
    start_response('200 OK', [
        ('Content-Type', 'application/json; charset=utf-8')
        ])
    return [json.dumps({
        'type': 'FeatureCollection',
        'features': [node.out for node in lb.leaders],
        })]


if __name__ == '__main__':
    application()
