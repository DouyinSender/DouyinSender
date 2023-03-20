import collections
import logging
import random
from abc import ABC, abstractmethod
from enum import Enum

from mitmproxy import connection, ctx, tls
from mitmproxy.utils import human
from mitmproxy import http
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec
import mitmproxy.http

import re
import redis
import asyncio
import time
import random

# 添加代理IP部分
connection_pool = redis.ConnectionPool(host="localhost",port=6379,decode_responses=True)
#r = redis.Redis(host="localhost",port=6379,decode_responses=True)
r = redis.Redis(connection_pool=connection_pool)
__ip__ = r.get("ip")
daili = __ip__.split(":")
ip,port = daili
class HandleRequest:

    def request(self,flow: http.HTTPFlow) -> None:
        #ctx.log.warn("[*] ChangeProxy Request Start ...")
        address = (ip,int(port))
        is_proxy_change = address != flow.server_conn.via.address
        server_connection_already_open = flow.server_conn.timestamp_start is not None
        if is_proxy_change and server_connection_already_open:
            # server_conn already refers to an existing connection (which cannot be modified),
            # so we need to replace it with a new server connection object.
            flow.server_conn = Server(flow.server_conn.address)
        flow.server_conn.via = ServerSpec("http", address)
        #ctx.log.warn(f"[*] Request Change Proxy {daili}")




        # 解析 X-Bogus
        is_login = r.get('is_login')
        if is_login=='1':
            if "https://www.douyin.com/" in flow.request.url:
            #if 'douyin.com' in flow.request.url:
                try:
                    x_bogus = flow.request.query.get("X-Bogus")
                    r.set("x_bogus",x_bogus)
                except:
                    pass
                try:

                    mstoken = flow.request.query.get("msToken")
                    r.set("mstoken_query",mstoken)
                except:
                    pass
                try:
                    webid = flow.request.query.get("webid")
                    r.set("webid",webid)
                except:
                    pass
                try:
                    xgplayer_user_id = flow.request.cookies.get("xgplayer_user_id")
                    r.set('xgplayer_user_id',xgplayer_user_id)
                except:
                    pass

    def response(self,flow:http.HTTPFlow) -> None: 
        #if "captcha.js" in flow.request.url:
        #ctx.log.warn("[*] ChangeProxy Response Start ...")
        for webdriver_key in ['webdriver', '__driver_evaluate', '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium', '_WEBDRIVER_ELEM_CACHE', 'ChromeDriverw', 'driver-evaluate', 'webdriver-evaluate', 'selenium-evaluate', 'webdriverCommand', 'webdriver-evaluate-response', '__webdriverFunc', '__webdriver_script_fn', '__$webdriverAsyncExecutor', '__lastWatirAlert', '__lastWatirConfirm', '__lastWatirPrompt', '$chrome_asyncScriptInfo', '$cdc_asdjflasutopfhvcZLmcfl_','$cdc_lsidnglsidnglsiddldien_' ]:
            message = 'Remove "{}" from {}.'.format(
            webdriver_key, flow.request.url
            )
            info = webdriver_key+","+flow.request.url+"\n"
            flow.response.text = flow.response.text.replace('"{}"'.format(webdriver_key), '"NO-SUCH-ATTR"')  

        flow.response.text = flow.response.text.replace('t.webdriver', 'false')
        flow.response.text = flow.response.text.replace('ChromeDriver', '')
        #ctx.log.warn("[*] Response Replace Webdriver ...")





# TLS部分
class InterceptionResult(Enum):
    SUCCESS = 1
    FAILURE = 2
    SKIPPED = 3


class TlsStrategy(ABC):
    def __init__(self):
        # A server_address -> interception results mapping
        self.history = collections.defaultdict(lambda: collections.deque(maxlen=200))

    @abstractmethod
    def should_intercept(self, server_address: connection.Address) -> bool:
        raise NotImplementedError()

    def record_success(self, server_address):
        self.history[server_address].append(InterceptionResult.SUCCESS)

    def record_failure(self, server_address):
        self.history[server_address].append(InterceptionResult.FAILURE)

    def record_skipped(self, server_address):
        self.history[server_address].append(InterceptionResult.SKIPPED)


class ConservativeStrategy(TlsStrategy):
    """
    Conservative Interception Strategy - only intercept if there haven't been any failed attempts
    in the history.
    """
    def should_intercept(self, server_address: connection.Address) -> bool:
        return InterceptionResult.FAILURE not in self.history[server_address]


class ProbabilisticStrategy(TlsStrategy):
    """
    Fixed probability that we intercept a given connection.
    """
    def __init__(self, p: float):
        self.p = p
        super().__init__()

    def should_intercept(self, server_address: connection.Address) -> bool:
        return random.uniform(0, 1) < self.p


class MaybeTls:
    strategy: TlsStrategy

    def load(self, l):
        l.add_option(
            "tls_strategy", int, 0,
            "TLS passthrough strategy. If set to 0, connections will be passed through after the first unsuccessful "
            "handshake. If set to 0 < p <= 100, connections with be passed through with probability p.",
        )

    def configure(self, updated):
        if "tls_strategy" not in updated:
            return
        if ctx.options.tls_strategy > 0:
            self.strategy = ProbabilisticStrategy(ctx.options.tls_strategy / 100)
        else:
            self.strategy = ConservativeStrategy()

    def tls_clienthello(self, data: tls.ClientHelloData):
        server_address = data.context.server.peername
        #ctx.log.warn("[*] TLS Client Hello Start ...")
        if not self.strategy.should_intercept(server_address):
            #logging.info(f"TLS passthrough: {human.format_address(server_address)}.")
            data.ignore_connection = True
            self.strategy.record_skipped(server_address)

    def tls_established_client(self, data: tls.TlsData):
        server_address = data.context.server.peername
        #logging.info(f"TLS handshake successful: {human.format_address(server_address)}")
        self.strategy.record_success(server_address)

    def tls_failed_client(self, data: tls.TlsData):
        server_address = data.context.server.peername
        #logging.info(f"TLS handshake failed: {human.format_address(server_address)}")
        self.strategy.record_failure(server_address)

addons = [
    HandleRequest(),
    MaybeTls()
]