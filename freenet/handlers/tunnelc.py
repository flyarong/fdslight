#!/usr/bin/env python3
"""客户端隧道实现
"""
import socket, time, ssl, random, hashlib

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.logging as logging


class tcp_tunnel(tcp_handler.tcp_handler):
    __encrypt = None
    __decrypt = None

    __LOOP_TIMEOUT = 10
    __update_time = 0
    __conn_timeout = 0

    __server_address = None

    __enable_heartbeat = None
    __heartbeat_timeout = None

    __ssl_handshake_ok = None
    __over_https = None

    __http_handshake_ok = None
    __http_handshake_key = None
    __http_auth_id = None
    __enable_https_sni = None
    __https_sni_host = None
    __strict_https = None

    __tmp_buf = None

    def init_func(self, creator, crypto, crypto_configs, conn_timeout=720, is_ipv6=False, **kwargs):
        self.__ssl_handshake_ok = False
        self.__over_https = False
        self.__https_sni_host = None
        self.__enable_https_sni = None

        self.__http_handshake_ok = False
        self.__tmp_buf = []

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_STREAM)

        self.__over_https = kwargs.get("tunnel_over_https", False)

        if self.__over_https:
            cfgs = self.dispatcher.https_configs
            self.__enable_https_sni = cfgs["enable_https_sni"]
            self.__https_sni_host = cfgs["https_sni_host"]
            self.__strict_https = cfgs["strict_https"]

            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_alpn_protocols(["http/1.1"])
            if self.__enable_https_sni:
                if not self.__https_sni_host: self.__https_sni_host = kwargs["host"]
                s = context.wrap_socket(s, do_handshake_on_connect=False, server_hostname=self.__https_sni_host)
            else:
                s = context.wrap_socket(s, do_handshake_on_connect=False)

            if self.__strict_https:
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(self.dispatcher.ca_path)
            else:
                context.verify_mode = ssl.CERT_NONE

        self.set_socket(s)
        self.__conn_timeout = conn_timeout

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        self.__enable_heartbeat = kwargs.get("enable_heartbeat", False)
        self.__heartbeat_timeout = kwargs.get("heartbeat_timeout", 15)

        return self.fileno

    def create_tunnel(self, server_address):
        server_ip = self.dispatcher.get_server_ip(server_address[0])
        if not server_ip: return False

        try:
            self.connect((server_ip, server_address[1]), timeout=8)
            logging.print_general("connecting", server_address)
        except socket.gaierror:
            logging.print_general("not_found_host", server_address)
            return False

        self.__server_address = server_address
        return True

    def tcp_readable(self):
        if self.__over_https and not self.__http_handshake_ok:
            self.recv_handshake()

        # 此处是为了握手成功后接收需要传送的数据包
        if self.__over_https and not self.__http_handshake_ok: return

        rdata = self.reader.read()
        self.__decrypt.input(rdata)

        while self.__decrypt.can_continue_parse():
            try:
                self.__decrypt.parse()
            except proto_utils.ProtoError:
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.__decrypt.get_pkt()
                if not pkt_info: break

                session_id, action, message = pkt_info

                if action not in proto_utils.ACTS: continue
                if action == proto_utils.ACT_PONG: continue
                if action == proto_utils.ACT_PING: continue

                self.__update_time = time.time()
                self.dispatcher.handle_msg_from_tunnel(session_id, action, message)
            ''''''
        return

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.dispatcher.tell_tunnel_close()
        self.unregister(self.fileno)
        self.close()

        if self.is_conn_ok():
            logging.print_general("disconnect", self.__server_address)
        return

    def tcp_error(self):
        logging.print_general("tcp_error", self.__server_address)
        self.delete_handler(self.fileno)

    def __handle_heartbeat_timeout(self):
        t = time.time()

        if t - self.__update_time >= self.__heartbeat_timeout:
            self.send_msg_to_tunnel(self.dispatcher.session_id, proto_utils.ACT_PING, proto_utils.rand_bytes())
        return

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.dispatcher.tunnel_conn_fail()
            logging.print_general("connecting_timeout", self.__server_address)
            self.delete_handler(self.fileno)
            return

        t = time.time()
        v = t - self.__update_time

        if v > self.__conn_timeout:
            self.delete_handler(self.fileno)
            logging.print_general("connected_timeout", self.__server_address)
            return

        if self.__enable_heartbeat:
            if v >= self.__heartbeat_timeout:
                self.send_msg_to_tunnel(self.dispatcher.session_id, proto_utils.ACT_PING, proto_utils.rand_bytes())
            ''''''
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def connect_ok(self):
        self.__update_time = time.time()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        # 发送还没有连接的时候堆积的数据包
        if not self.writer.is_empty():
            self.__update_time = time.time()
            self.add_evt_write(self.fileno)

        logging.print_general("connected", self.__server_address)

        if self.__over_https:
            self.do_ssl_handshake()

        self.dispatcher.tunnel_conn_ok()

    def evt_read(self):
        if not self.is_conn_ok():
            super().evt_read()
            return

        if not self.__over_https:
            super().evt_read()
            return

        if not self.__ssl_handshake_ok:
            self.do_ssl_handshake()

        if not self.__ssl_handshake_ok: return

        try:
            super().evt_read()
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLWantReadError:
            if self.reader.size() > 0:
                self.tcp_readable()
        except ssl.SSLZeroReturnError:
            if self.reader.size() > 0:
                self.tcp_readable()
            if self.handler_exists(self.fileno): self.delete_handler(self.fileno)
        except ssl.SSLError:
            self.delete_handler(self.fileno)

    def evt_write(self):
        if not self.is_conn_ok():
            super().evt_write()
            return

        if not self.__over_https:
            super().evt_write()
            return

        if not self.__ssl_handshake_ok:
            self.remove_evt_write(self.fileno)
            self.do_ssl_handshake()

        if not self.__ssl_handshake_ok: return
        try:
            super().evt_write()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLEOFError:
            self.delete_handler(self.fileno)
        except ssl.SSLError:
            self.delete_handler(self.fileno)

    def do_ssl_handshake(self):
        try:
            self.socket.do_handshake()
            self.__ssl_handshake_ok = True

            # 如果开启SNI那么匹配证书
            if self.__enable_https_sni:
                cert = self.socket.getpeercert()
                ssl.match_hostname(cert, self.__https_sni_host)

            logging.print_general("TLS_handshake_ok", self.__server_address)
            self.add_evt_read(self.fileno)
            self.send_handshake()
        except ssl.SSLWantReadError:
            self.add_evt_read(self.fileno)
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except:
            logging.print_error()
            self.delete_handler(self.fileno)

    def send_msg_to_tunnel(self, session_id, action, message):
        sent_pkt = self.__encrypt.build_packet(session_id, action, message)

        if self.__over_https and not self.__http_handshake_ok:
            self.__tmp_buf.append(sent_pkt)
        else:
            self.writer.write(sent_pkt)

        if self.is_conn_ok(): self.add_evt_write(self.fileno)

        self.__encrypt.reset()

    def rand_string(self, length=8):
        seq = []
        for i in range(length):
            n = random.randint(65, 122)
            seq.append(chr(n))

        s = "".join(seq)
        self.__http_handshake_key = s

        return s

    def send_handshake(self):
        cfgs = self.dispatcher.https_configs
        url = cfgs["url"]
        self.__http_auth_id = cfgs["auth_id"]

        # 伪装成websocket握手
        kv_pairs = [("Connection", "Upgrade"), ("Upgrade", "websocket",), (
            "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:67.0) Gecko/20100101 Firefox/67.0",),
                    ("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"),
                    ("Sec-WebSocket-Version", 13,), ("Sec-WebSocket-Key", self.rand_string(),),
                    ("Sec-WebSocket-Protocol", "fdslight")]

        if int(self.__server_address[1]) == 443:
            host = ("Host", self.__server_address[0],)
            origin = ("Origin", "https://%s" % self.__server_address[0])
        else:
            host = ("Host", "%s:%s" % self.__server_address,)
            origin = ("Origin", "https://%s:%s" % self.__server_address,)

        kv_pairs.append(host)
        kv_pairs.append(origin)

        s = httputils.build_http1x_req_header("GET", url, kv_pairs)

        self.writer.write(s.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

    def recv_handshake(self):
        size = self.reader.size()
        data = self.reader.read()

        p = data.find(b"\r\n\r\n")

        if p < 10 and size > 2048:
            logging.print_general("wrong_http_response_header", self.__server_address)
            self.delete_handler(self.fileno)
            return

        if p < 0:
            self.reader._putvalue(data)
            return
        p += 4

        self.reader._putvalue(data[p:])

        s = data[0:p].decode("iso-8859-1")

        try:
            resp, kv_pairs = httputils.parse_http1x_response_header(s)
        except httputils.Http1xHeaderErr:
            logging.print_general("wrong_http_reponse_header", self.__server_address)
            self.delete_handler(self.fileno)
            return

        version, status = resp

        if status.find("101") != 0:
            logging.print_general("https_handshake_error:%s" % status, self.__server_address)
            self.delete_handler(self.fileno)
            return

        accept_key = self.get_http_kv_pairs("sec-websocket-accept", kv_pairs)
        if wslib.gen_handshake_key(self.__http_handshake_key) != accept_key:
            logging.print_general("https_handshake_error:wrong websocket response key", self.__server_address)
            self.delete_handler(self.fileno)
            return

        auth_id = self.get_http_kv_pairs("x-auth-id", kv_pairs)
        if hashlib.sha256(self.__http_auth_id.encode()).hexdigest() != auth_id:
            logging.print_general("wrong_auth_id", self.__server_address)
            self.delete_handler(self.fileno)
            return

        self.__http_handshake_ok = True
        logging.print_general("http_handshake_ok", self.__server_address)
        # 发送还没有连接的时候堆积的数据包
        if self.__tmp_buf: self.add_evt_write(self.fileno)
        while 1:
            try:
                self.writer.write(self.__tmp_buf.pop(0))
            except IndexError:
                break
            ''''''
        ''''''

    def get_http_kv_pairs(self, name, kv_pairs):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return None


class udp_tunnel(udp_handler.udp_handler):
    __encrypt = None
    __decrypt = None

    __LOOP_TIMEOUT = 10
    __update_time = 0
    __conn_timeout = 0
    __sent_queue = None

    __server_address = None
    __redundancy = None

    __enable_heartbeat = None
    __heartbeat_timeout = None

    def init_func(self, creator, crypto, crypto_configs, redundancy=False, conn_timeout=720, is_ipv6=False, **kwargs):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        self.__redundancy = redundancy

        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)

        self.__conn_timeout = conn_timeout
        self.__sent_queue = []

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        self.__enable_heartbeat = kwargs.get("enable_heartbeat", False)
        self.__heartbeat_timeout = kwargs.get("heartbeat_timeout", 15)

        return self.fileno

    def create_tunnel(self, server_address):
        server_ip = self.dispatcher.get_server_ip(server_address[0])

        if not server_ip: return False

        try:
            self.connect((server_ip, server_address[1]))
        except socket.gaierror:
            self.dispatcher.tunnel_conn_ok()
            logging.print_general("not_found_host", server_address)
            return False

        self.__server_address = server_address
        logging.print_general("udp_open", server_address)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__update_time = time.time()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.dispatcher.tunnel_conn_ok()

        return True

    def udp_readable(self, message, address):
        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result

        if action not in proto_utils.ACTS: return

        if action == proto_utils.ACT_PONG: return
        if action == proto_utils.ACT_PING: return

        self.__update_time = time.time()
        self.dispatcher.handle_msg_from_tunnel(session_id, action, byte_data)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        logging.print_general("udp_error", self.__server_address)
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        t = time.time()
        v = t - self.__update_time

        if v > self.__conn_timeout:
            logging.print_general("udp_timeout", self.__server_address)
            self.delete_handler(self.fileno)
            return

        if self.__enable_heartbeat:
            if t >= self.__heartbeat_timeout:
                self.send_msg_to_tunnel(self.dispatcher.session_id, proto_utils.ACT_PING, proto_utils.rand_bytes())
            ''''''
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.dispatcher.tell_tunnel_close()
        self.close()
        logging.print_general("udp_close", self.__server_address)

    def send_msg_to_tunnel(self, session_id, action, message):
        ippkts = self.__encrypt.build_packets(session_id, action, message, redundancy=self.__redundancy)
        self.__encrypt.reset()

        for ippkt in ippkts: self.send(ippkt)

        self.add_evt_write(self.fileno)
