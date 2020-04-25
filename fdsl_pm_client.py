#!/usr/bin/env python3

import os, getopt, signal, importlib, socket, sys, json, struct
import dns.resolver

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile
import pywind.lib.timer as timer

import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.proc as proc
import freenet.handlers.tundev as tundev
import freenet.handlers.tunnelc as tunnelc
import freenet.lib.logging as logging
import freenet.lib.port_map as port_map
import freenet.lib.cfg_check as cfg_check
import freenet.lib.ippkts as ippkts

PID_FILE = "/tmp/fdslight_pm.pid"
LOG_FILE = "/tmp/fdslight_pm.log"
ERR_FILE = "/tmp/fdslight_pm_error.log"


class _fdslight_pm_client(dispatcher.dispatcher):
    __routes = None

    __DEVNAME = "portmap"

    __configs = None

    __mbuf = None

    __tunnel_fileno = -1
    __tundev_fileno = -1
    __debug = False

    __tcp_crypto = None
    __udp_crypto = None
    __crypto_configs = None

    __support_protocols = (6, 17, 132, 136,)
    # 服务器地址
    __server_ip = None

    __port_mapv4 = None
    __port_mapv6 = None

    # 路由超时
    __ROUTE_TIMEOUT = 600
    __route_timer = None
    __session_id = None

    @property
    def https_configs(self):
        configs = self.__configs.get("tunnel_over_https", {})
        enable_https_sni = bool(int(configs.get("enable_https_sni", 0)))
        https_sni_host = configs.get("https_sni_host", "")
        strict_https = bool(int(configs.get("strict_https", "0")))

        pyo = {
            "url": configs.get("url", "/"),
            "auth_id": configs.get("auth_id", "fdslight"),
            "enable_https_sni": enable_https_sni,
            "https_sni_host": https_sni_host,
            "strict_https": strict_https,
        }

        return pyo

    def init_func(self, debug, configs):
        self.create_poll()

        signal.signal(signal.SIGINT, self.__exit)

        self.__routes = {}
        self.__configs = configs

        self.__mbuf = utils.mbuf()
        self.__debug = debug
        self.__tundev_fileno = self.create_handler(-1, tundev.tundevc, self.__DEVNAME)

        self.__port_mapv4 = port_map.port_map(is_ipv6=False)
        self.__port_mapv6 = port_map.port_map(is_ipv6=True)

        self.__ROUTE_TIMEOUT = 1200
        self.__route_timer = timer.timer()

        conn = configs["connection"]

        m = "freenet.lib.crypto.noany"
        try:
            self.__tcp_crypto = importlib.import_module("%s.noany_tcp" % m)
            self.__udp_crypto = importlib.import_module("%s.noany_udp" % m)
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        crypto_fpath = "%s/fdslight_etc/noany.json" % BASE_DIR

        if not os.path.isfile(crypto_fpath):
            print("crypto configfile not exists")
            sys.exit(-1)

        try:
            crypto_configs = proto_utils.load_crypto_configfile(crypto_fpath)
        except:
            print("crypto configfile should be json file")
            sys.exit(-1)

        self.__crypto_configs = crypto_configs

        if not debug:
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")
        ''''''

    def __handle_ipv4_msg_from_tundev(self):
        self.__mbuf.offset = 9
        protocol = self.__mbuf.get_part(1)
        self.__mbuf.offset = 12
        byte_saddr = self.__mbuf.get_part(4)

        if protocol not in self.__support_protocols: return

        hdrlen = self.__get_ip4_hdrlen()
        if hdrlen < 28: return

        self.__mbuf.offset = hdrlen
        byte_sport = self.__mbuf.get_part(2)
        src_port = utils.bytes2number(byte_sport)

        rules = self.__port_mapv4.find_rule_for_out(byte_saddr, protocol, src_port)
        if not rules: return

        in_key, byte_src_ip, p, port = rules
        ippkts.modify_ip4address(byte_saddr, self.__mbuf, flags=0)
        ippkts.modify_port(port, self.__mbuf, flags=0)

        self.__mbuf.offset = 0
        message = self.__mbuf.get_data()

        self.send_msg_to_tunnel(proto_utils.ACT_IPDATA, message)

    def send_msg_to_tunnel(self, action, message):
        if not self.handler_exists(self.__tunnel_fileno):
            self.__open_tunnel()

        if not self.handler_exists(self.__tunnel_fileno): return

        handler = self.get_handler(self.__tunnel_fileno)
        handler.send_msg_to_tunnel(self.session_id, action, message)

    def __handle_ipv6_msg_from_tundev(self):
        self.__mbuf.offset = 6
        nexthdr = self.__mbuf.get_part(1)
        self.__mbuf.offset = 8
        byte_saddr = self.__mbuf.get_part(16)

        if nexthdr not in self.__support_protocols: return

        self.__mbuf.offset = 40

        byte_sport = self.__mbuf.get_part(2)
        src_port = utils.bytes2number(byte_sport)

        rules = self.__port_mapv6.find_rule_for_out(byte_saddr, nexthdr, src_port)
        if not rules: return

        in_key, byte_src_ip, p, port = rules
        ippkts.modify_ip6address(byte_saddr, self.__mbuf, flags=0)
        ippkts.modify_port(port, self.__mbuf, flags=0)

        self.__mbuf.offset = 0
        message = self.__mbuf.get_data()

        self.send_msg_to_tunnel(proto_utils.ACT_IPDATA, message)

    def handle_msg_from_tundev(self, message):
        """处理来TUN设备的数据包
        :param message:
        :return:
        """
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()

        if ip_ver not in (4, 6,): return

        if ip_ver == 4:
            self.__handle_ipv4_msg_from_tundev()
        else:
            self.__handle_ipv6_msg_from_tundev()

    def __get_ip4_hdrlen(self):
        self.__mbuf.offset = 0
        n = self.__mbuf.get_part(1)
        hdrlen = (n & 0x0f) * 4

        return hdrlen

    def __handle_ipv4_data_from_tunnel(self):
        self.__mbuf.offset = 12
        byte_src_addr = self.__mbuf.get_part(4)
        self.__mbuf.offset = 16
        byte_dst_addr = self.__mbuf.get_part(4)
        self.__mbuf.offset = 9
        protocol = self.__mbuf.get_part(1)

        hdrlen = self.__get_ip4_hdrlen()
        if hdrlen + 8 < 28: return False

        # 检查IP数据报长度是否合法
        self.__mbuf.offset = 2
        payload_length = utils.bytes2number(self.__mbuf.get_part(2))

        if payload_length != self.__mbuf.payload_size: return
        if protocol not in self.__support_protocols: return

        self.__mbuf.offset = hdrlen + 2
        byte_dst_port = self.__mbuf.get_part(2)
        dst_port = utils.bytes2number(byte_dst_port)

        rule = self.__port_mapv4.find_rule_for_in(byte_dst_addr, protocol, dst_port)
        if not rule: return

        src_addr = socket.inet_ntop(socket.AF_INET, byte_src_addr)
        k = "%s/32" % src_addr
        if k not in self.__routes:
            self.set_route(src_addr, prefix=32, is_ipv6=False)

        _, rewrite_dest_ip, p, rewrite_dest_port = rule
        # 此处重写IP地址
        ippkts.modify_ip4address(rewrite_dest_ip, self.__mbuf, flags=1)
        ippkts.modify_port(rewrite_dest_port, self.__mbuf, flags=1)
        self.__mbuf.offset = 0
        byte_data = self.__mbuf.get_data()
        self.get_handler(self.__tundev_fileno).msg_from_tunnel(byte_data)

    def __handle_ipv6_data_from_tunnel(self):
        self.__mbuf.offset = 4
        payload_length = utils.bytes2number(self.__mbuf.get_part(2))
        if payload_length + 40 != self.__mbuf.payload_size: return

        self.__mbuf.offset = 6
        nexthdr = self.__mbuf.get_part(1)

        if nexthdr not in self.__support_protocols: return

        self.__mbuf.offset = 24
        byte_dst_addr = self.__mbuf.get_part(16)
        self.__mbuf.offset = 42
        byte_dst_port = self.__mbuf.get_part(2)
        dst_port = utils.bytes2number(byte_dst_port)

        rule = self.__port_mapv6.find_rule_for_in(byte_dst_addr, nexthdr, dst_port)
        if not rule: return

        self.__mbuf.offset = 8
        byte_src_addr = self.__mbuf.get_part(16)
        src_addr = socket.inet_ntop(socket.AF_INET6, byte_src_addr)
        k = "%s/132" % src_addr

        if k not in self.__routes:
            self.set_route(src_addr, prefix=132, is_ipv6=True)
        # 此处重写IP地址
        byte_rewrite, extra_data = rule
        ippkts.modify_ip6address(byte_rewrite, self.__mbuf, flags=1)
        self.__mbuf.offset = 0
        byte_data = self.__mbuf.get_data()
        self.get_handler(self.__tundev_fileno).msg_from_tunnel(byte_data)

    def handle_msg_from_tunnel(self, seession_id, action, message):
        if seession_id != self.session_id: return
        if action != proto_utils.ACT_IPDATA: return

        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()
        if ip_ver not in (4, 6,): return

        if 4 == ip_ver:
            self.__handle_ipv4_data_from_tunnel()
        else:
            self.__handle_ipv6_data_from_tunnel()

    @property
    def session_id(self):
        if not self.__session_id:
            connection = self.__configs["connection"]
            auth_id = connection["auth_id"]
            self.__session_id = proto_utils.calc_content_md5(auth_id)
        return self.__session_id

    def __check_rule(self, rule: dict):
        """检查每一条规则
        :param rule:
        :return:
        """
        keys = (
            "is_ipv6", "dest_addr", "rewrite_dest_addr", "dest_port", "rewrite_dest_port",
        )

        for k in keys:
            if k not in rule: return False

        is_ipv6 = rule["is_ipv6"]
        dest_addr = rule["dest_addr"]
        rewrite_dest = rule["rewrite_dest_addr"]
        dest_port = rule["dest_port"]
        rewrite_dest_port = rule["rewrite_dest_port"]
        protocol = rule["protocol"]

        if protocol not in ("tcp", "udp", "udplite", "sctp",): return False

        if is_ipv6 and (not utils.is_ipv6_address(dest_addr) or not utils.is_ipv6_address(rewrite_dest)):
            return False

        if not is_ipv6 and (not utils.is_ipv4_address(dest_addr) or not utils.is_ipv4_address(rewrite_dest)):
            return False

        if not cfg_check.is_port(dest_port): return False
        if not cfg_check.is_port(rewrite_dest_port): return False

        return True

    def __load_port_map_rules(self):
        fpath = "%s/fdslight_etc/fn_pm_client_rules.json" % BASE_DIR

        with open(fpath, "r") as f:
            s = f.read()
        f.close()

        try:
            rules = json.loads(s)
        except json.JSONDecodeError:
            logging.print_error("wrong port map client rules")
            return

        if not isinstance(rules, list):
            logging.print_error("wrong port map client rules,it must be list type")
            return

        for info in rules:
            if not self.__check_rule(info):
                logging.print_error("wrong port map rule about %s" % info)
                break

            is_ipv6 = info["is_ipv6"]
            if is_ipv6:
                cls = self.__port_mapv6
            else:
                cls = self.__port_mapv4

    def __open_tunnel(self):
        conn = self.__configs["connection"]
        host = conn["host"]
        port = int(conn["port"])
        enable_ipv6 = bool(int(conn["enable_ipv6"]))
        conn_timeout = int(conn["conn_timeout"])
        tunnel_type = conn["tunnel_type"]
        redundancy = bool(int(conn.get("udp_tunnel_redundancy", 1)))
        over_https = bool(int(conn.get("tunnel_over_https", 0)))

        is_udp = False
        heartbeat_timeout = int(conn.get("heartbeat_timeout", 15))
        if heartbeat_timeout < 10:
            raise ValueError("wrong heartbeat_timeout value from config")

        if tunnel_type.lower() == "udp":
            handler = tunnelc.udp_tunnel
            crypto = self.__udp_crypto
            is_udp = True
        else:
            handler = tunnelc.tcp_tunnel
            crypto = self.__tcp_crypto

        if conn_timeout < 120:
            raise ValueError("the conn timeout must be more than 120s")

        enable_heartbeat = True

        kwargs = {"conn_timeout": conn_timeout, "is_ipv6": enable_ipv6, "enable_heartbeat": enable_heartbeat,
                  "heartbeat_timeout": heartbeat_timeout, "host": host}

        if not is_udp:
            kwargs["tunnel_over_https"] = over_https

        if tunnel_type.lower() == "udp": kwargs["redundancy"] = redundancy

        self.__tunnel_fileno = self.create_handler(-1, handler, crypto, self.__crypto_configs, **kwargs)

        rs = self.get_handler(self.__tunnel_fileno).create_tunnel((host, port,))
        if not rs:
            self.delete_handler(self.__tunnel_fileno)

    def tell_tunnel_close(self):
        self.__tunnel_fileno = -1

    def get_server_ip(self, host):
        """获取服务器IP
        :param host:
        :return:
        """
        self.__server_ip = host

        if utils.is_ipv4_address(host): return host
        if utils.is_ipv6_address(host): return host

        enable_ipv6 = bool(int(self.__configs["connection"]["enable_ipv6"]))
        resolver = dns.resolver.Resolver()

        try:
            if enable_ipv6:
                rs = resolver.query(host, "AAAA")
            else:
                rs = resolver.query(host, "A")
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except dns.resolver.NoNameservers:
            return None
        except:
            return None

        ipaddr = None

        for anwser in rs:
            ipaddr = anwser.__str__()
            break

        self.__server_ip = ipaddr
        return ipaddr

    def myloop(self):
        names = self.__route_timer.get_timeout_names()
        for name in names:
            if self.__route_timer.exists(name):
                self.__route_timer.drop(name)
                host, prefix, is_ipv6 = self.__routes[name]
                self.__del_route(host, prefix=prefix, is_ipv6=is_ipv6)
            ''''''
        return

    def set_route(self, host, prefix=None, is_ipv6=False):
        if host in self.__routes: return
        # 如果是服务器的地址,那么不设置路由,避免使用ip_rules规则的时候进入死循环,因为服务器地址可能不在ip_rules文件中
        if host == self.__server_ip: return

        if is_ipv6:
            s = "-6"
            if not prefix: prefix = 128
        else:
            s = ""
            if not prefix: prefix = 32

        # 已經存在的路由不添加s
        k = "%s/%s" % (host, prefix,)
        if k in self.__routes: return

        cmd = "ip %s route add %s/%s dev %s" % (s, host, prefix, self.__DEVNAME)

        self.__routes[k] = (host, prefix, is_ipv6,)
        self.__route_timer.set_timeout(k, self.__ROUTE_TIMEOUT)

        os.system(cmd)

    def __del_route(self, host, prefix=None, is_ipv6=False):
        if is_ipv6:
            s = "-6"
            if not prefix: prefix = 128
        else:
            s = ""
            if not prefix: prefix = 32

        cmd = "ip %s route del %s/%s dev %s" % (s, host, prefix, self.__DEVNAME)
        os.system(cmd)

    def __exit(self, signum, frame):
        sys.exit(0)

    @property
    def ca_path(self):
        """获取CA路径
        :return:
        """
        path = "%s/fdslight_etc/ca-bundle.crt" % BASE_DIR
        return path


def __start_service(debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the fdsl_pm_client process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    config_path = "%s/fdslight_etc/fn_pm_client.ini" % BASE_DIR

    configs = configfile.ini_parse_from_file(config_path)

    cls = _fdslight_pm_client()

    if debug:
        cls.ioloop(debug, configs)
        return
    try:
        cls.ioloop(debug, configs)
    except:
        logging.print_error()

    os.remove(PID_FILE)


def __stop_service():
    pid = proc.get_pid(PID_FILE)
    if pid < 0: return

    os.kill(pid, signal.SIGINT)


def __update_rules():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("fdslight port map process not exists")
        return

    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    -d      debug | start | stop     debug,start or stop application
    -u      rules                      update port map rules
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:", [])
    except getopt.GetoptError:
        print(help_doc)
        return
    d = ""
    u = ""

    for k, v in opts:
        if k == "-u":
            u = v
            break
        if k == "-d": d = v

    if not d and not u:
        print(help_doc)
        return

    if u and u != "rules":
        print(help_doc)
        return
    if u == "rules":
        __update_rules()
        return

    if d not in ("debug", "start", "stop",):
        print(help_doc)
        return

    if d in ("start", "debug",):
        if d == "debug":
            debug = True
        else:
            debug = False
        __start_service(debug)
        return

    if d == "stop": __stop_service()


if __name__ == '__main__': main()
