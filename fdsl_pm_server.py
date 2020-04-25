#!/usr/bin/env python3
import sys, getopt, os, signal, importlib, socket

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/fdslight_pm.pid"
LOG_FILE = "/tmp/fdslight_pm.log"
ERR_FILE = "/tmp/fdslight_pm_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile

import freenet.lib.proc as proc
import freenet.handlers.tundev as tundev
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.handlers.tunnels as tunnels
import freenet.lib.logging as logging
import freenet.lib.port_map as port_map


class _fdslight_pm_server(dispatcher.dispatcher):
    __configs = None
    __debug = None
    __mbuf = None

    __udp6_fileno = -1
    __tcp6_fileno = -1

    __udp_fileno = -1
    __tcp_fileno = -1

    __tcp_crypto = None
    __udp_crypto = None

    __crypto_configs = None

    __support_protocols = (6, 17, 132, 136,)

    __tundev_fileno = -1

    __DEVNAME = "portmap"

    __port_mapv4 = None
    __port_mapv6 = None

    __access = None

    @property
    def http_configs(self):
        configs = self.__configs.get("tunnel_over_http", {})

        pyo = {"auth_id": configs.get("auth_id", "fdslight"), "origin": configs.get("origin", "example.com")}

        return pyo

    def init_func(self, debug, configs, enable_nat_module=False):
        self.create_poll()

        self.__configs = configs
        self.__debug = debug

        self.__port_mapv4 = port_map.port_map(is_ipv6=False)
        self.__port_mapv6 = port_map.port_map(is_ipv6=True)

        signal.signal(signal.SIGUSR1, self.__sig_handle)

        conn_config = self.__configs["connection"]

        tcp_crypto = "freenet.lib.crypto.noany.noany_tcp"
        udp_crypto = "freenet.lib.crypto.noany.noany_udp"

        crypto_configfile = "%s/fdslight_etc/noany.json" % BASE_DIR

        try:
            self.__tcp_crypto = importlib.import_module(tcp_crypto)
            self.__udp_crypto = importlib.import_module(udp_crypto)
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        if not os.path.isfile(crypto_configfile):
            print("cannot found crypto configfile")
            sys.exit(-1)

        try:
            self.__crypto_configs = proto_utils.load_crypto_configfile(crypto_configfile)
        except:
            print("crypto configfile should be json file")
            sys.exit(-1)

        conn_config = self.__configs["connection"]
        mod_name = "freenet.port_map_access.%s" % conn_config["access_module"]

        try:
            access = importlib.import_module(mod_name)
        except ImportError:
            print("cannot found access module %s" % mod_name)
            sys.exit(-1)

        enable_ipv6 = bool(int(conn_config["enable_ipv6"]))
        listen_port = int(conn_config["port"])
        conn_timeout = int(conn_config["conn_timeout"])

        listen_ip = conn_config["listen_ip"]
        listen_ip6 = conn_config["listen_ip6"]

        listen = (listen_ip, listen_port,)
        listen6 = (listen_ip6, listen_port)

        over_http = bool(int(conn_config["tunnel_over_http"]))
        self.__mbuf = utils.mbuf()

        self.__access = access.access(self)

        if enable_ipv6:
            self.__tcp6_fileno = self.create_handler(-1, tunnels.tcp_tunnel, listen6, self.__tcp_crypto,
                                                     self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=True,
                                                     over_http=over_http)
            self.__udp6_fileno = self.create_handler(-1, tunnels.udp_tunnel, listen6, self.__udp_crypto,
                                                     self.__crypto_configs, is_ipv6=True)
        self.__tcp_fileno = self.create_handler(-1, tunnels.tcp_tunnel, listen, self.__tcp_crypto,
                                                self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=False,
                                                over_http=over_http)
        self.__udp_fileno = self.create_handler(-1, tunnels.udp_tunnel, listen, self.__udp_crypto,
                                                self.__crypto_configs, is_ipv6=False)

        self.__tundev_fileno = self.create_handler(-1, tundev.tundevs, self.__DEVNAME)

        if not debug:
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")

    def __get_ip4_hdrlen(self):
        self.__mbuf.offset = 0
        n = self.__mbuf.get_part(1)
        hdrlen = (n & 0x0f) * 4
        return hdrlen

    def myloop(self):
        self.__access.loop()

    def __handle_ipv4_msg_from_tunnel(self, session_id, data_size):
        self.__mbuf.offset = 9
        protocol = self.__mbuf.get_part(1)
        self.__mbuf.offset = 12
        byte_saddr = self.__mbuf.get_part(4)
        if protocol not in self.__support_protocols: return

        hdrlen = self.__get_ip4_hdrlen()
        self.__mbuf.offset = hdrlen
        byte_sport = self.__mbuf.get_part(2)
        src_port = utils.bytes2number(byte_sport)

        rs = self.__access.get_map_rule(byte_saddr, protocol, src_port)
        if not rs: return
        _id, key = rs
        # 会话ID不一致就丢弃数据包
        if session_id != _id: return

        if not self.__access.handle_packet_from_recv(key, data_size): return

        self.__mbuf.offset = 0
        self.get_handler(self.__tundev_fileno).handle_msg_from_tunnel(self.__mbuf.get_data())

    def __handle_ipv6_msg_from_tunnel(self, session_id, data_size):
        self.__mbuf.offset = 6
        nexthdr = self.__mbuf.get_part(1)
        self.__mbuf.offset = 8
        byte_saddr = self.__mbuf.get_part(16)

        if nexthdr not in self.__support_protocols: return

        self.__mbuf.offset = 40

        byte_sport = self.__mbuf.get_part(2)
        src_port = utils.bytes2number(byte_sport)

        rs = self.__access.get_map_rule(byte_saddr, nexthdr, src_port)
        if not rs: return
        _id, key = rs
        if _id != session_id: return
        if not self.__access.handle_packet_from_recv(key, data_size): return

        self.__mbuf.offset = 0
        self.get_handler(self.__tundev_fileno).handle_msg_from_tunnel(self.__mbuf.get_data())

    def handle_msg_from_tunnel(self, fileno, session_id, address, action, message):
        if action != proto_utils.ACT_IPDATA: return
        size = len(message)

        ip_ver = self.__mbuf.ip_version()
        if ip_ver not in (4, 6,): return

        self.__access.set_session(session_id, fileno, address)
        self.__mbuf.copy2buf(message)

        if ip_ver == 4:
            if size < 28: return
            self.__handle_ipv4_msg_from_tunnel(session_id, size)
        else:
            if size < 48: return
            self.__handle_ipv6_msg_from_tunnel(session_id, size)

    def __handle_msg_from_tun_for_ipv4(self, data_size):
        self.__mbuf.offset = 9
        protocol = self.__mbuf.get_part(1)
        self.__mbuf.offset = 16
        byte_daddr = self.__mbuf.get_part(4)
        if protocol not in self.__support_protocols: return

        hdrlen = self.__get_ip4_hdrlen()
        self.__mbuf.offset = hdrlen
        byte_dport = self.__mbuf.get_part(2)
        dst_port = utils.bytes2number(byte_dport)

        rs = self.__access.get_map_rule(byte_daddr, protocol, dst_port)
        if not rs: return
        _id, key = rs
        if not self.__access.handle_packet_for_send(key, data_size): return

        self.__mbuf.offset = 0
        self.__send_msg_to_tunnel(_id, key, self.__mbuf.get_data())

    def __handle_msg_from_tun_for_ipv6(self, data_size):
        self.__mbuf.offset = 6
        nexthdr = self.__mbuf.get_part(1)
        self.__mbuf.offset = 24
        byte_daddr = self.__mbuf.get_part(16)

        if nexthdr not in self.__support_protocols: return

        self.__mbuf.offset = 40

        byte_dport = self.__mbuf.get_part(2)
        dst_port = utils.bytes2number(byte_dport)

        rs = self.__access.get_map_rule(byte_daddr, nexthdr, dst_port)
        if not rs: return
        _id, key = rs

        if not self.__access.handle_packet_for_send(key, data_size): return

        self.__mbuf.offset = 0
        self.__send_msg_to_tunnel(_id, key, self.__mbuf.get_data())

    def __send_msg_to_tunnel(self, session_id, key, message):
        # 查找ID所对应的文件描述符是否存在
        fd, address = self.__access.get_session(session_id)
        if not self.handler_exists(fd): return
        # 查找ID所对应的文件描述符是否存在
        self.get_handler(fd).send_msg(session_id, address, proto_utils.ACT_IPDATA, message)

    def send_msg_to_tunnel_from_tun(self, packet):
        size = len(packet)
        self.__mbuf.copy2buf(packet)
        ver = self.__mbuf.ip_version()

        if ver not in (4, 6,): return

        if ver == 4:
            self.__handle_msg_from_tun_for_ipv4(size)
        else:
            self.__handle_msg_from_tun_for_ipv6(size)

    def set_port_map(self, address, protocol, port, is_ipv6=False):
        if not is_ipv6:
            cmds = [
                "iptables -t nat -I PREROUTING -p %s --dport %d -j DNAT --to %s" % (protocol, port, address,),
                "iptables -t nat -I POSTROUTING -p %s --dport %d -j MASQUERADE" % (protocol, port,)
            ]
        else:
            cmds = [
                "ip6tables -t nat -I PREROUTING -p %s --dport %d -j DNAT --to %s" % (protocol, port, address,),
                "ip6tables -t nat -I POSTROUTING -p %s --dport %d -j MASQUERADE" % (protocol, port,)
            ]

        for cmd in cmds: os.system(cmd)

    def set_route(self, host, prefix=None, is_ipv6=False):
        if is_ipv6:
            s = "-6"
            if not prefix: prefix = 128
        else:
            s = ""
            if not prefix: prefix = 32

        cmd = "ip %s route add %s/%s dev %s" % (s, host, prefix, self.__DEVNAME)
        os.system(cmd)

    def config_os(self, subnet, prefix, eth_name, is_ipv6=False):
        """ 配置系统
        :param subnet:子网
        :param prefix:子网前缀
        :param eth_name:流量出口网卡名
        :return:
        """
        if not is_ipv6:
            # 添加一条到tun设备的IPV4路由
            cmd = "ip route add %s/%s dev %s" % (subnet, prefix, self.__DEVNAME)
            os.system(cmd)
            # 开启ip forward
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        else:
            # 添加一条到tun设备的IPv6路由
            cmd = "ip -6 route add %s/%s dev %s" % (subnet, prefix, self.__DEVNAME)
            os.system(cmd)
            # 开启IPV6流量重定向
            os.system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding")

    def __sig_handle(self, signum, frame):
        pass


def __start_service(debug, enable_nat_module):
    if not debug and os.path.isfile(PID_FILE):
        print("the fdsl_pm_server process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    configs = configfile.ini_parse_from_file("%s/fdslight_etc/fn_pm_server.ini" % BASE_DIR)
    cls = _fdslight_pm_server()

    if debug:
        cls.ioloop(debug, configs, enable_nat_module=enable_nat_module)
        return
    try:
        cls.ioloop(debug, configs, enable_nat_module=enable_nat_module)
    except:
        logging.print_error()

    os.remove(PID_FILE)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found fdslight port map server process")
        return

    os.kill(pid, signal.SIGINT)


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:", [])
    except getopt.GetoptError:
        print(help_doc)
        return
    d = None

    enable_nat_module = False

    for k, v in opts:
        if k == "-d": d = v

    if not d:
        print(help_doc)
        return

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    debug = False

    if d == "stop":
        __stop_service()
        return

    if d == "debug": debug = True
    if d == "start": debug = False

    __start_service(debug, enable_nat_module)


if __name__ == '__main__': main()
