#!/usr/bin/env python3
"""端口映射的基本访问类
"""
import freenet.lib.logging as logging
import freenet.lib.base_proto.utils as proto_utils

import pywind.lib.timer as timer

import socket, struct


class base(object):
    __map_info = None
    __timer = None
    __sessions = None
    __serviced = None

    def __init__(self, serviced):
        self.__map_info = {}
        self.__timer = timer.timer()
        self.__sessions = {}
        self.__serviced = serviced

        self.myinit()

    def myinit(self):
        """重写这个方法
        :return:
        """
        pass

    def handle_packet_from_recv(self, key, packet_size):
        """重写这个方法,处理从服务器tun设备接受过来的数据
        :param packet_size:
        :return Boolean: True表示接受数据包,False表示抛弃数据包
        """
        return True

    def handle_packet_for_send(self, key, packet_size):
        """重写这个方法,处理发送到服务器tun设备的数据
        :param packet_size:
        :return Boolean: True表示接受数据包,False表示抛弃数据包
        """
        return True

    def __build_key2(self, byte_ip: bytes, proto_num: int, port: int, is_ipv6=False):
        if is_ipv6:
            fmt = "!16sBH"
        else:
            fmt = "!4sBH"

        key = struct.pack(fmt, byte_ip, proto_num, port)

        return key

    def __build_key(self, address: str, protocol: str, port: int, is_ipv6=False):
        proto_numbers = {
            "tcp": 6, "udp": 17, "sctp": 132, "udplite": 136,
        }
        if protocol not in proto_numbers: return False
        proto_num = proto_numbers[protocol]

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        byte_ip = socket.inet_pton(fa, address)

        return self.__build_key2(byte_ip, proto_num, port, is_ipv6=is_ipv6)

    def set_map_info(self, key: str, address: str, protocol: str, port: int, is_ipv6=False):
        k = self.__build_key(address, protocol, port, is_ipv6=is_ipv6)
        self.__map_info[k] = (proto_utils.calc_content_md5(key.encode()), key,)

    def get_map_rule(self, byte_ip, proto_num, port, is_ipv6=False):
        """
        :param byte_ip:
        :param proto_num:
        :param port:
        :param is_ipv6:
        :return:
        """
        k = self.__build_key2(byte_ip, proto_num, port, is_ipv6=is_ipv6)

        return self.__map_info.get(k, None)

    def clear_map_rule(self):
        self.__map_info = {}

    @property
    def sessions(self):
        return self.__sessions

    @property
    def map_info(self):
        return self.__map_info

    def change_map_rule(self):
        """改变映射规则,重写这个方法,该函数用于程序不重新启动的情况下更改端口映射规则
        :return:
        """
        pass

    def get_session(self, session_id):
        return self.__sessions.get(session_id, -1)

    def set_session(self, session_id, fd, address):
        self.__sessions[session_id] = (fd, address,)
        self.__timer.set_timeout(session_id, 600)

    def loop(self):
        names = self.__timer.get_timeout_names()

        for name in names:
            if self.__timer.exists(name):
                self.__timer.drop(name)
                del self.__sessions[name]
            ''''''
        ''''''
