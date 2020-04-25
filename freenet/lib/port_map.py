#!/usr/bin/env python3
"""端口映射相关处理
"""
import socket, struct


class port_map(object):
    __is_ipv6 = None

    __in_rules = None
    __out_rules = None

    def __init__(self, is_ipv6=False):
        self.__in_rules = {}
        self.__out_rules = {}
        self.__is_ipv6 = is_ipv6

    def __get_protcol_number(self, name):
        m = {
            "tcp": 6,
            "udp": 17,
            "sctp": 132,
            "udplite": 136.
        }

        return m.get(name, -1)

    def __build_key(self, ip: str, protocol: str, port: int):
        p = self.__get_protcol_number(protocol)

        if p < 0:
            raise ValueError("wrong protocol value %s,it must be tcp,udp,sctp or udplite" % protocol)

        if self.__is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        byte_ip = socket.inet_pton(fa, ip)

        return self.__build_key2(byte_ip, p, port)

    def __build_key2(self, byte_ip: bytes, proto: int, port: int):
        if self.__is_ipv6:
            fmt = "!16sBH"
        else:
            fmt = "!4sBH"
        key = struct.pack(fmt, byte_ip, proto, port)

        return key

    def add_rule(self, dest_ip: str, rewrite_dest_ip: str, protocol: str, dest_port: int, rewrite_dest_port: int,
                 extra_data=None):
        """
        :param dest_ip:
        :param rewrite_dest_ip:
        :param protocol:
        :param dest_port:
        :param rewrite_dest_port:
        :param extra_data:
        :return:
        """
        in_key = self.__build_key(dest_ip, protocol, dest_port)
        out_key = self.__build_key(rewrite_dest_ip, protocol, rewrite_dest_port)

        if self.__is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        byte_rewrite_dest_ip = socket.inet_pton(fa, rewrite_dest_ip)
        byte_dest_ip = socket.inet_pton(fa, dest_ip)

        self.__in_rules[in_key] = (out_key, byte_rewrite_dest_ip, p, rewrite_dest_port,)
        self.__out_rules[out_key] = (in_key, byte_dest_ip, p, dest_port,)

    def find_rule_for_in(self, byte_dest_ip: bytes, proto: int, dest_port: int):
        key = self.__build_key2(byte_dest_ip, proto, dest_port)

        return self.__in_rules.get(key, None)

    def find_rule_for_out(self, byte_src_ip: bytes, proto: int, src_port: int):
        key = self.__build_key2(byte_src_ip, proto, src_port)

        return self.__out_rules.get(key, None)

    def del_rule_with_in(self, dest_ip: str, protocol: str, dest_port: int):
        key = self.__build_key(dest_ip, protocol, dest_port)

        if key not in self.__in_rules: return

        rs = self.__in_rules[key]
        del self.__out_rules[rs[0]]
