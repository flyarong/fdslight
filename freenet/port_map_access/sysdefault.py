#!/usr/bin/env python3

import freenet.port_map_access._access as access_base
import freenet.lib.cfg_check as cfg_check
import freenet.lib.utils as utils
import freenet.lib.logging as logging
import os, json


class access(access_base.base):
    def myinit(self):
        path = "%s/../../fdslight_etc/fn_pm_server_rules.json" % os.path.dirname(__file__)

        with open(path, "r") as f:
            s = f.read()
        f.close()

        s = json.loads(s)

        if not isinstance(s, dict):
            logging.print_error("wrong port map rule file")
            return

        for k in s:
            o = s[k]
            if not self.check(o):
                logging.print_error("wrong port map rule:%s" % str(o))
                break
            self.set_map_info(k, o["address"], o["protocol"], o["port"], is_ipv6=o["is_ipv6"])

    def check(self, o):
        keys = (
            "port", "protocol", "is_ipv6", "address",
        )
        if not isinstance(o, dict): return False
        for k in keys:
            if k not in o: return False

        port = o["port"]
        protocol = o["protocol"]
        is_ipv6 = o["is_ipv6"]
        address = o["address"]

        if not cfg_check.is_port(port): return False
        if protocol not in ("tcp", "udp",): return False

        if is_ipv6 and not utils.is_ipv6_address(address): return False
        if not is_ipv6 and not utils.is_ipv4_address(address): return False

        return True
