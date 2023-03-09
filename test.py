#!/usr/bin/env python
import argparse
import base64
import logging
import os
import re
import sys
from dataclasses import dataclass
from itertools import chain
from json import dumps, loads
from typing import Union, Literal

import cmd2 as cmd2
from dotenv import load_dotenv
from pydantic import Extra

from simple_unifi import UnifiAPI, PortConf, UbiBase, LoginInfo, Device, PortOverride, PoeMode


@dataclass(init=False)
class TestApp(cmd2.Cmd):
    api: UnifiAPI
    request_logging: bool

    APP_CATEGORY = 'API'

    class MyHandler(logging.Handler):
        def __init__(self, app: 'TestApp', *args, **kwargs):
            self.app = app
            super().__init__(*args, **kwargs)

        def emit(self, record: logging.LogRecord) -> None:
            if self.app.request_logging:
                self.app.poutput(record.msg)

    def __init__(self, *, user: str, password: str, host: str):
        super().__init__()
        load_dotenv()
        self.api = UnifiAPI(host=host, user=user, password=password, verify=False)

        self.request_logging = False
        api_logger = logging.getLogger('simple_unifi')
        api_logger.setLevel(logging.DEBUG)
        app_handler = TestApp.MyHandler(app=self)
        api_logger.addHandler(app_handler)
        self.onecmd('set debug true')
        self.onecmd('login')
        self.onecmd('stat_device --summary')

    parser = argparse.ArgumentParser()
    parser.add_argument('logging', choices=['on', 'off'], help='turn logging of requests "on" or "off"')

    def print_model(self, data: Union[UbiBase, list[UbiBase]]):
        if isinstance(data, UbiBase):
            json_str = data.json()
        else:
            json_str = f'[{",".join(e.json() for e in data)}]'
        self.poutput(dumps(loads(json_str), indent=2))

    @cmd2.with_category('SYS')
    def do_clear_cookies(self, args: argparse.Namespace):
        """
        clear session cookies
        """
        self.api.cookies.clear()
        self.api.x_csrf_token = None
        self.api.referer = None

    @cmd2.with_category('SYS')
    def do_show_cookies(self, args: argparse.Namespace):
        """
        Show session cookies
        """

        def decode(p: str) -> str:
            try:
                return base64.b64decode(p + '==').decode()
            except Exception as e:
                return f'{e} trying to decode: {p}'

        for k, v in self.api.cookies.items():
            self.poutput(f'{k}: {v}')

        if token := self.api.cookies.get('TOKEN'):
            self.poutput('Token:')
            token_parts = token.split('.')
            token_parts = list(chain(map(decode, token_parts[:2]), [token_parts[2]]))
            self.poutput('\n'.join(f'  {s}' for s in token_parts))

    @cmd2.with_argparser(parser=parser)
    @cmd2.with_category('SYS')
    def do_logging(self, args: argparse.Namespace):
        """
        Turn request logging on or off
        """
        self.request_logging = args.logging == 'on'
        self.poutput(f'request logging {"on" if self.request_logging else "off"}')

    parser = argparse.ArgumentParser()
    parser.add_argument('extra', choices=['allow', 'forbid', 'ignore'], nargs='?',
                        help='allow, forbid, ignore extra attributes. If not provided then current setting is printed.')

    @cmd2.with_argparser(parser)
    @cmd2.with_category(APP_CATEGORY)
    def do_extra(self, args: argparse.Namespace):
        """
        Configure handling of extra attributes returned by the API
        """
        if args.extra:
            # set new extra handling
            enum_extra = next(e for e in Extra if e.value == args.extra)
            UbiBase.Config.extra = enum_extra
        self.poutput(f'Handling of extra attributes: {UbiBase.Config.extra.value}')

    @cmd2.with_category(APP_CATEGORY)
    def do_system(self, args: argparse.Namespace):
        """
        call api/system
        """
        self.print_model(self.api.system())

    @cmd2.with_category(APP_CATEGORY)
    def do_login(self, args: argparse.Namespace):
        """
        call api/auth/login
        """
        self.print_model(self.api.login())

    parser = argparse.ArgumentParser()
    parser.add_argument('mac', help='MAC of device', type=str, nargs='?')
    parser.add_argument('--summary', help='only display summary', action='store_true')

    @cmd2.with_argparser(parser=parser)
    @cmd2.with_category(APP_CATEGORY)
    def do_stat_device(self, args: argparse.Namespace):
        """
        call proxy/network/api/s/default/stat/device with optional MAC
        """
        device_list = self.api.stat_device(args.mac)
        if args.summary:
            type_len = max(map(len, (d.type for d in device_list)))
            model_len = max(map(len, (d.model for d in device_list)))
            ip_len = max(map(len, (d.ip for d in device_list)))
            self.poutput('\n'.join(f'mac: {d.mac} id: {d.id}, ip: {d.ip:{ip_len}} type: {d.type:{type_len}} '
                                   f'model: {d.model:{model_len}} ports: {len(d.port_table)}'
                                   for d in device_list))
            foo = 1
        else:
            self.print_model(device_list)

    @cmd2.with_category(APP_CATEGORY)
    def do_poe_ports(self, args: argparse.Namespace):
        """
        list all ports with PoE enabled and active
        """
        device_list = self.api.stat_device()
        devices_with_poe = [(d, poe_ports) for d in device_list
                            if (poe_ports := [port for port in d.port_table
                                              if port.port_poe and port.poe_enable])]
        for device, port_list in devices_with_poe:
            self.poutput(f'mac: {device.mac} id: {device.id}, ip: {device.ip} type: {device.type} '
                         f'model: {device.model} ports: {len(device.port_table)}')
            po_dict = device.override_dict
            for port in port_list:
                self.poutput(f'  port: {port.port_idx} host: {port.mac_table[0].hostname}')
                if override := po_dict.get(port.port_idx):
                    self.poutput(f'    overrides: {", ".join(override.__dict__)}')

    parser = argparse.ArgumentParser()
    parser.add_argument('mac', type=str, help='mac address of device')
    parser.add_argument('port', type=str,
                        help='Regex to match port index values ("," can be used instead of "|"). For example "1,2,'
                             '3" selects ports 1,2, and 3.'
                             'If missing then consider all ports', nargs='?')
    parser.add_argument('mode', type=str, nargs='?', choices=['auto', 'off'],
                        help='desired PoE mode. If missing then only determine current mode')

    @cmd2.with_argparser(parser)
    @cmd2.with_category(APP_CATEGORY)
    def do_poe_mode(self, args: argparse.Namespace):
        """
        Switch PoE mode of one or more ports. If no mode is given just determine current mode
        """
        device = self.api.stat_device(mac=args.mac)[0]
        poe_ports = [port.port_idx for port in device.port_table
                     if port.port_poe]
        updated = False
        if not poe_ports:
            self.poutput('Device doesn\'t have PoE ports')
            return

        if args.port:
            try:
                port_re = re.compile(f'^({args.port.replace(",", "|")})$')
            except re.error as e:
                self.perror(f'Invalid port spec: {e}')
                return
            target_ports = [port for port in poe_ports
                            if port_re.match(str(port))]
        else:
            target_ports = poe_ports
        for target_port in target_ports:
            port = next((port
                         for port in (device.port_table or list())
                         if port.port_idx == target_port), None)
            if port is None:
                self.perror(f'Invalid port index: {target_port}. Allowed: '
                            f'{", ".join(str(p) for p in sorted(poe_ports))}')
                continue

            # determine currents state and print info
            mode = port.poe_mode
            if args.mode and mode == args.mode:
                change = ', no change'
            elif args.mode is None:
                change = ''
            else:
                change = f', changing to {args.mode}'
            self.poutput(f'port {port.port_idx}, PoE mode: {mode if mode is not None else "unknown"}{change}')

            if args.mode is None or args.mode == mode:
                # nothing to do
                continue

            # set new mode
            updated = True
            override = device.override_dict.get(port.port_idx)
            if override is None:
                # add a new Override
                override = PortOverride(port_idx=port.port_idx)
                device.port_overrides.append(override)
                device.port_overrides.sort(key=lambda o: o.port_idx)
            override.poe_mode = args.mode
        if updated:
            # apply new port overrides
            self.api.apply_port_overrides(device_id=device.id, overrides=device.port_overrides)

    parser = argparse.ArgumentParser()
    parser.add_argument('mode', type=str, choices=['auto', 'off'],
                        help='desired PoE mode. ')

    @cmd2.with_argparser(parser)
    @cmd2.with_category(APP_CATEGORY)
    def do_poe_test(self, args: argparse.Namespace):
        """
        change PoE mode of some ports using direct API call
        :return:
        """
        self.api.change_poe_mode(mac='74:ac:b9:10:7b:8a', mode=args.mode, ports=[11, 12, 13, 14])


def main():
    load_dotenv()
    user = os.getenv('UNIFI_USER')
    password = os.getenv('UNIFI_PASSWORD')
    host = os.getenv('UNIFI_HOST')
    if not all((user, password, host)):
        print('UNIFI_USER, UNIFI_PASSWORD, and UNIFI_HOST all need to be set', file=sys.stderr)
        exit(1)
    if True:
        app = TestApp(host=host, user=user, password=password)
        sys.exit(app.cmdloop())
    with UnifiAPI(host=host, user=user, password=password, verify=False) as api:
        api.login()
        device = api.device()
        device_basic = api.device_basic()
        port_conf = api.portconf()
        network_conf = api.networkconf()

    print('Port configs:')
    print('\n'.join(f'{pc}' for pc in port_conf))

    port_configs: dict[str, PortConf] = {pc.id: pc for pc in port_conf}

    poe_switch_basic = next((b for b in device_basic if b.model == 'USL24P'), None)
    mac = poe_switch_basic.mac
    poe_switch = next((d for d in device if d.mac == mac), None)

    print(f'PoE switch: {poe_switch}')
    print('Port overrides')
    for override in poe_switch.port_overrides:
        print(f'  {override.port_idx:2}: ', end='')
        port_config = port_configs.get(override.portconf_id)
        if port_config:
            print(f'portconf: {port_config.name} ', end='')

        ignore = {'port_idx', 'portconf_id', 'autoneg', 'stp_port_mode', 'port_security_enabled'}
        or_repr = ', '.join(f'{k}: {v}' for k, v in override.__dict__.items()
                            if k not in ignore and v is not None and v != [])
        print(f'{or_repr} ')
    return


if __name__ == '__main__':
    main()
