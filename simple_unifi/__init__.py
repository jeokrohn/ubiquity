import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from io import StringIO, TextIOBase
from typing import Optional, Any
from urllib.parse import parse_qsl

import urllib3
import urllib3.exceptions
from pydantic import BaseModel, Extra, Field, parse_obj_as

from requests import Session, Response

__all__ = ['Port', 'Device', 'BasicDevice', 'UnifiAPI', 'LoginInfo', 'PortConf']

log = logging.getLogger(__name__)


def dump_response(response: Response, file: TextIOBase = None):
    """
    Dump response object to log file

    :param response: HTTP request response
    :param file: stream to dump to
    :type file: TextIOBase
    """
    if not log.isEnabledFor(logging.DEBUG):
        return
    dump_log = log
    output = file or StringIO()

    # dump response objects in redirect history
    for h in response.history:
        dump_response(response=h, file=output)

    print(f'Request {response.status_code}[{response.reason}]: '
          f'{response.request.method} {response.request.url}', file=output)

    # request headers
    for k, v in response.request.headers.items():
        if k.lower() == 'authorization':
            v = 'Bearer ***'
        print(f'  {k}: {v}', file=output)

    # request body
    request_body = response.request.body
    if request_body:
        print('  --- body ---', file=output)
        ct = response.request.headers.get('content-type').lower()
        if ct.startswith('application/json'):
            for line in json.dumps(json.loads(request_body), indent=2).splitlines():
                print(f'  {line}', file=output)
        elif ct.startswith('application/x-www-form-urlencoded'):
            for k, v in parse_qsl(request_body):
                print(f'  {k}: {"***" if k == "client_secret" else v}',
                      file=output)
        else:
            print(f'  {request_body}', file=output)

    print(' Response', file=output)
    # response headers
    for k in response.headers:
        print(f'  {k}: {response.headers[k]}', file=output)
    body = response.text
    # dump response body
    if body:
        print('  --- response body ---', file=output)
        try:
            body = json.loads(body)
            if 'access_token' in body:
                # mask access token
                body['access_token'] = '***'
            elif 'refresh_token' in body:
                body['refresh_token'] = '***'
            body = json.dumps(body, indent=2)
        except json.JSONDecodeError:
            pass
        for line in body.splitlines():
            print(f'  {line}', file=output)
    print(' ---- end ----', file=output)
    dump_log.debug(output.getvalue())


class UbiBase(BaseModel):
    """
    Base class for all data models used on the API
    """

    class Config:
        extra = Extra.allow

    def __str__(self):
        values = self.dict(exclude_unset=True, exclude_none=True)
        return ' '.join(f'{k}={v}' for k, v in values.items())

    def __repr__(self):
        return f'{self.__class__.__name__}({self})'

    def json(self, exclude_none: bool = True, **kwargs) -> str:
        return super().json(exclude_none=exclude_none, **kwargs)


class Hardware(UbiBase):
    shortname: str


class SystemResponse(UbiBase):
    hardware: Optional[Hardware]
    name: Optional[str]
    mac: Optional[str]
    isSingleUser: Optional[bool]
    isSsoEnabled: Optional[bool]
    directConnectDomain: Optional[str]
    deviceState: Optional[str]


class LoginInfo(UbiBase):
    unique_id: Optional[str]
    id: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    full_name: Optional[str]
    email: Optional[str]
    email_status: Optional[str]
    email_is_null: Optional[bool]
    create_time: Optional[datetime]
    login_time: Optional[datetime]
    update_time: Optional[datetime]
    device_token: Optional[str] = Field(alias='deviceToken')


class PoeMode(str, Enum):
    auto = 'auto'
    off = 'off'


class PortOverride(UbiBase):
    port_idx: Optional[int]
    portconf_id: Optional[str]
    poe_mode: Optional[PoeMode]
    port_security_enabled: Optional[bool]
    port_security_mac_address: Optional[list[Any]]
    stp_port_mode: Optional[bool]
    autoneg: Optional[bool]
    name: Optional[str]


class MacTableEntry(UbiBase):
    age: Optional[int]
    hostname: Optional[str]
    ip: Optional[str]
    mac: Optional[str]
    static: Optional[bool]
    uptime: Optional[int]
    vlan: Optional[int]
    is_only_station_on_port: Optional[bool]


class Port(UbiBase):
    port_idx: Optional[int]
    media: Optional[str]
    port_poe: Optional[bool]
    poe_caps: Optional[int]
    speed: Optional[int]
    speed_caps: Optional[int]
    op_mode: Optional[str]
    portconf_id: Optional[str]
    poe_mode: Optional[str]
    autoneg: Optional[bool]
    poe_class: Optional[str]
    poe_current_ma: Optional[float] = Field(alias='poe_current')
    poe_enable: Optional[bool]
    poe_good: Optional[bool]
    poe_power_w: Optional[float] = Field(alias='poe_power')
    poe_voltage_v: Optional[float] = Field(alias='poe_voltage')
    mac_table: Optional[list[MacTableEntry]]


class Device(UbiBase):
    id: str = Field(alias='_id')
    ip: Optional[str]
    mac: Optional[str]
    model: Optional[str]
    type: Optional[str]
    version: Optional[str]
    adopted: Optional[bool]
    site_id: Optional[str]
    port_table: list[Port]
    port_overrides: list[PortOverride] = Field(default_factory=list)

    @property
    def override_dict(self) -> dict[int, PortOverride]:
        return {po.port_idx: po for po in (self.port_overrides or list())}


class BasicDevice(UbiBase):
    mac: Optional[str]
    name: Optional[str]
    state: Optional[int]
    adopted: Optional[bool]
    disabled: Optional[bool]
    type: Optional[str]
    model: Optional[str]


class PortConf(UbiBase):
    name: Optional[str]
    id: Optional[str] = Field(alias='_id')
    site_id: Optional[str]
    forward: Optional[str]
    attr_hidden_id: Optional[str]
    attr_hidden: Optional[bool]
    attr_no_delete: Optional[bool]
    attr_no_edit: Optional[bool]
    dot1x_ctrl: Optional[str]
    autoneg: Optional[bool]
    isolation: Optional[bool]
    stormctrl_ucast_enabled: Optional[bool]
    stormctrl_mcast_enabled: Optional[bool]
    stormctrl_bcast_enabled: Optional[bool]
    stp_port_mode: Optional[bool]
    lldpmed_enabled: Optional[bool]
    lldpmed_notify_enabled: Optional[bool]
    egress_rate_limit_kbps_enabled: Optional[bool]
    setting_preference: Optional[str]


class NetworkConf(UbiBase):
    id: str = Field(alias='_id')
    attr_no_delete: Optional[bool]
    attr_hidden_id: Optional[str]
    name: Optional[str]
    site_id: Optional[str]
    vlan_enabled: Optional[bool]
    purpose: Optional[str]
    ip_subnet: Optional[str]
    ipv6_interface_type: Optional[str]
    domain_name: Optional[str]
    is_nat: Optional[bool]
    dhcpd_enabled: Optional[bool]
    dhcpd_start: Optional[str]
    dhcpd_stop: Optional[str]
    dhcpdv6_enabled: Optional[bool]
    ipv6_ra_enabled: Optional[bool]
    networkgroup: Optional[str]
    dhcp_relay_enabled: Optional[bool]
    dhcpd_dns_enabled: Optional[bool]
    dhcpd_gateway_enabled: Optional[bool]
    dhcpd_ip_1: Optional[str]
    dhcpd_leasetime: Optional[int]
    dhcpd_time_offset_enabled: Optional[bool]
    dhcpguard_enabled: Optional[bool]
    enabled: Optional[bool]
    dhcpd_ip_2: Optional[str]
    lte_lan_enabled: Optional[bool]
    setting_preference: Optional[str]
    mdns_enabled: Optional[bool]
    auto_scale_enabled: Optional[bool]
    vlan: Optional[str]
    wan_networkgroup: Optional[str]
    wan_type: Optional[str]
    wan_smartq_enabled: Optional[bool]
    wan_smartq_up_rate: Optional[int]
    wan_smartq_down_rate: Optional[int]
    report_wan_event: Optional[bool]
    wan_type_v6: Optional[str]
    wan_load_balance_type: Optional[str]
    wan_load_balance_weight: Optional[int]
    wan_egress_qos: Optional[str]
    wan_provider_capabilities: Optional[dict]
    wan_dns_preference: Optional[str]


@dataclass(init=False)
class UnifiAPI(Session):
    host: str
    user: str
    password: str = field(repr=False)
    login_response: LoginInfo
    x_csrf_token: str

    def __init__(self, host: str, user: str, password: str, verify: bool = None):
        super().__init__()
        self.host = host
        self.user = user
        self.password = password
        self.x_csrf_token = None
        if verify is not None:
            self.verify = verify
            if not verify:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def restart(self):
        """
        Reset context (clear cookies and x-csrf-token
        """
        self.cookies.clear()
        self.x_csrf_token = None

    def url(self, path: str) -> str:
        return f'https://{self.host}/{path}'

    def request(self, method, url, *args, headers: dict = None, **kwargs) -> Response:
        headers = headers or dict()
        if self.x_csrf_token and method in ('PUT', 'POST'):
            headers.update({'x-csrf-token': self.x_csrf_token})
        response = super().request(method, url, *args, headers=headers, **kwargs)
        dump_response(response)
        response.raise_for_status()
        token = response.headers.get('x-csrf-token')
        if token and token != self.x_csrf_token:
            self.x_csrf_token = token
        return response

    def system(self) -> SystemResponse:
        url = self.url('api/system')
        with self.get(url=url) as r:
            data = r.json()
        return SystemResponse.parse_obj(data)

    def login(self) -> LoginInfo:
        url = self.url('api/auth/login')
        body = {'password': self.password,
                'token': '',
                'username': self.user,
                'rememberMe': False}
        with self.post(url=url, json=body) as r:
            data = r.json()
            self.login_response = LoginInfo.parse_obj(data)
        return self.login_response

    def stat_device(self, mac: Optional[str] = None) -> list[Device]:
        url = self.url('proxy/network/api/s/default/stat/device')
        if mac:
            url = f'{url}/{mac}'
        with self.get(url=url) as r:
            data = r.json()
        return parse_obj_as(list[Device], data['data'])

    def stat_device_basic(self) -> list[BasicDevice]:
        url = self.url('proxy/network/api/s/default/stat/device-basic')
        with self.get(url=url) as r:
            data = r.json()
        return parse_obj_as(list[BasicDevice], data['data'])

    def portconf(self) -> list[PortConf]:
        url = self.url('proxy/network/api/s/default/rest/portconf')
        with self.get(url=url) as r:
            data = r.json()
        return parse_obj_as(list[PortConf], data['data'])

    def networkconf(self) -> list[NetworkConf]:
        url = self.url('proxy/network/api/s/default/rest/networkconf')
        with self.get(url=url) as r:
            data = r.json()
        return parse_obj_as(list[NetworkConf], data['data'])

    def apply_port_overrides(self, device_id: str, overrides: list[PortOverride]) -> Optional[Device]:
        url = self.url(f'proxy/network/api/s/default/rest/device/{device_id}')
        body = {'port_overrides': [json.loads(po.json()) for po in overrides]}
        with self.put(url=url, json=body) as r:
            data = r.json()
        device_list = data['data']
        if not device_list:
            return None
        return Device.parse_obj(device_list[0])

    def change_poe_mode(self, mac: str, mode: PoeMode, ports: Iterable[int]) -> Optional[Device]:
        """

        :param mac:
        :param mode:
        :param ports:
        :return:
        """
        mode_enum = next((e for e in PoeMode if mode == e), None)
        if mode_enum is None:
            raise ValueError(f'invalid mode argument: {mode}')
        mode_enum: PoeMode
        self.restart()
        self.login()

        device = self.stat_device(mac=mac)[0]
        poe_ports: dict[int, Port] = {port.port_idx: port for port in device.port_table
                                      if port.port_poe}
        # determined target ports
        target_ports: dict[int, Port] = {}
        for port_idx in ports:
            if (poe_port := poe_ports.get(port_idx)) is None:
                raise KeyError(f'port {mac}:{port_idx} is not a PoE port')
            target_ports[port_idx] = poe_port

        overrides = device.override_dict
        update_required = False
        for target_port_idx, port in target_ports.items():
            if port.poe_mode == mode_enum.value:
                # port already has the correct value
                log.debug(f'port {mac},{port.port_idx}, already set to {mode_enum.value}')
                continue
            log.debug(f'port {mac},{port.port_idx}, update to {mode_enum.value}')

            # set new mode
            update_required = True
            override = overrides.get(target_port_idx)
            if override is None:
                # add a new Override
                override = PortOverride(port_idx=target_port_idx)
                device.port_overrides.append(override)
            # apply new poe mode
            override.poe_mode = mode_enum
        if update_required:
            # apply new port overrides
            device.port_overrides.sort(key=lambda o: o.port_idx)
            return self.apply_port_overrides(device_id=device.id, overrides=device.port_overrides)
        return
