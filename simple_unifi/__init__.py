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
from pydantic import BaseModel, Field, TypeAdapter, ConfigDict
from requests import Session, Response

__all__ = [
    "Port",
    "Device",
    "BasicDevice",
    "UnifiAPI",
    "LoginInfo",
    "PortConf",
    "UbiBase",
    "PortOverride",
]

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

    print(
        f"Request {response.status_code}[{response.reason}]: "
        f"{response.request.method} {response.request.url}",
        file=output,
    )

    # request headers
    for k, v in response.request.headers.items():
        if k.lower() == "authorization":
            v = "Bearer ***"
        print(f"  {k}: {v}", file=output)

    # request body
    request_body = response.request.body
    if request_body:
        print("  --- body ---", file=output)
        ct = response.request.headers.get("content-type").lower()
        if ct.startswith("application/json"):
            for line in json.dumps(json.loads(request_body), indent=2).splitlines():
                print(f"  {line}", file=output)
        elif ct.startswith("application/x-www-form-urlencoded"):
            for k, v in parse_qsl(request_body):
                print(f"  {k}: {'***' if k == 'client_secret' else v}", file=output)
        else:
            print(f"  {request_body}", file=output)

    print(" Response", file=output)
    # response headers
    for k in response.headers:
        print(f"  {k}: {response.headers[k]}", file=output)
    body = response.text
    # dump response body
    if body:
        print("  --- response body ---", file=output)
        try:
            body = json.loads(body)
            if "access_token" in body:
                # mask access token
                body["access_token"] = "***"
            elif "refresh_token" in body:
                body["refresh_token"] = "***"
            body = json.dumps(body, indent=2)
        except json.JSONDecodeError:
            pass
        for line in body.splitlines():
            print(f"  {line}", file=output)
    print(" ---- end ----", file=output)
    dump_log.debug(output.getvalue())


class UbiBase(BaseModel):
    """
    Base class for all data models used on the API
    """

    model_config = ConfigDict(extra="allow")

    def __str__(self):
        values = self.model_dump(mode="json", exclude_unset=True, exclude_none=True)
        return " ".join(f"{k}={v}" for k, v in values.items())

    def __repr__(self):
        return f"{self.__class__.__name__}({self})"

    def json(self, exclude_none: bool = True, **kwargs) -> str:
        return super().model_dump_json(exclude_none=exclude_none, **kwargs)


class Hardware(UbiBase):
    shortname: str


class SystemResponse(UbiBase):
    hardware: Optional[Hardware] = Field(None)
    name: Optional[str] = Field(None)
    mac: Optional[str] = Field(None)
    isSingleUser: Optional[bool] = Field(None)
    isSsoEnabled: Optional[bool] = Field(None)
    directConnectDomain: Optional[str] = Field(None)
    deviceState: Optional[str] = Field(None)


class LoginInfo(UbiBase):
    unique_id: Optional[str] = Field(None)
    id: Optional[str] = Field(None)
    first_name: Optional[str] = Field(None)
    last_name: Optional[str] = Field(None)
    full_name: Optional[str] = Field(None)
    email: Optional[str] = Field(None)
    email_status: Optional[str] = Field(None)
    email_is_null: Optional[bool] = Field(None)
    create_time: Optional[datetime] = Field(None)
    login_time: Optional[datetime] = Field(None)
    update_time: Optional[datetime] = Field(None)
    device_token: Optional[str] = Field(alias="deviceToken")


class PoeMode(str, Enum):
    auto = "auto"
    off = "off"


class PortOverride(UbiBase):
    port_idx: Optional[int] = Field(None)
    portconf_id: Optional[str] = Field(None)
    poe_mode: Optional[PoeMode] = Field(None)
    port_security_enabled: Optional[bool] = Field(None)
    port_security_mac_address: Optional[list[Any]] = Field(None)
    stp_port_mode: Optional[bool] = Field(None)
    autoneg: Optional[bool] = Field(None)
    name: Optional[str] = Field(None)


class MacTableEntry(UbiBase):
    age: Optional[int] = Field(None)
    hostname: Optional[str] = Field(None)
    ip: Optional[str] = Field(None)
    mac: Optional[str] = Field(None)
    static: Optional[bool] = Field(None)
    uptime: Optional[int] = Field(None)
    vlan: Optional[int] = Field(None)
    is_only_station_on_port: Optional[bool] = Field(None)


class Port(UbiBase):
    port_idx: Optional[int] = Field(None)
    media: Optional[str] = Field(None)
    port_poe: Optional[bool] = Field(None)
    poe_caps: Optional[int] = Field(None)
    speed: Optional[int] = Field(None)
    speed_caps: Optional[int] = Field(None)
    op_mode: Optional[str] = Field(None)
    portconf_id: Optional[str] = Field(None)
    poe_mode: Optional[str] = Field(None)
    autoneg: Optional[bool] = Field(None)
    poe_class: Optional[str] = Field(None)
    poe_current_ma: Optional[float] = Field(None, alias="poe_current")
    poe_enable: Optional[bool] = Field(None)
    poe_good: Optional[bool] = Field(None)
    poe_power_w: Optional[float] = Field(None, alias="poe_power")
    poe_voltage_v: Optional[float] = Field(None, alias="poe_voltage")
    mac_table: Optional[list[MacTableEntry]] = Field(None)


class Device(UbiBase):
    id: str = Field(alias="_id")
    ip: Optional[str] = Field(None)
    mac: Optional[str] = Field(None)
    model: Optional[str] = Field(None)
    type: Optional[str] = Field(None)
    version: Optional[str] = Field(None)
    adopted: Optional[bool] = Field(None)
    site_id: Optional[str] = Field(None)
    port_table: list[Port]
    port_overrides: list[PortOverride] = Field(default_factory=list)

    @property
    def override_dict(self) -> dict[int, PortOverride]:
        return {po.port_idx: po for po in (self.port_overrides or list())}


class BasicDevice(UbiBase):
    mac: Optional[str] = Field(None)
    name: Optional[str] = Field(None)
    state: Optional[int] = Field(None)
    adopted: Optional[bool] = Field(None)
    disabled: Optional[bool] = Field(None)
    type: Optional[str] = Field(None)
    model: Optional[str] = Field(None)


class PortConf(UbiBase):
    name: Optional[str] = Field(None)
    id: Optional[str] = Field(None, alias="_id")
    site_id: Optional[str] = Field(None)
    forward: Optional[str] = Field(None)
    attr_hidden_id: Optional[str] = Field(None)
    attr_hidden: Optional[bool] = Field(None)
    attr_no_delete: Optional[bool] = Field(None)
    attr_no_edit: Optional[bool] = Field(None)
    dot1x_ctrl: Optional[str] = Field(None)
    autoneg: Optional[bool] = Field(None)
    isolation: Optional[bool] = Field(None)
    stormctrl_ucast_enabled: Optional[bool] = Field(None)
    stormctrl_mcast_enabled: Optional[bool] = Field(None)
    stormctrl_bcast_enabled: Optional[bool] = Field(None)
    stp_port_mode: Optional[bool] = Field(None)
    lldpmed_enabled: Optional[bool] = Field(None)
    lldpmed_notify_enabled: Optional[bool] = Field(None)
    egress_rate_limit_kbps_enabled: Optional[bool] = Field(None)
    setting_preference: Optional[str] = Field(None)


class NetworkConf(UbiBase):
    id: str = Field(alias="_id")
    attr_no_delete: Optional[bool] = Field(None)
    attr_hidden_id: Optional[str] = Field(None)
    name: Optional[str] = Field(None)
    site_id: Optional[str] = Field(None)
    vlan_enabled: Optional[bool] = Field(None)
    purpose: Optional[str] = Field(None)
    ip_subnet: Optional[str] = Field(None)
    ipv6_interface_type: Optional[str] = Field(None)
    domain_name: Optional[str] = Field(None)
    is_nat: Optional[bool] = Field(None)
    dhcpd_enabled: Optional[bool] = Field(None)
    dhcpd_start: Optional[str] = Field(None)
    dhcpd_stop: Optional[str] = Field(None)
    dhcpdv6_enabled: Optional[bool] = Field(None)
    ipv6_ra_enabled: Optional[bool] = Field(None)
    networkgroup: Optional[str] = Field(None)
    dhcp_relay_enabled: Optional[bool] = Field(None)
    dhcpd_dns_enabled: Optional[bool] = Field(None)
    dhcpd_gateway_enabled: Optional[bool] = Field(None)
    dhcpd_ip_1: Optional[str] = Field(None)
    dhcpd_leasetime: Optional[int] = Field(None)
    dhcpd_time_offset_enabled: Optional[bool] = Field(None)
    dhcpguard_enabled: Optional[bool] = Field(None)
    enabled: Optional[bool] = Field(None)
    dhcpd_ip_2: Optional[str] = Field(None)
    lte_lan_enabled: Optional[bool] = Field(None)
    setting_preference: Optional[str] = Field(None)
    mdns_enabled: Optional[bool] = Field(None)
    auto_scale_enabled: Optional[bool] = Field(None)
    vlan: Optional[str] = Field(None)
    wan_networkgroup: Optional[str] = Field(None)
    wan_type: Optional[str] = Field(None)
    wan_smartq_enabled: Optional[bool] = Field(None)
    wan_smartq_up_rate: Optional[int] = Field(None)
    wan_smartq_down_rate: Optional[int] = Field(None)
    report_wan_event: Optional[bool] = Field(None)
    wan_type_v6: Optional[str] = Field(None)
    wan_load_balance_type: Optional[str] = Field(None)
    wan_load_balance_weight: Optional[int] = Field(None)
    wan_egress_qos: Optional[str] = Field(None)
    wan_provider_capabilities: Optional[dict] = Field(None)
    wan_dns_preference: Optional[str] = Field(None)


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
        return f"https://{self.host}/{path}"

    def request(self, method, url, *args, headers: dict = None, **kwargs) -> Response:
        headers = headers or dict()
        if self.x_csrf_token and method in ("PUT", "POST"):
            headers.update({"x-csrf-token": self.x_csrf_token})
        response = super().request(method, url, *args, headers=headers, **kwargs)
        dump_response(response)
        response.raise_for_status()
        token = response.headers.get("x-csrf-token")
        if token and token != self.x_csrf_token:
            self.x_csrf_token = token
        return response

    def system(self) -> SystemResponse:
        url = self.url("api/system")
        with self.get(url=url) as r:
            data = r.json()
        return SystemResponse.model_validate(data)

    def login(self) -> LoginInfo:
        url = self.url("api/auth/login")
        body = {
            "password": self.password,
            "token": "",
            "username": self.user,
            "rememberMe": False,
        }
        with self.post(url=url, json=body) as r:
            data = r.json()
            self.login_response = LoginInfo.model_validate(data)
        return self.login_response

    def stat_device(self, mac: Optional[str] = Field(None)) -> list[Device]:
        url = self.url("proxy/network/api/s/default/stat/device")
        if mac:
            url = f"{url}/{mac}"
        with self.get(url=url) as r:
            data = r.json()
        return TypeAdapter(list[Device]).validate_python(data["data"])

    def stat_device_basic(self) -> list[BasicDevice]:
        url = self.url("proxy/network/api/s/default/stat/device-basic")
        with self.get(url=url) as r:
            data = r.json()
        return TypeAdapter(list[BasicDevice]).validate_python(data["data"])

    def portconf(self) -> list[PortConf]:
        url = self.url("proxy/network/api/s/default/rest/portconf")
        with self.get(url=url) as r:
            data = r.json()
        return TypeAdapter(list[PortConf]).validate_python(data["data"])

    def networkconf(self) -> list[NetworkConf]:
        url = self.url("proxy/network/api/s/default/rest/networkconf")
        with self.get(url=url) as r:
            data = r.json()
        return TypeAdapter(list[NetworkConf]).validate_python(data["data"])

    def apply_port_overrides(
        self, device_id: str, overrides: list[PortOverride]
    ) -> Optional[Device]:
        url = self.url(f"proxy/network/api/s/default/rest/device/{device_id}")
        body = {"port_overrides": [json.loads(po.json()) for po in overrides]}
        with self.put(url=url, json=body) as r:
            data = r.json()
        device_list = data["data"]
        if not device_list:
            return None
        return Device.model_validate(device_list[0])

    def change_poe_mode(
        self, mac: str, mode: PoeMode, ports: Iterable[int]
    ) -> Optional[Device]:
        """

        :param mac:
        :param mode:
        :param ports:
        :return:
        """
        mode_enum = next((e for e in PoeMode if mode == e), None)
        if mode_enum is None:
            raise ValueError(f"invalid mode argument: {mode}")
        mode_enum: PoeMode
        self.restart()
        self.login()

        device = self.stat_device(mac=mac)[0]
        poe_ports: dict[int, Port] = {
            port.port_idx: port for port in device.port_table if port.port_poe
        }
        # determined target ports
        target_ports: dict[int, Port] = {}
        for port_idx in ports:
            if (poe_port := poe_ports.get(port_idx)) is None:
                raise KeyError(f"port {mac}:{port_idx} is not a PoE port")
            target_ports[port_idx] = poe_port

        overrides = device.override_dict
        update_required = False
        for target_port_idx, port in target_ports.items():
            if port.poe_mode == mode_enum.value:
                # port already has the correct value
                log.debug(
                    f"port {mac},{port.port_idx}, already set to {mode_enum.value}"
                )
                continue
            log.debug(f"port {mac},{port.port_idx}, update to {mode_enum.value}")

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
            return self.apply_port_overrides(
                device_id=device.id, overrides=device.port_overrides
            )
        return None
