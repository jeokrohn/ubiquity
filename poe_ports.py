"""
Python module to be used as homeassistant AppDaemon app. The app monitors an entity (typically a text input),
takes the state of that entity as arguments and then executes an action accordingly. This mimics the functionality of
calling a Python method as a service from HA.
"""
import re
from dataclasses import dataclass

import appdaemon.plugins.hass.hassapi as hass

from simple_unifi import UnifiAPI


@dataclass(init=False)
class PoeManager(hass.Hass):
    # entity ID to be monitored
    args_helper: str
    # target host for Unifi API calls
    unifi_host: str
    # user to authenticate the API calls
    unifi_user: str
    # password to authenticate the API calls
    unifi_pass: str

    def initialize(self):
        def log(s: str, level: str = 'INFO'):
            self.log(f'{self.__class__.__name__}:initialize: {s}', level=level)

        # get and validate parameters
        params = ['unifi_host', 'unifi_user', 'unifi_pass', 'args_helper']
        missing = [param for param in params if not self.args.get(param)]
        if missing:
            log(f'missing parameters {", ".join(missing)}',
                level='ERROR')
            return
        # set all arguments
        self.__dict__.update(((param, self.args[param]) for param in params))

        self.log(f'listening for updates on "{self.args_helper}"')
        self.listen_state(self.parameter_change, self.args_helper)

    @staticmethod
    def parse_args(s: str) -> dict[str, str]:
        """
        Parse argument string which has a comma separated list of k=v tuples into a dict
        :param s:
        :return: dict of arguments with values
        """
        arg_parser = re.compile(r"""([^=]+) # key: sequence of characters other than "="
                                    =       # delimiter between key and value
                                    ([^=]+) # value: another sequence of characters other than "="
                                    (?:,|$) # followed by either a comma or end of string""",
                                flags=re.VERBOSE)
        # find all non-overlapping matches and put groups into dict as k,v tuples
        args = dict(arg_parser.findall(s))
        return args

    def parameter_change(self, entity, attribute, old_value, new_value: str, *args):
        """
        Callback for state change

        The state value contains parameters for the call.
        Example: mac=74:ac:b9:10:7b:8a,ports=11,12,13,14,mode=auto

        :param entity: entity id
        :param attribute: attribute that changed: 'state'
        :param old_value:
        :param new_value:
        :return:
        """

        def log(s: str, level: str = 'INFO'):
            self.log(f'parameter_change: {s}', level=level)

        log(f'parameters: entity={entity}, attribute={attribute}, old={old_value}, new={new_value}')
        # parse arguments from input string
        args = self.parse_args(new_value)
        if not args:
            log('empty args, done')
            return

        # extract mac, ports and state
        if (mac := args.get('mac')) is None:
            log('missing argument "mac"', level='ERROR')
            return

        if (port_str := args.get('ports')) is None:
            log('missing argument "ports"', level='ERROR')
            return
        # ports is a list of comma separated ints
        ports = list(map(int, port_str.split(',')))

        if (mode := args.get('mode')) is None:
            log('missing argument "mode"', level='ERROR')
            return

        if mode not in ['auto', 'off']:
            log(f'invalid parameter. Allowed: auto, off', level='ERROR')
            return

        # get API instance
        with UnifiAPI(host=self.unifi_host, user=self.unifi_user, password=self.unifi_pass, verify=False) as api:
            api.login()
            log(f'change_poe_mode(mac={mac}, mode={mode}, ports={ports})')
            api.change_poe_mode(mac=mac, mode=mode, ports=ports)
