# -*- coding: utf-8 -*-
###
# (C) Copyright [2019] Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###


"""
This module implements a common client for HPE OneView REST API.
"""


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from future import standard_library

standard_library.install_aliases()

import json
import os

from hpOneView.connection import connection
from hpOneView.image_streamer.image_streamer_client import ImageStreamerClient
from hpOneView.resources.networking.fc_networks import FcNetworks
from hpOneView.resources.networking.fcoe_networks import FcoeNetworks
from hpOneView.resources.networking.ethernet_networks import EthernetNetworks
from hpOneView.resources.networking.connection_templates import ConnectionTemplates
from hpOneView.resources.networking.switch_types import SwitchTypes
from hpOneView.resources.servers.enclosures import Enclosures
from hpOneView.resources.servers.logical_enclosures import LogicalEnclosures
from hpOneView.resources.servers.enclosure_groups import EnclosureGroups
from hpOneView.resources.servers.server_hardware import ServerHardware
from hpOneView.resources.servers.server_hardware_types import ServerHardwareTypes
from hpOneView.resources.networking.interconnect_types import InterconnectTypes
from hpOneView.resources.networking.sas_interconnect_types import SasInterconnectTypes
from hpOneView.resources.networking.internal_link_sets import InternalLinkSets
from hpOneView.resources.fc_sans.managed_sans import ManagedSANs
from hpOneView.resources.networking.logical_interconnects import LogicalInterconnects
from hpOneView.resources.networking.logical_interconnect_groups import LogicalInterconnectGroups
from hpOneView.resources.networking.sas_logical_interconnects import SasLogicalInterconnects
from hpOneView.resources.networking.logical_switch_groups import LogicalSwitchGroups
from hpOneView.resources.networking.sas_interconnects import SasInterconnects
from hpOneView.resources.servers.server_profiles import ServerProfiles
from hpOneView.resources.servers.server_profile_templates import ServerProfileTemplate
from hpOneView.resources.networking.uplink_sets import UplinkSets
from hpOneView.resources.networking.sas_logical_interconnect_groups import SasLogicalInterconnectGroups
from hpOneView.resources.uncategorized.os_deployment_plans import OsDeploymentPlans

ONEVIEW_CLIENT_INVALID_PROXY = 'Invalid Proxy format'


class OneViewClient(object):
    DEFAULT_API_VERSION = 300

    def __init__(self, config):
        self.__connection = connection(config["ip"], config.get('api_version', self.DEFAULT_API_VERSION), config.get('ssl_certificate', False),
                                       config.get('timeout'))
        self.__image_streamer_ip = config.get("image_streamer_ip")
        self.__set_proxy(config)
        self.__connection.login(config["credentials"])
        self.__connection_templates = None
        self.__fc_networks = None
        self.__fcoe_networks = None
        self.__ethernet_networks = None
        self.__switch_types = None
        self.__enclosures = None
        self.__logical_enclosures = None
        self.__enclosure_groups = None
        self.__server_hardware = None
        self.__server_hardware_types = None
        self.__interconnect_types = None
        self.__sas_interconnect_types = None
        self.__internal_link_sets = None
        self.__logical_interconnects = None
        self.__sas_logical_interconnects = None
        self.__logical_interconnect_groups = None
        self.__logical_switch_groups = None
        self.__server_profiles = None
        self.__server_profile_templates = None
        self.__uplink_sets = None
        self.__managed_sans = None
        self.__sas_interconnects = None
        self.__sas_logical_interconnect_groups = None
        self.__os_deployment_plans = None

    @classmethod
    def from_json_file(cls, file_name):
        """
        Construct OneViewClient using a json file.

        Args:
            file_name: json full path.

        Returns:
            OneViewClient:
        """
        with open(file_name) as json_data:
            config = json.load(json_data)

        return cls(config)

    @classmethod
    def from_environment_variables(cls):
        """
        Construct OneViewClient using environment variables.

        Allowed variables: ONEVIEWSDK_IP (required), ONEVIEWSDK_USERNAME (required), ONEVIEWSDK_PASSWORD (required),
        ONEVIEWSDK_AUTH_LOGIN_DOMAIN, ONEVIEWSDK_API_VERSION, ONEVIEWSDK_IMAGE_STREAMER_IP, ONEVIEWSDK_SESSIONID, ONEVIEWSDK_SSL_CERTIFICATE,
        ONEVIEWSDK_CONNECTION_TIMEOUT and ONEVIEWSDK_PROXY.

        Returns:
            OneViewClient:
        """
        ip = os.environ.get('ONEVIEWSDK_IP', '')
        image_streamer_ip = os.environ.get('ONEVIEWSDK_IMAGE_STREAMER_IP', '')
        api_version = int(os.environ.get('ONEVIEWSDK_API_VERSION', OneViewClient.DEFAULT_API_VERSION))
        ssl_certificate = os.environ.get('ONEVIEWSDK_SSL_CERTIFICATE', '')
        username = os.environ.get('ONEVIEWSDK_USERNAME', '')
        auth_login_domain = os.environ.get('ONEVIEWSDK_AUTH_LOGIN_DOMAIN', '')
        password = os.environ.get('ONEVIEWSDK_PASSWORD', '')
        proxy = os.environ.get('ONEVIEWSDK_PROXY', '')
        sessionID = os.environ.get('ONEVIEWSDK_SESSIONID', '')
        timeout = os.environ.get('ONEVIEWSDK_CONNECTION_TIMEOUT')

        config = dict(ip=ip,
                      image_streamer_ip=image_streamer_ip,
                      api_version=api_version,
                      ssl_certificate=ssl_certificate,
                      credentials=dict(userName=username, authLoginDomain=auth_login_domain, password=password, sessionID=sessionID),
                      proxy=proxy, timeout=timeout)

        return cls(config)

    def __set_proxy(self, config):
        """
        Set proxy if needed
        Args:
            config: Config dict
        """
        if "proxy" in config and config["proxy"]:
            proxy = config["proxy"]
            splitted = proxy.split(':')
            if len(splitted) != 2:
                raise ValueError(ONEVIEW_CLIENT_INVALID_PROXY)

            proxy_host = splitted[0]
            proxy_port = int(splitted[1])
            self.__connection.set_proxy(proxy_host, proxy_port)

    @property
    def api_version(self):
        """
        Gets the OneView API Version.

        Returns:
            int: API Version.
        """
        return self.__connection._apiVersion

    @property
    def connection(self):
        """
        Gets the underlying HPE OneView connection used by the OneViewClient.

        Returns:
            connection:
        """
        return self.__connection

    def create_image_streamer_client(self):
        """
        Create the Image Streamer API Client.

        Returns:
            ImageStreamerClient:
        """
        image_streamer = ImageStreamerClient(self.__image_streamer_ip,
                                             self.__connection.get_session_id(),
                                             self.__connection._apiVersion,
                                             self.__connection._sslBundle)

        return image_streamer

    @property
    def connection_templates(self):
        """
        Gets the ConnectionTemplates API client.

        Returns:
            ConnectionTemplates:
        """
        return ConnectionTemplates(self.__connection)

    @property
    def fc_networks(self):
        """
        Gets the FcNetworks API client.

        Returns:
            FcNetworks:
        """
        return FcNetworks(self.__connection)

    @property
    def fcoe_networks(self):
        """
        Gets the FcoeNetworks API client.

        Returns:
            FcoeNetworks:
        """
        return FcoeNetworks(self.__connection)

    @property
    def ethernet_networks(self):
        """
        Gets the EthernetNetworks API client.

        Returns:
            EthernetNetworks:
        """
        return EthernetNetworks(self.__connection)

    @property
    def server_hardware(self):
        """
        Gets the ServerHardware API client.

        Returns:
            ServerHardware:
        """
        return ServerHardware(self.__connection)

    @property
    def server_hardware_types(self):
        """
        Gets the ServerHardwareTypes API client.

        Returns:
            ServerHardwareTypes:
        """
        return ServerHardwareTypes(self.__connection)

    @property
    def switch_types(self):
        """
        Gets the SwitchTypes API client.

        Returns:
            SwitchTypes:
        """
        return SwitchTypes(self.__connection)

    @property
    def logical_switch_groups(self):
        """
        Gets the LogicalSwitchGroups API client.

        Returns:
            LogicalSwitchGroups:
        """
        return LogicalSwitchGroups(self.__connection)

    @property
    def enclosure_groups(self):
        """
        Gets the EnclosureGroups API client.

        Returns:
            EnclosureGroups:
        """
        return EnclosureGroups(self.__connection)

    @property
    def enclosures(self):
        """
        Gets the Enclosures API client.

        Returns:
            Enclosures:
        """
        return Enclosures(self.__connection)

    @property
    def logical_enclosures(self):
        """
        Gets the LogicalEnclosures API client.

        Returns:
            LogicalEnclosures:
        """
        return LogicalEnclosures(self.__connection)

    @property
    def interconnect_types(self):
        """
        Gets the InterconnectTypes API client.

        Returns:
            InterconnectTypes:
        """
        return InterconnectTypes(self.__connection)

    @property
    def sas_interconnect_types(self):
        """
        Gets the SasInterconnectTypes API client.

        Returns:
            SasInterconnectTypes:
        """
        return SasInterconnectTypes(self.__connection)

    @property
    def internal_link_sets(self):
        """
        Gets the InternalLinkSets API client.

        Returns:
            InternalLinkSets:
        """
        return InternalLinkSets(self.__connection)

    @property
    def logical_interconnect_groups(self):
        """
        Gets the LogicalInterconnectGroups API client.

        Returns:
            LogicalInterconnectGroups:
        """
        return LogicalInterconnectGroups(self.__connection)

    @property
    def logical_interconnects(self):
        """
        Gets the LogicalInterconnects API client.

        Returns:
            LogicalInterconnects:
        """
        return LogicalInterconnects(self.__connection)

    @property
    def sas_logical_interconnects(self):
        """
        Gets the SasLogicalInterconnects API client.

        Returns:
            SasLogicalInterconnects:
        """
        return SasLogicalInterconnects(self.__connection)

    @property
    def server_profiles(self):
        """
        Gets the ServerProfiles API client.

        Returns:
            ServerProfiles:
        """
        return ServerProfiles(self.__connection)

    @property
    def server_profile_templates(self):
        """
        Gets the ServerProfileTemplate API client.

        Returns:
            ServerProfileTemplate:
        """
        return ServerProfileTemplate(self.__connection)

    @property
    def uplink_sets(self):
        """
        Gets the UplinkSets API client.

        Returns:
            UplinkSets:
        """
        return UplinkSets(self.__connection)

    @property
    def managed_sans(self):
        """
        Gets the Managed SANs API client.

        Returns:
            ManagedSANs:
        """
        return ManagedSANs(self.__connection)

    @property
    def sas_interconnects(self):
        """
        Gets the SAS Interconnects API client.

        Returns:
            SasInterconnects:
        """
        return SasInterconnects(self.__connection)

    @property
    def sas_logical_interconnect_groups(self):
        """
        Gets the SasLogicalInterconnectGroups API client.

        Returns:
            SasLogicalInterconnectGroups:
        """
        return SasLogicalInterconnectGroups(self.__connection)

    @property
    def os_deployment_plans(self):
        """
        Gets the Os Deployment Plans API client.

        Returns:
            OsDeploymentPlans:
        """
        return OsDeploymentPlans(self.__connection)
