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


import io
import unittest
import mock

from hpOneView.connection import connection
from hpOneView.oneview_client import OneViewClient
from hpOneView.resources.fc_sans.managed_sans import ManagedSANs
from hpOneView.resources.networking.fc_networks import FcNetworks
from hpOneView.resources.networking.fcoe_networks import FcoeNetworks
from hpOneView.resources.networking.logical_interconnect_groups import LogicalInterconnectGroups
from hpOneView.resources.networking.logical_interconnects import LogicalInterconnects
from hpOneView.resources.networking.logical_switch_groups import LogicalSwitchGroups
from hpOneView.resources.networking.uplink_sets import UplinkSets
from hpOneView.resources.networking.sas_interconnects import SasInterconnects
from hpOneView.resources.networking.sas_logical_interconnect_groups import SasLogicalInterconnectGroups
from hpOneView.resources.networking.sas_logical_interconnects import SasLogicalInterconnects
from hpOneView.resources.networking.sas_interconnect_types import SasInterconnectTypes
from hpOneView.resources.servers.server_profile_templates import ServerProfileTemplate
from hpOneView.resources.servers.server_profiles import ServerProfiles
from hpOneView.resources.networking.internal_link_sets import InternalLinkSets
from hpOneView.resources.uncategorized.os_deployment_plans import OsDeploymentPlans
from tests.test_utils import mock_builtin

OS_ENVIRON_CONFIG_MINIMAL = {
    'ONEVIEWSDK_IP': '172.16.100.199',
    'ONEVIEWSDK_USERNAME': 'admin',
    'ONEVIEWSDK_PASSWORD': 'secret123'
}

OS_ENVIRON_CONFIG_MINIMAL_WITH_SESSIONID = {
    'ONEVIEWSDK_IP': '172.16.100.199',
    'ONEVIEWSDK_SESSIONID': '123'
}

OS_ENVIRON_CONFIG_FULL = {
    'ONEVIEWSDK_IP': '172.16.100.199',
    'ONEVIEWSDK_IMAGE_STREAMER_IP': '172.172.172.172',
    'ONEVIEWSDK_USERNAME': 'admin',
    'ONEVIEWSDK_PASSWORD': 'secret123',
    'ONEVIEWSDK_API_VERSION': '201',
    'ONEVIEWSDK_AUTH_LOGIN_DOMAIN': 'authdomain',
    'ONEVIEWSDK_PROXY': '172.16.100.195:9999',
    'ONEVIEWSDK_CONNECTION_TIMEOUT': '20'
}

OS_ENVIRON_CONFIG_FULL_WITH_SESSIONID = {
    'ONEVIEWSDK_IP': '172.16.100.199',
    'ONEVIEWSDK_IMAGE_STREAMER_IP': '172.172.172.172',
    'ONEVIEWSDK_USERNAME': 'admin',
    'ONEVIEWSDK_PASSWORD': 'secret123',
    'ONEVIEWSDK_SESSIONID': '123',
    'ONEVIEWSDK_API_VERSION': '201',
    'ONEVIEWSDK_PROXY': '172.16.100.195:9999',
    'ONEVIEWSDK_CONNECTION_TIMEOUT': '20'

}


class OneViewClientTest(unittest.TestCase):
    def __mock_file_open(self, json_config_content):
        # Simulates a TextIOWrapper (file output)
        return io.StringIO(json_config_content)

    @mock.patch.object(connection, 'login')
    def setUp(self, mock_login):
        super(OneViewClientTest, self).setUp()

        config = {"ip": "172.16.102.59",
                  "proxy": "127.0.0.1:3128",
                  "credentials": {
                      "authLoginDomain": "",
                      "userName": "administrator",
                      "password": ""}}

        self._oneview = OneViewClient(config)

    def test_raise_error_invalid_proxy(self):
        config = {"ip": "172.16.102.59",
                  "proxy": "3128",
                  "credentials": {
                      "authLoginDomain": "",
                      "userName": "administrator",
                      "password": ""}}

        try:
            OneViewClient(config)
        except ValueError as e:
            self.assertTrue("Proxy" in e.args[0])
        else:
            self.fail()

    @mock.patch.object(connection, 'login')
    @mock.patch(mock_builtin('open'))
    def test_from_json_file(self, mock_open, mock_login):
        json_config_content = u"""{
          "ip": "172.16.102.59",
          "credentials": {
            "userName": "administrator",
            "authLoginDomain": "",
            "password": ""
          }
        }"""
        mock_open.return_value = self.__mock_file_open(json_config_content)
        oneview_client = OneViewClient.from_json_file("config.json")

        self.assertIsInstance(oneview_client, OneViewClient)
        self.assertEqual("172.16.102.59", oneview_client.connection.get_host())

    @mock.patch.object(connection, 'login')
    @mock.patch(mock_builtin('open'))
    def test_from_json_file_with_sessionID(self, mock_open, mock_login):
        json_config_content = u"""{
          "ip": "172.16.102.59",
          "credentials": {
            "userName": "administrator",
            "authLoginDomain": "",
            "password": "",
            "sessionID": "123"
          }
        }"""
        mock_open.return_value = self.__mock_file_open(json_config_content)
        oneview_client = OneViewClient.from_json_file("config.json")

        self.assertIsInstance(oneview_client, OneViewClient)
        self.assertEqual("172.16.102.59", oneview_client.connection.get_host())

    @mock.patch.object(connection, 'login')
    @mock.patch(mock_builtin('open'))
    def test_from_json_file_with_only_sessionID(self, mock_open, mock_login):
        json_config_content = u"""{
          "ip": "172.16.102.59",
          "credentials": {
            "sessionID": "123"
          }
        }"""
        mock_open.return_value = self.__mock_file_open(json_config_content)
        oneview_client = OneViewClient.from_json_file("config.json")

        self.assertIsInstance(oneview_client, OneViewClient)
        self.assertEqual("172.16.102.59", oneview_client.connection.get_host())

    @mock.patch.object(connection, 'login')
    @mock.patch(mock_builtin('open'))
    def test_default_api_version(self, mock_open, mock_login):
        json_config_content = u"""{
          "ip": "172.16.102.59",
          "credentials": {
            "userName": "administrator",
            "authLoginDomain": "",
            "password": ""
          }
        }"""
        mock_open.return_value = self.__mock_file_open(json_config_content)
        oneview_client = OneViewClient.from_json_file("config.json")

        self.assertEqual(300, oneview_client.connection._apiVersion)
        self.assertEqual(300, oneview_client.api_version)

    @mock.patch.object(connection, 'login')
    @mock.patch(mock_builtin('open'))
    def test_configured_api_version(self, mock_open, mock_login):
        json_config_content = u"""{
          "ip": "172.16.102.59",
          "api_version": 200,
          "credentials": {
            "userName": "administrator",
            "authLoginDomain": "",
            "password": ""
          }
        }"""
        mock_open.return_value = self.__mock_file_open(json_config_content)
        oneview_client = OneViewClient.from_json_file("config.json")

        self.assertEqual(200, oneview_client.connection._apiVersion)
        self.assertEqual(200, oneview_client.api_version)

    @mock.patch.object(connection, 'login')
    @mock.patch.object(connection, 'set_proxy')
    @mock.patch.dict('os.environ', OS_ENVIRON_CONFIG_MINIMAL)
    def test_from_minimal_environment_variables(self, mock_set_proxy, mock_login):
        oneview_client = OneViewClient.from_environment_variables()

        mock_login.assert_called_once_with(dict(userName='admin',
                                                password='secret123',
                                                authLoginDomain='',
                                                sessionID=''))
        mock_set_proxy.assert_not_called()
        self.assertEqual(300, oneview_client.connection._apiVersion)

    @mock.patch.object(connection, 'login')
    @mock.patch.object(connection, 'set_proxy')
    @mock.patch.dict('os.environ', OS_ENVIRON_CONFIG_MINIMAL_WITH_SESSIONID)
    def test_from_minimal_environment_variables_with_sessionID(self, mock_set_proxy, mock_login):
        oneview_client = OneViewClient.from_environment_variables()

        mock_login.assert_called_once_with(dict(userName='',
                                                password='',
                                                authLoginDomain='',
                                                sessionID='123'))
        mock_set_proxy.assert_not_called()
        self.assertEqual(300, oneview_client.connection._apiVersion)

    @mock.patch.object(connection, 'login')
    @mock.patch.object(connection, 'set_proxy')
    @mock.patch.dict('os.environ', OS_ENVIRON_CONFIG_FULL)
    def test_from_full_environment_variables(self, mock_set_proxy, mock_login):
        oneview_client = OneViewClient.from_environment_variables()

        mock_login.assert_called_once_with(dict(userName='admin',
                                                password='secret123',
                                                authLoginDomain='authdomain',
                                                sessionID=''))
        mock_set_proxy.assert_called_once_with('172.16.100.195', 9999)

        self.assertEqual(201, oneview_client.connection._apiVersion)
        self.assertEqual(oneview_client.create_image_streamer_client().connection.get_host(),
                         OS_ENVIRON_CONFIG_FULL['ONEVIEWSDK_IMAGE_STREAMER_IP'])

    @mock.patch.object(connection, 'login')
    @mock.patch.object(connection, 'set_proxy')
    @mock.patch.dict('os.environ', OS_ENVIRON_CONFIG_FULL_WITH_SESSIONID)
    def test_from_full_environment_variables_with_sessionID(self, mock_set_proxy, mock_login):
        oneview_client = OneViewClient.from_environment_variables()

        mock_login.assert_called_once_with(dict(userName='admin',
                                                password='secret123',
                                                authLoginDomain='',
                                                sessionID='123'))
        mock_set_proxy.assert_called_once_with('172.16.100.195', 9999)

        self.assertEqual(201, oneview_client.connection._apiVersion)
        self.assertEqual(oneview_client.create_image_streamer_client().connection.get_host(),
                         OS_ENVIRON_CONFIG_FULL_WITH_SESSIONID['ONEVIEWSDK_IMAGE_STREAMER_IP'])

    @mock.patch.dict('os.environ', OS_ENVIRON_CONFIG_FULL)
    @mock.patch.object(OneViewClient, '__init__')
    def test_from_environment_variables_is_passing_right_arguments_to_the_constructor(self, mock_cls):
        mock_cls.return_value = None
        OneViewClient.from_environment_variables()
        mock_cls.assert_called_once_with({'api_version': 201,
                                          'proxy': '172.16.100.195:9999',
                                          'timeout': '20',
                                          'ip': '172.16.100.199',
                                          'ssl_certificate': '',
                                          'image_streamer_ip': '172.172.172.172',
                                          'credentials':
                                              {'userName': 'admin',
                                               'password': 'secret123',
                                               'authLoginDomain': 'authdomain',
                                               'sessionID': ''}})

    @mock.patch.dict('os.environ', OS_ENVIRON_CONFIG_FULL_WITH_SESSIONID)
    @mock.patch.object(OneViewClient, '__init__')
    def test_from_environment_variables_is_passing_right_arguments_to_the_constructor_with_sessionID(self, mock_cls):
        mock_cls.return_value = None
        OneViewClient.from_environment_variables()
        mock_cls.assert_called_once_with({'api_version': 201,
                                          'proxy': '172.16.100.195:9999',
                                          'timeout': '20',
                                          'ip': '172.16.100.199',
                                          'image_streamer_ip': '172.172.172.172',
                                          'ssl_certificate': '',
                                          'credentials':
                                              {'userName': 'admin',
                                               'password': 'secret123',
                                               'authLoginDomain': '',
                                               'sessionID': '123'}})

    @mock.patch.dict('os.environ', OS_ENVIRON_CONFIG_MINIMAL_WITH_SESSIONID)
    @mock.patch.object(OneViewClient, '__init__')
    def test_from_environment_variables_is_passing_right_arguments_to_the_constructor_with_only_sessionID(self, mock_cls):
        mock_cls.return_value = None
        OneViewClient.from_environment_variables()
        mock_cls.assert_called_once_with({'api_version': 300,
                                          'proxy': '',
                                          'timeout': None,
                                          'ip': '172.16.100.199',
                                          'image_streamer_ip': '',
                                          'ssl_certificate': '',
                                          'credentials':
                                              {'userName': '',
                                               'password': '',
                                               'authLoginDomain': '',
                                               'sessionID': '123'}})

    @mock.patch.object(connection, 'login')
    def test_create_image_streamer_client_without_image_streamer_ip(self, mock_login):

        config = {"ip": "172.16.102.59",
                  "credentials": {
                      "userName": "administrator",
                      "password": "password"}}

        client = OneViewClient(config)
        client.connection.set_session_id('123')

        i3s = client.create_image_streamer_client()

        self.assertEqual(i3s.connection.get_session_id(), client.connection.get_session_id())
        self.assertEqual(i3s.connection._apiVersion, client.api_version)
        self.assertEqual(i3s.connection.get_host(), None)
        self.assertEqual(client.connection.get_host(), "172.16.102.59")

    @mock.patch.object(connection, 'login')
    def test_create_image_streamer_client_with_image_streamer_ip(self, mock_login):

        config = {"ip": "172.16.102.59",
                  "image_streamer_ip": "172.16.102.50",
                  "credentials": {
                      "userName": "administrator",
                      "password": "password"}}

        client = OneViewClient(config)
        client.connection.set_session_id('124')

        i3s = client.create_image_streamer_client()

        self.assertEqual(i3s.connection.get_session_id(), client.connection.get_session_id())
        self.assertEqual(i3s.connection._apiVersion, client.api_version)
        self.assertEqual(i3s.connection.get_host(), "172.16.102.50")
        self.assertEqual(client.connection.get_host(), "172.16.102.59")

    def test_fc_networks_has_right_type(self):
        self.assertIsInstance(self._oneview.fc_networks, FcNetworks)

    def test_fc_networks_has_value(self):
        self.assertIsNotNone(self._oneview.fc_networks)

    def test_connection_type(self):
        self.assertIsInstance(self._oneview.connection, connection)

    def test_fcoe_networks_has_right_type(self):
        self.assertIsInstance(self._oneview.fcoe_networks, FcoeNetworks)

    def test_fcoe_networks_has_value(self):
        self.assertIsNotNone(self._oneview.fcoe_networks)

    def test_should_return_new_fcoe_networks_obj(self):
        fcn = self._oneview.fcoe_networks
        self.assertNotEqual(fcn, self._oneview.fcoe_networks)

    def test_should_return_new_enclosure_groups_obj(self):
        enclosure_groups = self._oneview.enclosure_groups
        self.assertNotEqual(enclosure_groups, self._oneview.enclosure_groups)

    def test_should_return_new_connection_templates_obj(self):
        self.assertNotEqual(self._oneview.connection_templates, self._oneview.connection_templates)

    def test_should_return_new_switch_types_obj(self):
        switch_types = self._oneview.switch_types
        self.assertNotEqual(switch_types, self._oneview.switch_types)

    def test_should_return_new_ethernet_networks_obj(self):
        self.assertNotEqual(self._oneview.ethernet_networks, self._oneview.ethernet_networks)

    def test_should_return_new_server_hardware_obj(self):
        server_hardware = self._oneview.server_hardware
        self.assertNotEqual(server_hardware, self._oneview.server_hardware)

    def test_sas_interconnect_types_has_right_type(self):
        self.assertIsInstance(self._oneview.sas_interconnect_types, SasInterconnectTypes)

    def test_should_return_new_sas_interconnect_types_obj(self):
        sas_interconnect_types = self._oneview.sas_interconnect_types
        self.assertNotEqual(sas_interconnect_types, self._oneview.sas_interconnect_types)

    def test_should_return_new_server_hardware_types_obj(self):
        server_hardware_types = self._oneview.server_hardware_types
        self.assertNotEqual(server_hardware_types, self._oneview.server_hardware_types)

    def test_should_return_new_logical_enclosures_obj(self):
        logical_enclosures = self._oneview.logical_enclosures
        self.assertNotEqual(logical_enclosures, self._oneview.logical_enclosures)

    def test_should_return_new_interconnect_types_obj(self):
        self.assertNotEqual(self._oneview.interconnect_types, self._oneview.interconnect_types)

    def test_logical_interconnect_groups_has_right_type(self):
        self.assertIsInstance(self._oneview.logical_interconnect_groups, LogicalInterconnectGroups)

    def test_logical_interconnect_groups_has_value(self):
        self.assertIsNotNone(self._oneview.logical_interconnect_groups)

    def test_should_return_new_logical_interconnect_groups_obj(self):
        logical_interconnect_groups = self._oneview.logical_interconnect_groups
        self.assertNotEqual(logical_interconnect_groups, self._oneview.logical_interconnect_groups)

    def test_logical_switch_groups_has_right_type(self):
        self.assertIsInstance(self._oneview.logical_switch_groups, LogicalSwitchGroups)

    def test_logical_switch_groups_has_value(self):
        self.assertIsNotNone(self._oneview.logical_switch_groups)

    def test_logical_switch_groups_return(self):
        self.assertNotEqual(self._oneview.logical_switch_groups,
                            self._oneview.logical_switch_groups)

    def test_logical_interconnects_has_right_type(self):
        self.assertIsInstance(self._oneview.logical_interconnects, LogicalInterconnects)

    def test_logical_interconnects_has_value(self):
        self.assertIsNotNone(self._oneview.logical_interconnects)

    def test_logical_interconnects_return(self):
        self.assertNotEqual(self._oneview.logical_interconnects,
                            self._oneview.logical_interconnects)

    def test_sas_logical_interconnects_has_right_type(self):
        self.assertIsInstance(self._oneview.sas_logical_interconnects, SasLogicalInterconnects)

    def test_should_return_new_sas_logical_interconnects_obj(self):
        sas_logical_interconnects = self._oneview.sas_logical_interconnects
        self.assertNotEqual(sas_logical_interconnects, self._oneview.sas_logical_interconnects)

    def test_should_return_new_uplink_sets_obj(self):
        self.assertNotEqual(self._oneview.uplink_sets, self._oneview.uplink_sets)

    def test_uplink_sets_has_right_type(self):
        self.assertIsInstance(self._oneview.uplink_sets, UplinkSets)

    def test_uplink_sets_has_value(self):
        self.assertIsNotNone(self._oneview.uplink_sets)

    def test_sas_logical_interconnect_groups_has_right_type(self):
        self.assertIsInstance(self._oneview.sas_logical_interconnect_groups, SasLogicalInterconnectGroups)

    def test_should_return_newsas_logical_interconnect_groups_obj(self):
        sas_logical_interconnect_groups = self._oneview.sas_logical_interconnect_groups
        self.assertNotEqual(sas_logical_interconnect_groups, self._oneview.sas_logical_interconnect_groups)

    def test_server_profile_templates_has_right_type(self):
        self.assertIsInstance(self._oneview.server_profile_templates, ServerProfileTemplate)

    def test_server_profile_templates_has_value(self):
        self.assertIsNotNone(self._oneview.server_profile_templates)

    def test_server_profile_templates_return(self):
        self.assertNotEqual(self._oneview.server_profile_templates,
                            self._oneview.server_profile_templates)

    def test_server_profiles_has_right_type(self):
        self.assertIsInstance(self._oneview.server_profiles, ServerProfiles)

    def test_server_profiles_has_value(self):
        self.assertIsNotNone(self._oneview.server_profiles)

    def test_server_profiles_return(self):
        self.assertNotEqual(self._oneview.server_profiles,
                            self._oneview.server_profiles)

    def test_managed_sans_has_right_type(self):
        self.assertIsInstance(self._oneview.managed_sans, ManagedSANs)

    def test_should_return_new_managed_sans_obj(self):
        managed_sans = self._oneview.managed_sans
        self.assertNotEqual(managed_sans, self._oneview.managed_sans)

    def test_sas_interconnects_has_right_type(self):
        self.assertIsInstance(self._oneview.sas_interconnects, SasInterconnects)

    def test_should_return_new_sas_interconnects(self):
        sas_interconnects = self._oneview.sas_interconnects
        self.assertNotEqual(sas_interconnects, self._oneview.sas_interconnects)

    def test_internal_link_sets_has_right_type(self):
        self.assertIsInstance(self._oneview.internal_link_sets, InternalLinkSets)

    def test_should_return_new_internal_link_sets_obj(self):
        internal_links = self._oneview.internal_link_sets
        self.assertNotEqual(internal_links, self._oneview.internal_link_sets)

    def test_os_deployment_plans_has_right_type(self):
        self.assertIsInstance(self._oneview.os_deployment_plans, OsDeploymentPlans)

    def test_os_deployment_plans_return(self):
        self.assertNotEqual(self._oneview.os_deployment_plans,
                            self._oneview.os_deployment_plans)
