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
This module implements a common client for HPE Image Streamer REST API.
"""


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from future import standard_library

standard_library.install_aliases()


from hpOneView.connection import connection


class ImageStreamerClient(object):
    def __init__(self, ip, session_id, api_version, sslBundle=False):
        self.__connection = connection(ip, api_version, sslBundle)
        self.__connection.set_session_id(session_id)
        self.__golden_images = None
        self.__plan_scripts = None
        self.__build_plans = None
        self.__os_volumes = None
        self.__deployment_plans = None
        self.__artifact_bundles = None
        self.__deployment_groups = None

    @property
    def connection(self):
        """
        Gets the underlying HPE Image Streamer connection used by the ImageStreamerClient.

        Returns:
            connection:
        """
        return self.__connection
