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


from unittest import TestCase

from hpOneView.image_streamer.image_streamer_client import ImageStreamerClient


class ImageStreamerClientTest(TestCase):
    def setUp(self):
        self.host = '127.0.0.1'
        self.session_id = 'LTU1NzIzMDMxMjIxcsgLtu5d6Q_oydNqaO2oWuZz5Xj7L7cc'
        self._client = ImageStreamerClient(self.host, self.session_id, 300)

    def test_connection_has_right_host(self):
        self.assertEqual(self._client.connection.get_host(), self.host)

    def test_connection_has_right_session_id(self):
        self.assertEqual(self._client.connection.get_session_id(), self.session_id)

    def test_connection_has_session(self):
        self.assertEqual(self._client.connection.get_session(), True)
