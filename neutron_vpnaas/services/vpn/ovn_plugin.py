#    (c) Copyright 2016 IBM Corporation
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from neutron_vpnaas.db.vpn.vpn_db import VPNPluginDb

from neutron_vpnaas.db.vpn import vpn_ext_gw_db
from neutron_vpnaas.services.vpn.plugin import VPNDriverPlugin


class VPNOVNPlugin(VPNPluginDb, vpn_ext_gw_db.VPNExtGWPlugin_db):
    """Implementation of the VPN Service Plugin.

    This class manages the workflow of VPNaaS request/response.
    Most DB related works are implemented in class
    vpn_db.VPNPluginDb.
    """

    def check_router_in_use(self, context, router_id):
        pass

    supported_extension_aliases = ["vpnaas",
                                   "vpn-endpoint-groups",
                                   "service-type",
                                   "vpn-ext-gw"]
    path_prefix = "/vpn"


class VPNOVNDriverPlugin(VPNOVNPlugin, VPNDriverPlugin):
    pass
