#    (c) Copyright 2016 IBM Corporation, All Rights Reserved.
# All Rights Reserved.
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
import netaddr
import socket

from neutron import context as nctx
from neutron import manager
from neutron.plugins.common import constants as nconstants
from neutron.plugins.common import constants as p_constants
from neutron_lib.api import validators

from neutron_vpnaas._i18n import _LI
from neutron_vpnaas.db.vpn import vpn_db
from neutron_vpnaas.db.vpn import vpn_ext_gw_db
from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.db.vpn import vpn_validator

from neutron_vpnaas.extensions import vpnaas

from oslo_utils import uuidutils


class OVNVpnReferenceValidator(vpn_validator.VpnReferenceValidator):
    # rewrite some verification API for vpn gw of OVN VPN

    @property
    def vpn_plugin(self):
        try:
            return self._vpn_plugin
        except AttributeError:
            self._vpn_plugin = manager.NeutronManager.get_service_plugins().get(
                nconstants.VPN)
            return self._vpn_plugin

    def _check_vpn_gateway(self, context, router_id):
        gateway = self.vpn_plugin.get_vpn_gw_dict_by_router_id(
            context, router_id)
        if gateway is None or gateway['external_fixed_ips'] is None:
            raise vpn_ext_gw_db.RouterIsNotVPNExternal(router_id=router_id)

    def validate_vpnservice(self, context, vpnservice):
        self._check_vpn_gateway(context, vpnservice['router_id'])

    def _validate_peer_address(self, ip_version, router):
        context = nctx.get_admin_context()
        gateway = self.vpn_plugin.get_vpn_gw_dict_by_router_id(
            context, router['id'])
        if gateway is None or gateway['external_fixed_ips'] is None:
            raise vpn_ext_gw_db.RouterIsNotVPNExternal(router_id=router.id)

        for fixed_ip in gateway['external_fixed_ips']:
            addr = fixed_ip['ip_address']
            if ip_version == netaddr.IPAddress(addr).version:
                return

        raise vpnaas.ExternalNetworkHasNoSubnet(
            router_id=router.id,
            ip_version='IPv6' if ip_version ==6 else "IPv4")

    def resolve_peer_address(self, ipsec_sitecon, router):
        address = ipsec_sitecon['peer_address']
        # check if address is an ip address or fqdn
        invalid_ip_address = validators.validate_ip_address(address)
        if invalid_ip_address:
            # resolve fqdn
            try:
                addrinfo = socket.getaddrinfo(address, None)[0]
                ipsec_sitecon['peer_address'] = addrinfo[-1][0]
            except socket.gaierror:
                raise vpnaas.VPNPeerAddressNotResolved(peer_address=address)

        ip_version = netaddr.IPAddress(ipsec_sitecon['peer_address']).version
        self._validate_peer_address(ip_version, router)

class VPNOVNPluginDb(vpn_db.VPNPluginDb):
    # rewrite some DB API in VPNPluginDb for OVN VPN
    def _get_validator(self):
        return OVNVpnReferenceValidator()
