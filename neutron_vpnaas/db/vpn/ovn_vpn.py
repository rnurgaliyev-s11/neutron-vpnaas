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

from neutron.api.v2 import attributes
from neutron import manager
from neutron.plugins.common import constants as nconstants
from neutron.plugins.common import constants as p_constants

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

    def validate_vpnservice_ovn(self, context, vpnservice):
        self._check_vpn_gateway(context, vpnservice['router_id'])

    def _validate_peer_address_ovn(self, context, ip_version, router):
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

    def resolve_peer_address_ovn(self, context, ipsec_sitecon, router):
        address = ipsec_sitecon['peer_address']
        # check if address is an ip address or fqdn
        invalid_ip_address = attributes._validate_ip_address(address)
        if invalid_ip_address:
            # resolve fqdn
            try:
                addrinfo = socket.getaddrinfo(address, None)[0]
                ipsec_sitecon['peer_address'] = addrinfo[-1][0]
            except socket.gaierror:
                raise vpnaas.VPNPeerAddressNotResolved(peer_address=address)

        ip_version = netaddr.IPAddress(ipsec_sitecon['peer_address']).version
        self._validate_peer_address_ovn(context, ip_version, router)

class VPNOVNPluginDb(vpn_db.VPNPluginDb):
    # rewrite some DB API in VPNPluginDb for OVN VPN
    def _get_validator(self):
        return OVNVpnReferenceValidator()

    def create_ipsec_site_connection_ovn(self, context, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        validator = self._get_validator()
        validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        with context.session.begin(subtransactions=True):
            #Check permissions
            vpnservice_id = ipsec_sitecon['vpnservice_id']
            self._get_resource(context, vpn_models.VPNService, vpnservice_id)
            self._get_resource(context, vpn_models.IKEPolicy,
                               ipsec_sitecon['ikepolicy_id'])
            self._get_resource(context, vpn_models.IPsecPolicy,
                               ipsec_sitecon['ipsecpolicy_id'])
            vpnservice = self._get_vpnservice(context, vpnservice_id)
            validator.validate_ipsec_conn_optional_args(ipsec_sitecon,
                                                        vpnservice.subnet)
            self.validate_connection_info(context, validator, ipsec_sitecon,
                                          vpnservice)
            validator.resolve_peer_address_ovn(context, ipsec_sitecon, vpnservice.router)

            ipsec_site_conn_db = vpn_models.IPsecSiteConnection(
                id=uuidutils.generate_uuid(),
                tenant_id=ipsec_sitecon['tenant_id'],
                name=ipsec_sitecon['name'],
                description=ipsec_sitecon['description'],
                peer_address=ipsec_sitecon['peer_address'],
                peer_id=ipsec_sitecon['peer_id'],
                local_id=ipsec_sitecon['local_id'],
                route_mode='static',
                mtu=ipsec_sitecon['mtu'],
                auth_mode='psk',
                psk=ipsec_sitecon['psk'],
                initiator=ipsec_sitecon['initiator'],
                dpd_action=ipsec_sitecon['dpd_action'],
                dpd_interval=ipsec_sitecon['dpd_interval'],
                dpd_timeout=ipsec_sitecon['dpd_timeout'],
                admin_state_up=ipsec_sitecon['admin_state_up'],
                status=p_constants.PENDING_CREATE,
                vpnservice_id=vpnservice_id,
                ikepolicy_id=ipsec_sitecon['ikepolicy_id'],
                ipsecpolicy_id=ipsec_sitecon['ipsecpolicy_id'],
                local_ep_group_id=ipsec_sitecon['local_ep_group_id'],
                peer_ep_group_id=ipsec_sitecon['peer_ep_group_id']
            )
            context.session.add(ipsec_site_conn_db)
            for cidr in ipsec_sitecon['peer_cidrs']:
                peer_cidr_db = vpn_models.IPsecPeerCidr(
                    cidr=cidr,
                    ipsec_site_connection_id=ipsec_site_conn_db['id']
                )
                context.session.add(peer_cidr_db)
        return self._make_ipsec_site_connection_dict(ipsec_site_conn_db)

    def update_ipsec_site_connection_ovn(
            self, context,
            ipsec_site_conn_id, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        changed_peer_cidrs = False
        validator = self._get_validator()
        with context.session.begin(subtransactions=True):
            ipsec_site_conn_db = self._get_resource(
                context, vpn_models.IPsecSiteConnection, ipsec_site_conn_id)
            vpnservice_id = ipsec_site_conn_db['vpnservice_id']
            vpnservice = self._get_vpnservice(context, vpnservice_id)

            validator.assign_sensible_ipsec_sitecon_defaults(
                ipsec_sitecon, ipsec_site_conn_db)
            validator.validate_ipsec_conn_optional_args(ipsec_sitecon,
                                                        vpnservice.subnet)
            self.validate_connection_info(context, validator, ipsec_sitecon,
                                          vpnservice)
            if 'peer_address' in ipsec_sitecon:
                validator.resolve_peer_address_ovn(context, ipsec_sitecon,
                                               vpnservice.router)
            self.assert_update_allowed(ipsec_site_conn_db)

            if "peer_cidrs" in ipsec_sitecon:
                changed_peer_cidrs = True
                old_peer_cidr_list = ipsec_site_conn_db['peer_cidrs']
                old_peer_cidr_dict = dict(
                    (peer_cidr['cidr'], peer_cidr)
                    for peer_cidr in old_peer_cidr_list)
                new_peer_cidr_set = set(ipsec_sitecon["peer_cidrs"])
                old_peer_cidr_set = set(old_peer_cidr_dict)

                new_peer_cidrs = list(new_peer_cidr_set)
                for peer_cidr in old_peer_cidr_set - new_peer_cidr_set:
                    context.session.delete(old_peer_cidr_dict[peer_cidr])
                for peer_cidr in new_peer_cidr_set - old_peer_cidr_set:
                    pcidr = vpn_models.IPsecPeerCidr(
                        cidr=peer_cidr,
                        ipsec_site_connection_id=ipsec_site_conn_id)
                    context.session.add(pcidr)
            # Note: Unconditionally remove peer_cidrs, as they will be set to
            # previous, if unchanged (to be able to validate above).
            del ipsec_sitecon["peer_cidrs"]
            if ipsec_sitecon:
                ipsec_site_conn_db.update(ipsec_sitecon)
        result = self._make_ipsec_site_connection_dict(ipsec_site_conn_db)
        if changed_peer_cidrs:
            result['peer_cidrs'] = new_peer_cidrs
        return result

    def create_vpnservice_ovn(self, context, vpnservice):
        vpns = vpnservice['vpnservice']
        validator = self._get_validator()
        with context.session.begin(subtransactions=True):
            validator.validate_vpnservice_ovn(context, vpns)
            vpnservice_db = vpn_models.VPNService(
                id=uuidutils.generate_uuid(),
                tenant_id=vpns['tenant_id'],
                name=vpns['name'],
                description=vpns['description'],
                subnet_id=vpns['subnet_id'],
                router_id=vpns['router_id'],
                admin_state_up=vpns['admin_state_up'],
                status=p_constants.PENDING_CREATE)
            context.session.add(vpnservice_db)
        return self._make_vpnservice_dict(vpnservice_db)
