import re
import traceback

from netaddr import IPAddress, IPNetwork
from socket import gethostbyaddr


class FilterModule(object):

    def hostname(self, hostname):
        """ Returns short hostname from given hostname or FQDN

        :param hostname: str The hostname or FQDN to shorten
        :return: str
        """
        return hostname.split('.', 1)[0]

    def normalise_iface(self, iface):
        """ Normalise interface names to the short form

        :param iface: str|list Name(s) of the interface to normalise
        :return: str Normalised interface name
        """
        pattern = r'^(Et|Gi|Lo|Po|po|Te|Vl)(?:[a-zA-Z-]*)(\d.*)$'
        if type(iface) == list:
            return [re.sub(pattern, r'\1\2', i, re.IGNORECASE).capitalize() for i in iface]
        else:
            return re.sub(pattern, r'\1\2', iface, re.IGNORECASE).capitalize()

    def normalise_address(self, address):
        """ Normalise ip addresses to drop cidr prefix for /32

        :param iface: str|list IP address(es) to normalise
        :return: str Normalised IP address
        """
        pattern = r'^(.*?)(\/32)?$'
        if type(address) == list:
            return [re.sub(pattern, r'\1', i, re.IGNORECASE) for i in address]
        else:
            return re.sub(pattern, r'\1', address, re.IGNORECASE)

    def has_mroutes(self, value):
        """ Checkes whether the given mroutes is valid or not

        :param value: The mroute object to check
        :return: bool
        """
        if not value:
            return False

        if len(value) == 1 and type(value[0]) != dict:
            return False

        return True

    def has_rp(self, value):
        """ Checkes whether the given RP is valid or not

        :param value: The RP object to check
        :return: bool
        """
        if not value:
            return False

        if len(value) == 1 and type(value[0]) != dict:
            return False

        return True

    def has_snooping(self, value):
        """ Checkes whether the given snooping data is valid or not

        :param value: The snooping data to check
        :return: bool
        """
        if not value:
            return False

        if len(value) == 1 and type(value[0]) != dict:
            return False

        return True

    def get_rp_address(self, value):
        """ Retrieves the RP IP address from a host's 'rp' report section

        :param value: A list of RP or RP hash entries
        :return: The IP address of the RP
        """
        try:
            if len(value) < 1:
                return None

            # Deal with the Arista EOS rp-hash case
            if 'selected_rp' in value[0]:
                return value[0]['selected_rp']

            # Standard case, list of potential RPs
            rps = sorted(value, key=lambda k: k['priority'])
            if 'rp' in rps[0]:
                return rps[0]['rp']
            else:
                return None
        except Exception:
            traceback.print_exc()

    def is_rp(self, rp, interfaces):
        """ Returns true if the given RP is listed in any of the interfaces

        :param rp: str|None The RP to check for
        :param interfaces: list List of interfaces to check against
        :return: bool
        """

        if not rp or not interfaces:
            return False

        for interface in interfaces:
            if interface['ip_address'] and interface['ip_address'].split('/')[0] == rp:
                return True

        return False

    def get_mroute_neighbours(self, mroute, neighbours, direction='in'):
        """ Retrieves the LLDP neighbour information for an mroute incoming interface from the given neighbour list

        :param mroute: The mroute object to find the neighbour for
        :param neighbours: The neighbour list for the host to search in
        :param direction: Whether the neighbour being sought is incoming or outgoing
        :return: The found neighbor, or None
        """
        results = []

        # Not parsed correctly, or not matched
        if type(mroute) == str:
            return []

        if not mroute or not neighbours:
            return []

        field = 'incoming_iface' if direction == 'in' else 'outgoing_iface'

        candidate_interface_names = set(self.normalise_iface([mroute[field]] if direction == 'in' else mroute[field]))

        # Find neighbours based on LLDP links between physical L3 interfaces
        for neighbour in neighbours:
            if self.normalise_iface(neighbour['local_interface']) in candidate_interface_names:
                    results.append(neighbour)

        return results

    def get_l2_neighbours(self, host, mroute, direction, report):
        """ Retrives the list of L2 neighbours based on matching Vlans between switches

        This isn't a perfect model of the real network, but it's as close as we can get with data available

        :param host: str Hostname for the current host
        :param mroute: Mroute to look for matches on
        :param direction: Whether to look for matches on inbound or outbound interfaces for this mroute
        :param report: Full report object
        :return: list List of neighbours for this L2 interface
        """
        results = []

        # Not parsed correctly, or not matched
        if type(mroute) == str:
            return []

        field = 'incoming_iface' if direction == 'in' else 'outgoing_iface'
        candidate_interface_names = set(
            filter(
                lambda x: re.match(r'^Vl', x, re.IGNORECASE),
                self.normalise_iface([mroute[field]] if direction == 'in' else mroute[field])))

        for neighbour_host in report:
            if host == neighbour_host or neighbour_host == '_meta':
                continue

            try:
                for remote_interface in report[neighbour_host]['interfaces']:
                    if self.normalise_iface(remote_interface['interface']) in candidate_interface_names:
                        # Found a potential L2 relationship
                        # Could potentially filter this out based on matching L3 info, if we see false positives
                        results.append({
                            'local_interface': remote_interface['interface'],  # matches the local interface name by definition
                            'neighbor': neighbour_host,
                            'neighbor_interface': remote_interface['interface'],
                        })
            except Exception:
                print("Failed matching up l2 interfaces between {} and {}".format(host, neighbour_host))
                traceback.print_exc()

        return results

    def get_portchannel_neighbours(self, host, mroute, neighbours, port_channels, direction, report):
        """ Retrieves the list of PortChannel neighbours between switches

        :param host: str Hostname for the current host
        :param mroute: Mroute to look for matches on
        :param port_channels: Portchannel list to look for matches in
        :param direction: Whether to look for matches on inbound or outbound interfaces for this mroute
        :param report: Full report object
        :return: list List of neighbours for this L2 interface
        """
        results = []

        # Not parsed correctly, or not matched
        if type(mroute) == str:
            return []

        field = 'incoming_iface' if direction == 'in' else 'outgoing_iface'

        port_channel_names = filter(
            lambda x: re.match(r'^Po', x, re.IGNORECASE),
            self.normalise_iface([mroute[field]] if direction == 'in' else mroute[field]))

        for port_channel_name in port_channel_names:
            # Find the physical interfaces for this portchannel
            for port_channel in port_channels:
                if port_channel_name == self.normalise_iface(port_channel['bundle_iface']):
                    normalised_phys_ifaces = self.normalise_iface(port_channel['phys_iface'])
                    for neighbour in neighbours:
                        if self.normalise_iface(neighbour['local_interface']) in normalised_phys_ifaces:
                            normalised_neighbour = self.hostname(neighbour['neighbor'])
                            if normalised_neighbour not in report:
                                # Discovered device not polled, ignoring silently
                                continue
                            # Find the port channel which contains this interface on the neighbour side
                            for npc in report[normalised_neighbour]['lags']:
                                normalised_neighbour_interface = self.normalise_iface(neighbour['neighbor_interface'])
                                if normalised_neighbour_interface in self.normalise_iface(npc['phys_iface']):
                                    npc_name = self.normalise_iface(npc['bundle_iface'])

                                    results.append({
                                        'local_interface': port_channel_name,
                                        'neighbor': neighbour['neighbor'],
                                        'neighbor_interface': npc_name,
                                    })

        return results

    def get_mroute_edges(self, report, mcast_group, play_hosts=[]):
        """ Calculates the set of mroute edges between play_hosts in the report

        :param report: The full report object
        :param play_hosts: list Optional list of play hosts to filter the report to
        :return: Dictionary of edges with {left|right}_{host|interface}, indexed by label
        """
        edges = {}

        if not report:
            return edges

        if not play_hosts:
            play_hosts = report.keys()

        def add_edge(neighbour, direction):
            try:
                if direction == 'in':
                    edge = {
                        'left_host': self.hostname(neighbour['neighbor']),
                        'left_interface': self.normalise_iface(neighbour['neighbor_interface']),
                        'right_host': host,
                        'right_interface': self.normalise_iface(neighbour['local_interface']),
                    }
                else:
                    edge = {
                        'left_host': host,
                        'left_interface': self.normalise_iface(neighbour['local_interface']),
                        'right_host': self.hostname(neighbour['neighbor']),
                        'right_interface': self.normalise_iface(neighbour['neighbor_interface']),
                    }

                if re.match(r'^Vl', neighbour['local_interface'], re.IGNORECASE):
                    edge['key'] = neighbour['local_interface']
                else:
                    edge['key'] = "{}:{}\\n-\\n{}:{}".format(
                        edge['left_host'], edge['left_interface'],
                        edge['right_host'], edge['right_interface'])

                edge['publisher'] = mroute['publisher'].replace('0.0.0.0', '*')
                edge['key'] += "\\n({}, {})".format(self.normalise_address(edge['publisher']), self.normalise_address(mroute['group']))

                if edge['key'] not in edges:
                    edges[edge['key']] = edge

            except Exception as e:
                traceback.print_exc()

        for host in play_hosts:
            if host not in report:
                # Failed host
                continue

            for mroute in report[host]['mroutes']:
                try:
                    for in_neighbour in self.get_mroute_neighbours(mroute, report[host]['neighbours'], 'in'):
                        add_edge(in_neighbour, 'in')

                    for in_l2_neighbour in self.get_l2_neighbours(host, mroute, 'in', report):
                        add_edge(in_l2_neighbour, 'in')

                    for in_pc_neighbour in self.get_portchannel_neighbours(host, mroute, report[host]['neighbours'], report[host]['lags'], 'in', report):
                        add_edge(in_pc_neighbour, 'in')

                    for out_neighbour in self.get_mroute_neighbours(mroute, report[host]['neighbours'], 'out'):
                        add_edge(out_neighbour, 'out')

                    for out_l2_neighbour in self.get_l2_neighbours(host, mroute, 'out', report):
                        add_edge(out_l2_neighbour, 'out')

                    for out_pc_neighbour in self.get_portchannel_neighbours(host, mroute, report[host]['neighbours'], report[host]['lags'], 'out', report):
                        add_edge(out_pc_neighbour, 'out')

                except Exception as e:
                    traceback.print_exc()
        return edges

    def get_interface_neighbour(self, report, host, port):
        """ Retrieves the host attached to an interface

        Attempts to locate the host via LLDP information first, and by description second

        :param report: Full report object
        :param host: str Hostname of the device to lookup the interface on
        :param interface: str Name of the interface to lookup the neighbour of
        """
        #return "Unknown"
        if host not in report or not host or not port:
            return "Unknown"

        normalised_port = self.normalise_iface(port)

        # Build am index into this host's neighbours to ease repeat lookups
        if 'neighbour_map' not in report[host]:
            report[host]['neighbour_map'] = {self.normalise_iface(n['local_interface']): n for n in report[host]['neighbours']}

        if normalised_port in report[host]['neighbour_map']:
            return self.hostname(report[host]['neighbour_map'][normalised_port]['neighbor'])

        # Build am index into this host's neighbours to ease repeat lookups
        if 'interface_map' not in report[host]:
            report[host]['interface_map'] = {i['interface']: i for i in report[host]['interfaces']}

        if port in report[host]['interface_map']:
            pass

        return "{}_{}".format(host, re.sub(r'[^a-zA-Z0-9-]', r'_', normalised_port))

    def get_publishers(self, mroutes, interfaces):
        """ Returns a list of Publisher nodes attached to this switch by
            matching mroute publisher addresses to interface subnets

        :param mroutes: list List of mroutes on this switch
        :param interfaces: list List of interfaecs on this switch
        :return: list List of hostnames that publish to this switch
        """
        results = []

        for mroute in mroutes:
            for interface in interfaces:
                if not mroute['publisher'] or mroute['publisher'] == '*' or mroute['publisher'] == '0.0.0.0':
                    continue

                if not interface['ip_address']:
                    continue

                ip_address = IPAddress(mroute['publisher'].split('/')[0])
                ip_network = IPNetwork(interface['ip_address'])
                if ip_address in ip_network:
                    publisher_hostname = self.hostname(gethostbyaddr(str(ip_address))[0])
                    results.append({
                        'hostname': publisher_hostname,
                        'ip': mroute['publisher'],
                    })

        return results

    def filters(self):
        return {
            'hostname': self.hostname,
            'normalise_iface': self.normalise_iface,
            'normalise_group': self.normalise_address,
            'has_mroutes': self.has_mroutes,
            'has_rp': self.has_rp,
            'has_snooping': self.has_snooping,
            'get_rp_address': self.get_rp_address,
            'is_rp': self.is_rp,
            'get_mroute_neighbours': self.get_mroute_neighbours,
            'get_mroute_edges': self.get_mroute_edges,
            'get_interface_neighbour': self.get_interface_neighbour,
            'get_publishers': self.get_publishers,
        }
