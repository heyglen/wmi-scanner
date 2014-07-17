import logging
import socket

import ipaddress
import wmi


class wmiComputer(object):
	def __init__(self, host=None):
		if not host:
			hosts = "localhost"
		else:
			hosts = host.split(",")
			hosts = [host.strip() for host in hosts]
		self._connect(hosts)
		self._logging()

	def _invalid_host(self, host):
		try:
			socket.gethostbyname(host)
		except socket.gaierror:
			return "DNS: Cannot resolve hostname"
		return ""

	def _connect(self, hosts):
		filtered_host_list = set()
		self.computers = list()
		self.skipped_computers = list()
		self.hosts = set()
		for host in hosts:
			error = self._invalid_host(host)
			if error:
				self.skipped_computers.append((host, error))
				continue
			self.hosts.add(host)
			try:
				host = wmi.WMI(computer=host)
				self.computers.append(host)
			except wmi.x_wmi as error:
				self.skipped_computers.append((host, error))
			

	def _logging(self):
		self.logger = logging.getLogger("windows-diagnositc")
		self.logger.setLevel(logging.DEBUG)
		handler = logging.StreamHandler()
		handler.setLevel(logging.DEBUG)
		self.logger.addHandler(handler)

	def get_hostname(self, computer_obj):
		for host in computer_obj.Win32_ComputerSystem():
			return host.DNSHostName.lower()

	def services(self, whitelisted=False, blacklisted=False):
		service_whitelist = []
		service_blacklist = ["Windows Firewall"]
		self.whitelisted_services = list()
		self.blacklisted_services = list()
		services = list()
		for computer in self.computers:
			hostname = self.get_hostname(computer)
			for service in computer.Win32_Service():
				if whitelisted or blacklisted:
					if whitelisted and service.Caption in service_whitelist and service.State != "Running":
						self.whitelisted_services.append((hostname, service.State, service.Caption))
					if blacklisted and service.Caption in service_blacklist and service.State == "Running":
						self.blacklisted_services.append((hostname, service.State, service.Caption))
				else:
					services.append((hostname, service.State, service.Caption))
		if whitelisted and blacklisted:
			return self.whitelisted_services + self.blacklisted_services
		elif whitelisted:
			return self.whitelisted_services
		elif blacklisted:
			return self.blacklisted_services
		else:
			return services

	def ethernet_nics(self, connected=None):
		self.connected_nics = list()
		self.disconnected_nics = list()
		valid_network_adaptor_types = ["Ethernet 802.3"]
		status_code = {0: "Disconnected", 1: "Connecting", 2: "Connected", 3: "Disconnecting", 4: "Hardware not present", 5: "Hardware disabled", 6: "Hardware malfunction", 7: "Media disconnected", 8: "Authenticating", 9: "Authentication succeeded", 10: "Authentication failed", 11: "Invalid address", 12: "Credentials required"}
		for computer in self.computers:
			hostname = self.get_hostname(computer)
			for nic in computer.Win32_NetworkAdapterSetting():
				if hasattr(nic, "Element"):
					nic_element = nic.Element
					if nic_element and nic_element.AdapterType in valid_network_adaptor_types:
						status = "Unknown"
						if nic_element.NetConnectionStatus in status_code.keys():
							status = status_code[int(nic_element.NetConnectionStatus)]
						speed = "??Mbps"
						if nic_element.Speed:
							speed = "%sMbps" % (int(nic_element.Speed)/1000000)
						ip_addresses = ""
						if nic.Setting.IPAddress:
							ip_addresses = ",".join(nic.Setting.IPAddress)

						if nic_element.NetEnabled:			
							self.connected_nics.append((hostname, status, nic_element.NetConnectionID, speed, ip_addresses, nic_element.MACAddress, nic_element.LastErrorCode))
						else:
							self.disconnected_nics.append((hostname, status, nic_element.NetConnectionID, speed, ip_addresses, nic_element.MACAddress, nic_element.LastErrorCode))
		if connected is None:
			return self.connected_nics + self.disconnected_nics
		if connected:
			return self.connected_nics
		if not connected:
			return self.disconnected_nics

	def dns(self):
		try:
			return self.dns_ips
		except AttributeError:
			pass
		self.dns_ips = list()
		for computer in self.computers:
			hostname = self.get_hostname(computer)
			for nic in computer.Win32_NetworkAdapterSetting():	
				if hasattr(nic, "Setting"):
					nic_setting = nic.Setting
					if nic_setting.DNSServerSearchOrder:
						for dns_ip in nic_setting.DNSServerSearchOrder:
							self.dns_ips.append((hostname, dns_ip))
		return self.dns_ips

	def dns_suffix(self):
		try:
			return self.dns_domain_suffix_search
		except AttributeError:
			pass
		self.dns_domain_suffix_search = list()
		for computer in self.computers:
			hostname = self.get_hostname(computer)
			suffixes = set()
			for nic in computer.Win32_NetworkAdapterSetting():	
				if hasattr(nic, "Setting"):
					nic_setting = nic.Setting
					if nic_setting.DNSDomainSuffixSearchOrder:
						for suffix in nic.Setting.DNSDomainSuffixSearchOrder:
							suffixes.add(suffix)			
			for suffix in suffixes:
				self.dns_domain_suffix_search.append((hostname, suffix))
		return self.dns_domain_suffix_search
	
	def persistent_routes(self):
		try:
			return self.persistent_static_routes
		except AttributeError:
			self.persistent_static_routes = list()
		for computer in self.computers:
			hostname = self.get_hostname(computer)
			for route in computer.Win32_IP4PersistedRouteTable():
				try:
					route = "%s via %s" % (ipaddress.IPv4Network("%s/%s" % (route.Destination, route.Mask)), route.NextHop)
				except ValueError:
					self.logger.error("Hostname: %s" % hostname)
					raise
				self.persistent_static_routes.append((hostname, route))
		return self.persistent_static_routes

	def routing_table(self):
		try:
			return self.route_table
		except AttributeError:
			self.route_table = list()
		for computer in self.computers:
			hostname = self.get_hostname(computer)
			for route in computer.Win32_IP4RouteTable():
				route = "%s via %s" % (ipaddress.IPv4Network("%s/%s" % (route.Destination, route.Mask)), route.NextHop)
				self.route_table.append((hostname, route))
		return self.route_table

	def gateway(self):
		try:
			return self.default_gateway
		except AttributeError:
			self.default_gateway = list()
		for computer in self.computers:
			hostname = self.get_hostname(computer)
			for nic in computer.Win32_NetworkAdapterSetting():
				if hasattr(nic, "Setting") and nic.Setting.DefaultIPGateway is not None:
					for ip in nic.Setting.DefaultIPGateway:
						self.default_gateway.append((hostname, ip))
		return self.default_gateway


	def print_all(self):
		if self.connected_nics:
			self.logger.info("\nConnected NICs")
			for interface in self.connected_nics:
				(status, name, speed, ips, mac, last_error) = interface
				self.logger.info("\t[%s] %s %s '%s' %s" % (status, name, speed, ips, mac))
				if last_error:
					self.logger.error("\t\tLast Error: %s" % last_error)
		
		if self.disconnected_nics:
			self.logger.info("\nDisconnected NICs")
			for interface in self.disconnected_nics:
				(status, name, last_error) = interface
				self.logger.info("\t[%s] %s" % (status, name))
				if last_error:
					self.logger.error("\t\tLast Error: %s" % last_error)
		
		if self.dns:
			self.logger.info("\nDNS Servers")
			for ip in self.dns:
				self.logger.info("\t%s" % ip)
		
		if self.dns_domain_suffix_search:
			self.logger.info("\nDNS Suffix List")
			for suffix in self.dns_domain_suffix_search:
				self.logger.info("\t%s" % suffix)
		
		if self.whitelisted_services or self.blacklisted_services:
			self.logger.info("\nInteresting Services")
			for service in self.whitelisted_services:
				self.logger.info("\t[%s] %s" % service)
			for service in self.blacklisted_services:
				self.logger.error("\t[%s] %s" % service)
		
		if self.persistent_routes:
			self.logger.info("\nPersistent Routes")
			for route in self.persistent_routes:
				self.logger.error("\t%s" % route)

if __name__ == "__main__":
	pass
