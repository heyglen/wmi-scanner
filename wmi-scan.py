import sys

import click

import wmi_computer

class Config(object):
	def __init__(self):
		pass

pass_config = click.make_pass_decorator(Config, ensure=True)

def print_services(services, filter_fn=None):
	if filter_fn is None:
		filter_fn = lambda x: True
	if services:
		click.echo("\tServices")
		for host, status, service in sorted(filter(filter_fn, services)):
				click.echo("\t\t%s: [%s] %s" % (host, status, service))
	else:
		click.echo("No Services Found")

@click.group()
@click.option("--hostname", "-h", default="localhost", help="Hostname to scan")
@pass_config
def cli(config, hostname):
	config.computers = wmi_computer.wmiComputer(hostname)
	if config.computers.skipped_computers:
		for computer, error in config.computers.skipped_computers:
			click.echo("Skipping %s %s" % (computer, error))
	
	if not config.computers:
		click.echo("No hosts to scan. Quitting...")
		sys.exit()
	else:
		click.echo()
		click.echo("Scanning %s..." % ", ".join(config.computers.hosts))


@cli.group()
@pass_config
def service(config):
	""" Services """
	pass

@cli.group()
@pass_config
def dns(config):
	""" DNS Configuration """
	config.computers.dns()

@dns.command()
@pass_config
def suffix(config):
	suffixes = config.computers.dns_suffix()
	if suffixes:
		click.echo("\tDNS Suffixes")
		for hostname, suffix in suffixes:
			click.echo("\t\t%s: %s" % (hostname, suffix))
	else:
		click.echo("No Domain Suffixes Found")

@dns.command()
@pass_config
def servers(config):
	dns = config.computers.dns()
	if dns:
		click.echo("\tDNS Servers")
		for hostname, ip in dns:
			click.echo("\t\t%s: %s" % (hostname, ip))
	else:
		click.echo("No DNS Servers Found")

@cli.group()
@pass_config
def route(config):
	""" Routing Table """
	pass

@cli.group()
@pass_config
def nic(config):
	""" Net """
	pass

def print_nics(nics):
	if nics:
		click.echo("\tEthernet NICs")
		for hostname, status, name, speed, ip, mac, error in nics:
			click.echo("\t\t%s: [%s] %s %s %s %s %s" % (hostname, status, name, speed, ip, mac, error))
	else:
		click.echo("\tNo NICs Found")

@nic.command()
@pass_config
def all_nics(config):
	""" All Ethernet NICs """
	nics = config.computers.ethernet_nics()
	print_nics(nics)

@nic.command()
@pass_config
def active(config):
	""" Active Ethernet NICs """
	nics = config.computers.ethernet_nics(connected=True)
	print_nics(nics)

@nic.command()
@pass_config
def disconnected(config):
	""" Disconnected Ethernet NICs """
	nics = config.computers.ethernet_nics(connected=False)
	print_nics(nics)

@route.command()
@pass_config
def default(config):
	""" IP Default Gateway """
	gateways = config.computers.gateway()
	if gateways:
		click.echo("\tIP Default Gateway")
		for hostname, gateway in gateways:
			click.echo("\t\t%s: %s" % (hostname, gateway))
	else:
		click.echo("\tNo Default Gateway Found")

@route.command()
@pass_config
def persistent(config):
	""" Persistent IP Routes """
	routes = config.computers.persistent_routes()
	if routes:
		click.echo("\tPersistent Routes:")
		for hostname, route in routes:
			click.echo("\t\t%s: %s" % (hostname, route))
	else:
		click.echo("\tNo Persistent Routes Found")

@route.command()
@pass_config
def verify_persistent(config):
	""" Active Persistent IP Routes Check """
	persistent_routes = config.computers.persistent_routes()
	routes = config.computers.routing_table()
	missing_routes = list()
	if persistent_routes:
		host_routes = dict()
		for hostname, route in routes:
			if hostname not in host_routes.keys():
				host_routes[hostname] = list()
			host_routes[hostname].append(route)

		for hostname, route in persistent_routes:
			if route not in host_routes[hostname]:
				missing_routes.append((hostname, route))

		if missing_routes:
			click.echo("\tInactive Persistent Routes:")
			for hostname, route in missing_routes:
				click.echo("\t\t%s: %s" % (hostname, route))
		else:
			click.echo("\tOK - Persistent Routes Match")
	else:
		click.echo("\tOK - No Persistent Routes")

@route.command()
@pass_config
def table(config):
	""" IP Routing Table """
	routes = config.computers.routing_table()
	if routes:
		click.echo("\tRouting Table:")
		for hostname, route in routes:
			click.echo("\t\t%s: %s" % (hostname, route))
	else:
		click.echo("\tNo Routing Table Entries Found")

@service.command()
@pass_config
def whitelisted(config):
	services = config.computers.services(whitelisted=True)
	print_services(services)

@service.command()
@pass_config
def blacklisted(config):
	services = config.computers.services(blacklisted=True)
	print_services(services)

@service.command()
@pass_config
def all_services(config):
	services = config.computers.services()
	print_services(services)


@service.command()
@pass_config
def running(config):
	services = config.computers.services()
	print_services(services, lambda x:x[1]=="Running")

if __name__ == "__main__":
	cli()