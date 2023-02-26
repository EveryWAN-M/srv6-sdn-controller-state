#!/usr/bin/python

# General imports
from bson.objectid import ObjectId
import os
import pymongo
from enum import Enum
from pymongo import ReturnDocument
import datetime
import logging
import urllib.parse
from ipaddress import IPv4Interface, IPv6Interface, IPv4Network, IPv6Network
from srv6_sdn_controller_state import utils
import itertools


# Global variables
# DEFAULT_MONGODB_HOST = '0.0.0.0'
# DEFAULT_MONGODB_HOST = '160.80.105.253'
#mongodb running in docker container with ip 10.10.10.10
DEFAULT_MONGODB_HOST = os.environ.get('MONGODB_HOST', '10.10.10.10')
DEFAULT_MONGODB_PORT = int(os.environ.get('MONGODB_PORT', 27017))
DEFAULT_MONGODB_USERNAME = os.environ.get('MONGODB_USERNAME', 'root')
DEFAULT_MONGODB_PASSWORD = os.environ.get('MONGODB_PASSWORD', '12345678')

DEFAULT_VXLAN_PORT = 4789

# Table where we store our seg6local routes
LOCAL_SID_TABLE = 1
# Reserved table IDs
RESERVED_TABLEIDS = [0, 253, 254, 255]
RESERVED_TABLEIDS.append(LOCAL_SID_TABLE)
# Reserved VNI
RESERVED_VNI = [0, 1]
# Reserved VTEP IP address
RESERVED_VTEP_IP = [0, 65536]
RESERVED_VTEP_IPV6 = [0]
# Reserved Tunnel Indices
RESERVED_TUNNELID = []

# Set logging level
logging.basicConfig(level=logging.DEBUG)

# MongoDB client
client = None


class DeviceState(Enum):
    UNKNOWN = 0
    WORKING = 1
    REBOOT_REQUIRED = 2
    ADMIN_DISABLED = 3
    REBOOTING = 4
    FAILURE = 5

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_


# Get a reference to the MongoDB client
def get_mongodb_session(
    host=DEFAULT_MONGODB_HOST,
    port=DEFAULT_MONGODB_PORT,
    username=DEFAULT_MONGODB_USERNAME,
    password=DEFAULT_MONGODB_PASSWORD
):
    global client
    # Percent-escape username
    username = urllib.parse.quote_plus(username)
    # Percent-escape password
    password = urllib.parse.quote_plus(password)
    # Return the MogoDB client
    logging.debug(
        'Trying to establish a connection to the db (%s:%s)', host, port
    )
    # Adjust IP address representation
    host = '[%s]' % host
    if client is None:
        client = pymongo.MongoClient(
            host=host,
            port=port,
            username=username,
            password=password
        )
    return client


''' Functions operating on the devices collection '''


# Register a device
def register_device(
    deviceid,
    features,
    interfaces,
    mgmtip,
    tenantid,
    sid_prefix=None,
    public_prefix_length=None,
    enable_proxy_ndp=True,
    force_ip6tnl=False,
    force_srh=False,
    incoming_sr_transparency=None,
    outgoing_sr_transparency=None
):
    # Build the document to insert
    device = {
        'deviceid': deviceid,
        'name': None,
        'description': None,
        'features': features,
        'interfaces': interfaces,
        'default': {
            'interfaces': interfaces
        },
        'mgmtip': mgmtip,
        'mgmtip_orig': mgmtip,
        'mgmt_mac': None,
        'tenantid': tenantid,
        'tunnel_mode': None,
        'nat_type': None,
        'external_ip': None,
        'external_port': None,
        'vxlan_port': None,
        'connected': False,
        'configured': False,
        'enabled': False,
        'stats': {
            'counters': {
                'tunnels': [],
                'reconciliation_failures': 0
            }
        },
        'vtep_ip_addr': None,
        'vtep_ipv6_addr': None,
        'registration_timestamp': str(datetime.datetime.utcnow()),
        'sid_prefix': sid_prefix,
        'public_prefix_length': public_prefix_length,
        'enable_proxy_ndp': enable_proxy_ndp,
        'force_ip6tnl': force_ip6tnl,
        'force_srh': force_srh,
        'incoming_sr_transparency': incoming_sr_transparency,
        'outgoing_sr_transparency': outgoing_sr_transparency,
        'reconciliation_required': False,
        'allow_reboot': False,  # TODO read from device config file
        'state': DeviceState.UNKNOWN.value
    }
    # Register the device
    logging.debug('Registering device on DB: %s' % device)
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Add the device to the collection
        success = devices.insert_one(device).acknowledged
        if success:
            logging.debug('Device successfully registered')
        else:
            logging.error('Cannot register the device')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Unregister a device
def unregister_device(deviceid, tenantid):
    # Build the document to insert
    device = {'deviceid': deviceid, 'tenantid': tenantid}
    # Unregister the device
    logging.debug('Unregistering device: %s (tenant %s)', deviceid, tenantid)
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Delete the device from the collection
        success = devices.delete_one(device).deleted_count == 1
        if success:
            logging.debug('Device unregistered successfully')
        else:
            logging.error('Cannot unregister the device')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Unregister all devices of a tenant
def unregister_devices_by_tenantid(tenantid):
    # Build the filter
    device = {'tenantid': tenantid}
    # Delete all the devices in the collection
    logging.debug('Unregistering all the devices of the tenant %s', tenantid)
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        success = devices.delete_many(device).acknowledged
        if success:
            logging.debug('Devices successfully unregistered')
        else:
            logging.error('Cannot unregister the devices')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Unregister all devices
def unregister_all_devices():
    # Delete all the devices in the collection
    logging.debug('Unregistering all the devices')
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        success = devices.delete_many().acknowledged
        if success:
            logging.debug('Devices successfully unregistered')
        else:
            logging.error('Cannot unregister the devices')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Update management information
def update_mgmt_info(
    deviceid,
    tenantid,
    mgmtip,
    interfaces,
    tunnel_mode,
    nat_type,
    device_external_ip,
    device_external_port,
    device_vtep_mac,
    vxlan_port
):
    # Build the query
    query = [{'deviceid': deviceid, 'tenantid': tenantid}]
    for interface in interfaces:
        query.append(
            {
                'deviceid': deviceid,
                'tenantid': tenantid,
                'interfaces.name': interface
            }
        )
    # Build the update
    update = [
        {
            '$set': {
                'mgmtip': mgmtip,
                'tunnel_mode': tunnel_mode,
                'nat_type': nat_type,
                'external_ip': device_external_ip,
                'external_port': device_external_port,
                'mgmt_mac': device_vtep_mac,
                'vxlan_port': vxlan_port
            }
        }
    ]
    for interface in interfaces.values():
        update.append(
            {
                '$set': {
                    'interfaces.$.ext_ipv4_addrs': interface['ext_ipv4_addrs'],
                    'interfaces.$.ext_ipv6_addrs': interface['ext_ipv6_addrs']
                }
            }
        )
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Update the device
        for q, u in zip(query, update):
            logging.debug('Updating interface %s on DB', q)
            res = devices.update_one(q, u).matched_count == 1
            if res:
                logging.debug('Interface successfully updated')
                if success is not False:
                    success = True
            else:
                logging.error(
                    'Cannot update interface. Skipping. '
                    'Does the interface still exist?'
                )
                success = True
        if success:
            logging.debug('Device successfully updated')
        else:
            logging.error('Cannot update device')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False in case of failure or
    # None if an error occurred during the connection to the db
    return success


# Clear management information
def clear_mgmt_info(deviceid, tenantid):
    # Build the query
    query = [{'deviceid': deviceid, 'tenantid': tenantid}]
    interfaces = get_interfaces(deviceid, tenantid)
    for interface in interfaces:
        query.append(
            {
                'deviceid': deviceid,
                'tenantid': tenantid,
                'interfaces.name': interface['name']
            }
        )
    device = get_device(deviceid, tenantid)
    mgmtip_orig = device['mgmtip_orig']
    # Build the update
    update = [
        {
            '$set': {
                'mgmtip': mgmtip_orig,
                'tunnel_mode': None,
                'nat_type': None,
                'external_ip': None,
                'external_port': None,
                'mgmt_mac': None,
                'vxlan_port': None
            }
        }
    ]
    for interface in interfaces:
        update.append(
            {
                '$set': {
                    'interfaces.$.ext_ipv4_addrs': [],
                    'interfaces.$.ext_ipv6_addrs': []
                }
            }
        )
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Update the device
        for q, u in zip(query, update):
            logging.debug('Updating interface %s on DB', q)
            res = devices.update_one(q, u).matched_count == 1
            if res:
                logging.debug('Interface successfully updated')
                if success is not False:
                    success = True
            else:
                logging.error('Cannot update interface')
                success = False
        if success:
            logging.debug('Device successfully updated')
        else:
            logging.error('Cannot update device')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False in case of failure or
    # None if an error occurred during the connection to the db
    return success


# Get devices
def get_devices(deviceids=None, tenantid=None, return_dict=False):
    # Build the query
    query = dict()
    if tenantid is not None:
        query['tenantid'] = tenantid
    if deviceids is not None:
        query['deviceid'] = {'$in': list(deviceids)}
    # Find the device by device ID
    logging.debug(
        'Retrieving devices [%s] by tenant ID %s', deviceids, tenantid
    )
    res = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the devices
        devices = devices.find(query)
        if return_dict:
            # Build a dict representation of the devices
            res = dict()
            for device in devices:
                deviceid = device['deviceid']
                res[deviceid] = device
        else:
            res = list(devices)
        logging.debug('Devices found: %s' % devices)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the devices
    return res


# Get a device
def get_device(deviceid, tenantid):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Find the device
    logging.debug('Retrieving device %s', deviceid)
    device = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the devices
        device = devices.find_one(query)
        logging.debug('Device found: %s' % device)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the device
    return device


# Return True if a device exists,
# False otherwise
def device_exists(deviceid, tenantid):
    # Build the query
    device = {'deviceid': deviceid, 'tenantid': tenantid}
    device_exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Count the devices with the given device ID
        logging.debug(
            'Searching the device %s (tenant %s)', deviceid, tenantid
        )
        if devices.count_documents(device, limit=1):
            logging.debug('The device exists')
            device_exists = True
        else:
            logging.debug('The device does not exist')
            device_exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the device exists,
    # False if the device does not exist
    # or None if an error occurred during the connection to the db
    return device_exists


# Return True if all the devices exist,
# False otherwise
def devices_exists(deviceids):
    # Build the query
    query = {'deviceid': {'$in': deviceids}}
    devices_exist = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Count the devices with the given device ID
        logging.debug('Searching the devices %s', deviceids)
        if devices.count_documents(query) == len(deviceids):
            logging.debug('The devices exist')
            devices_exist = True
        else:
            logging.debug('The devices do not exist')
            devices_exist = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the devices exist,
    # False if the devices do not exist
    # or None if an error occurred during the connection to the db
    return devices_exist


# Return True if a device exists and is in enabled state,
# False otherwise
def is_device_enabled(deviceid, tenantid):
    # Get the device
    logging.debug('Searching the device %s (tenant %s)', deviceid, tenantid)
    device = get_device(deviceid, tenantid)
    res = None
    if device is not None:
        # Get the status of the device
        res = device['enabled']
        if res:
            logging.debug('The device is enabled')
        else:
            logging.debug('The device is not enabled')
    # Return True if the device is enabled,
    # False if it is not enabled or
    # None if an error occurred during the connection to the db
    return res


# Return True if a device exists and is in configured state,
# False otherwise
def is_device_configured(deviceid, tenantid):
    # Get the device
    logging.debug('Searching the device %s (tenant %s)', deviceid, tenantid)
    device = get_device(deviceid, tenantid)
    res = None
    if device is not None:
        # Get the status of the device
        res = device['configured']
        if res:
            logging.debug('The device is configured')
        else:
            logging.debug('The device is not configured')
    # Return True if the device is configured,
    # False if it is not configured or
    # None if an error occurred during the connection to the db
    return res


# Return True if a device exists and is in connected state,
# False otherwise
def is_device_connected(deviceid, tenantid):
    # Get the device
    logging.debug('Searching the device %s (tenant %s)', deviceid, tenantid)
    device = get_device(deviceid, tenantid)
    res = None
    if device is not None:
        # Get the status of the device
        res = device['connected']
        if res:
            logging.debug('The device is connected')
        else:
            logging.debug('The device is not connected')
    # Return True if the device is connected,
    # False if it is not connected or
    # None if an error occurred during the connection to the db
    return res


# Return True if a device can be rebooted, False otherwise
def can_reboot_device(deviceid, tenantid):
    # Get the device
    logging.debug('Searching the device %s (tenant %s)', deviceid, tenantid)
    device = get_device(deviceid, tenantid)
    res = None
    if device is not None:
        # Get the status of the device
        res = device.get('allow_reboot', False)
        if res:
            logging.debug('The device can be rebooted')
        else:
            logging.debug('The device cannot be rebooted')
    # Return True if the device is enabled,
    # False if it is not enabled or
    # None if an error occurred during the connection to the db
    return res


# Return True if an interface exists on a given device,
# False otherwise
def interface_exists_on_device(deviceid, tenantid, interface_name):
    # Build the query
    query = {
        'deviceid': deviceid,
        'tenantid': tenantid,
        'interfaces.name': interface_name
    }
    # Get the device
    logging.debug(
        'Getting the interface %s on the device %s (tenant %s)',
        interface_name,
        deviceid,
        tenantid
    )
    exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Add the device to the collection
        device = devices.find_one(query)
        if device is not None:
            logging.debug('The interface exists on the device')
            exists = True
        else:
            logging.debug('The interface does not exist on the device')
            exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the interface exists,
    # False if it not exists or
    # None if an error occurred during the connection to the db
    return exists


# Return an interface of a device
def get_interface(deviceid, tenantid, interface_name):
    logging.debug(
        'Getting the interface %s of device %s (tenant %s)',
        interface_name,
        deviceid,
        tenantid
    )
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the filter
    filter = {'interfaces': {'$elemMatch': {'name': interface_name}}}
    interface = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the interface
        interfaces = devices.find_one(query, filter).get('interfaces')
        if interfaces is None or len(interfaces) == 0:
            # Interface not found
            logging.debug('Interface not found')
        else:
            interface = interfaces[0]
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the interface if exists,
    # None if it does not exist or if an error occurred
    return interface


# Return all the interfaces of a device
def get_interfaces(deviceid, tenantid):
    # Get the device
    logging.debug(
        'Getting the interfaces of device %s (tenant %s)', deviceid, tenantid
    )
    device = get_device(deviceid, tenantid)
    interfaces = None
    if device is not None:
        # Return the interfaces
        interfaces = device['interfaces']
    # Return the interfaces if the device exists or
    # None if an error occurred during the connection to the db
    return interfaces


# Get device's IPv4 addresses
def get_ipv4_addresses(deviceid, tenantid, interface_name):
    # Find the IPv4 addresses by device ID and interface
    logging.debug('Retrieving IPv4 addresses for device %s' % deviceid)
    interface = get_interface(deviceid, tenantid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ipv4_addrs']
        logging.debug('IPv4 addresses: %s' % addrs)
    # Return the IPv4 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's IPv6 addresses
def get_ipv6_addresses(deviceid, tenantid, interface_name):
    # Find the IPv6 addresses by device ID and interface
    logging.debug(
        'Retrieving IPv6 addresses for device %s (tenant %s)',
        deviceid,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ipv6_addrs']
        logging.debug('IPv6 addresses: %s' % addrs)
    # Return the IPv6 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's IP addresses
def get_ip_addresses(deviceid, tenantid, interface_name):
    # Find the IP addresses by device ID and interface name
    logging.debug(
        'Retrieving IP addresses for device %s and interface %s (tenant %s)',
        deviceid,
        interface_name,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    addrs = None
    if interface is not None:
        addrs = interface['ipv4_addrs'] + \
            interface['ipv6_addrs']
        logging.debug('IP addresses: %s', addrs)
        return addrs
    # Return the IP addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's external IPv4 addresses
def get_ext_ipv4_addresses(deviceid, tenantid, interface_name):
    # Find the external IPv4 addresses by device ID and interface
    logging.debug(
        'Retrieving external IPv4 addresses for device %s (tenant %s)',
        deviceid,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ext_ipv4_addrs']
        logging.debug('External IPv4 addresses: %s' % addrs)
    # Return the IPv4 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's external IPv6 addresses
def get_ext_ipv6_addresses(deviceid, tenantid, interface_name):
    # Find the external IPv6 addresses by device ID and interface
    logging.debug(
        'Retrieving external IPv6 addresses for device %s (tenant %s)',
        deviceid,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ext_ipv6_addrs']
        logging.debug('External IPv6 addresses: %s', addrs)
    # Return the IPv6 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's external IP addresses
def get_ext_ip_addresses(deviceid, tenantid, interface_name):
    # Find the external IP addresses by device ID and interface name
    logging.debug(
        'Retrieving external IP addresses for device %s '
        'and interface %s (tenant %s)',
        deviceid,
        interface_name
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    addrs = None
    if interface is not None:
        addrs = interface['ext_ipv4_addrs'] + interface['ext_ipv6_addrs']
        logging.debug('External IP addresses: %s' % addrs)
        return addrs
    # Return the IP addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's IPv4 subnets
def get_ipv4_subnets(deviceid, tenantid, interface_name):
    # Find the IPv4 subnets by device ID and interface
    logging.debug(
        'Retrieving IPv4 subnets for device %s (tenant %s)',
        deviceid,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    subnets = None
    if interface is not None:
        # Extract the subnets
        subnets = interface['ipv4_subnets']
        logging.debug('IPv4 subnets: %s' % subnets)
    # Return the IPv4 subnets associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return subnets


# Get device's IPv6 subnets
def get_ipv6_subnets(deviceid, tenantid, interface_name):
    # Find the IPv6 subnets by device ID and interface
    logging.debug(
        'Retrieving IPv6 subnets for device %s, tenantid %s',
        deviceid,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    subnets = None
    if interface is not None:
        # Extract the subnets
        subnets = interface['ipv6_subnets']
        logging.debug('IPv6 subnets: %s' % subnets)
    # Return the IPv6 subnets associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return subnets


# Get device's IP subnets
def get_ip_subnets(deviceid, tenantid, interface_name):
    # Find the IP subnets by device ID and interface name
    logging.debug(
        'Retrieving IP subnets for device %s and interface %s (tenant %s)',
        deviceid,
        interface_name,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    subnets = None
    if interface is not None:
        subnets = interface['ipv4_subnets'] + interface['ipv6_subnets']
        logging.debug('IP subnets: %s' % subnets)
        return subnets
    # Return the IP subnets associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return subnets


# Get router's IPv4 loopback IP
def get_loopbackip_ipv4(deviceid, tenantid):
    addrs = get_ipv4_addresses(deviceid, tenantid, 'lo')
    if addrs is not None:
        return addrs[0]
    else:
        return None


# Get router's IPv4 loopback net
def get_loopbacknet_ipv4(deviceid, tenantid):
    loopbackip = get_loopbackip_ipv4(deviceid, tenantid)
    if loopbackip is not None:
        return IPv4Interface(loopbackip).network.__str__()
    else:
        return None


# Get router's IPv6 loopback IP
def get_loopbackip_ipv6(deviceid, tenantid):
    addrs = get_ipv6_addresses(deviceid, tenantid, 'lo')
    if addrs is not None:
        return addrs[0]
    else:
        return None


# Get router's IPv6 loopback net
def get_loopbacknet_ipv6(deviceid, tenantid):
    loopbackip = get_loopbackip_ipv6(deviceid, tenantid)
    if loopbackip is not None:
        return IPv6Interface(loopbackip).network.__str__()
    else:
        return None


# Get device's global IPv6 addresses
def get_global_ipv6_addresses(deviceid, tenantid, interface_name):
    # Find the IPv6 addresses by device ID and interface
    logging.debug(
        'Retrieving global IPv6 addresses for device %s (tenant %s)',
        deviceid,
        tenantid
    )
    interface = get_interface(deviceid, tenantid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        _addrs = interface['ipv6_addrs']
        addrs = []
        for addr in _addrs:
            if IPv6Interface(addr).is_global:
                addrs.append(addr)
        logging.debug('Global IPv6 addresses: %s', addrs)
    # Return the global IPv6 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get non link-local IPv6 addresses
def get_non_link_local_ipv6_addresses(
    deviceid,
    tenantid,
    interface_name,
    client=None
):
    # Find the IPv6 addresses by device ID and interface
    logging.debug(
        'Retrieving non link-local IPv6 addresses for device %s (tenant %s)',
        deviceid,
        tenantid
    )
    interface = get_interface(
        deviceid=deviceid, tenantid=tenantid, interface_name=interface_name
    )
    addrs = None
    if interface is not None:
        # Extract the addresses
        _addrs = interface['ipv6_addrs']
        addrs = []
        for addr in _addrs:
            if not IPv6Interface(addr).is_link_local:
                addrs.append(addr)
        logging.debug('Non link-local IPv6 addresses: %s', addrs)
    # Return the non link-local IPv6 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


def is_proxy_ndp_enabled(deviceid, tenantid):
    """
    Return True if the proxy NDP is enabled on the device, False otherwise.
    """
    logging.debug('Retrieving enable_proxy_ndp flag for device %s', deviceid)
    # Get the device
    device = get_device(deviceid, tenantid)
    is_proxy_ndp_enabled = None
    if device is not None:
        # Get the enable_proxy_ndp flag
        is_proxy_ndp_enabled = device.get('enable_proxy_ndp', False)
        logging.debug('enable_proxy_ndp: %s', is_proxy_ndp_enabled)
    # Return True if the enable_proxy_ndp flag is set,
    # False if it is not set,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return is_proxy_ndp_enabled


def is_ip6tnl_forced(deviceid, tenantid):
    """
    Return True if the force_ip6tnl parameter is set for the device, False
    otherwise.
    """
    logging.debug('Retrieving force_ip6tnl flag for device %s', deviceid)
    # Get the device
    device = get_device(deviceid, tenantid)
    is_ip6tnl_forced = None
    if device is not None:
        # Get the force_ip6tnl flag
        is_ip6tnl_forced = device.get('force_ip6tnl', False)
        logging.debug('force_ip6tnl: %s', is_proxy_ndp_enabled)
    # Return True if the force_ip6tnl flag is set,
    # False if it is not set,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return is_ip6tnl_forced


def is_srh_forced(deviceid, tenantid):
    """
    Return True if the force_srh parameter is set for the device, False
    otherwise.
    """
    logging.debug('Retrieving force_srh flag for device %s', deviceid)
    # Get the device
    device = get_device(deviceid, tenantid)
    is_srh_forced = None
    if device is not None:
        # Get the force_srh flag
        is_srh_forced = device.get('force_srh', False)
        logging.debug('force_srh: %s', is_proxy_ndp_enabled)
    # Return True if the force_srh flag is set,
    # False if it is not set,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return is_srh_forced


def get_incoming_sr_transparency(deviceid, tenantid):
    """
    Return the incoming Segment Routing Transparency.
    """
    logging.debug(
        'Retrieving incoming_sr_transparency for device %s', deviceid
    )
    # Get the device
    device = get_device(deviceid, tenantid)
    incoming_sr_transparency = None
    if device is not None:
        # Get the force_srh flag
        incoming_sr_transparency = device.get('incoming_sr_transparency', None)
        logging.debug('incoming_sr_transparency: %s', incoming_sr_transparency)
    # Return the incoming Segment Routing Transparency,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return incoming_sr_transparency


def get_outgoing_sr_transparency(deviceid, tenantid):
    """
    Return the outgoing Segment Routing Transparency.
    """
    logging.debug(
        'Retrieving outgoing_sr_transparency for device %s', deviceid
    )
    # Get the device
    device = get_device(deviceid, tenantid)
    outgoing_sr_transparency = None
    if device is not None:
        # Get the force_srh flag
        outgoing_sr_transparency = device.get('outgoing_sr_transparency', None)
        logging.debug('outgoing_sr_transparency: %s', outgoing_sr_transparency)
    # Return the outgoing Segment Routing Transparency,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return outgoing_sr_transparency


# Get router's SID prefix
def get_sid_prefix(deviceid, tenantid):
    logging.debug('Retrieving SID prefix for device %s', deviceid)
    # Get the device
    device = get_device(deviceid, tenantid)
    sid_prefix = None
    if device is not None:
        # Get the SID prefix
        sid_prefix = device['sid_prefix']
        logging.debug('SID prefix: %s', sid_prefix)
    # Return the SID prefix if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return sid_prefix


# Get router's public prefix length
def get_public_prefix_length(deviceid, tenantid):
    logging.debug('Retrieving public prefix length for device %s', deviceid)
    # Get the device
    device = get_device(deviceid, tenantid)
    public_prefix_length = None
    if device is not None:
        # Get the SID prefix
        public_prefix_length = device['public_prefix_length']
        logging.debug('Public prefix prefix: %s', public_prefix_length)
    # Return the public prefix length if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return public_prefix_length


# Get router's management IP address
def get_router_mgmtip(deviceid, tenantid):
    logging.debug('Retrieving management IP for device %s', deviceid)
    # Get the device
    device = get_device(deviceid, tenantid)
    mgmtip = None
    if device is not None:
        # Get the management IP address
        mgmtip = device['mgmtip']
        logging.debug('Management IP: %s', mgmtip)
    # Return the management IP address if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return mgmtip


# Get WAN interfaces of a device
def get_wan_interfaces(deviceid, tenantid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid, tenantid)
    wan_interfaces = None
    if interfaces is not None:
        # Filter WAN interfaces
        wan_interfaces = list()
        for interface in interfaces:
            if interface['type'] == utils.InterfaceType.WAN:
                wan_interfaces.append(interface['name'])
    # Return the WAN interfaces if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return wan_interfaces


# Get LAN interfaces of a device
def get_lan_interfaces(deviceid, tenantid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid, tenantid)
    lan_interfaces = None
    if interfaces is not None:
        # Filter LAN interfaces
        lan_interfaces = list()
        for interface in interfaces:
            if interface['type'] == utils.InterfaceType.LAN:
                lan_interfaces.append(interface['name'])
    # Return the LAN interfaces if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return lan_interfaces


# Get non-loopback interfaces of a device
def get_non_loopback_interfaces(deviceid, tenantid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid, tenantid)
    non_lo_interfaces = None
    if interfaces is not None:
        # Filter non-loopback interfaces
        non_lo_interfaces = list()
        for interface in interfaces:
            if interface['name'] != 'lo':
                non_lo_interfaces.append(interface['name'])
    # Return the non-loopback interfaces if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return non_lo_interfaces


# Configure the devices
def configure_devices(devices):
    # Build the update statements
    queries = []
    updates = []
    for device in devices:
        # Get device ID
        deviceid = device['deviceid']
        # Get tenant ID
        tenantid = device['tenantid']
        # Get device name
        name = device['name']
        # Get device description
        description = device['description']
        # Add query
        queries.append({'deviceid': deviceid, 'tenantid': tenantid})
        # Add update
        updates.append(
            {
                '$set': {
                    'name': name,
                    'description': description,
                    'configured': True
                }
            }
        )
        # Get interfaces
        interfaces = device['interfaces']
        for interface in interfaces.values():
            # Get interface name
            interface_name = interface['name']
            # Get IPv4 addresses
            ipv4_addrs = interface['ipv4_addrs']
            # Get IPv6 addresses
            ipv6_addrs = interface['ipv6_addrs']
            # Get IPv4 subnets
            ipv4_subnets = interface['ipv4_subnets']
            # Get IPv6 subnets
            ipv6_subnets = interface['ipv6_subnets']
            # Get the type of the interface
            type = interface['type']
            # Add query
            queries.append(
                {
                    'deviceid': deviceid,
                    'interfaces.name': interface_name,
                    'tenantid': tenantid
                }
            )
            # Add update
            updates.append(
                {
                    '$set': {
                        'interfaces.$.ipv4_addrs': ipv4_addrs,
                        'interfaces.$.ipv6_addrs': ipv6_addrs,
                        'interfaces.$.ipv4_subnets': ipv4_subnets,
                        'interfaces.$.ipv6_subnets': ipv6_subnets,
                        'interfaces.$.type': type
                    }
                }
            )
    res = True
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Update the devices
        logging.debug('Configuring devices')
        for query, update in zip(queries, updates):
            success = devices.update_one(query, update).matched_count == 1
            if not success:
                logging.error('Cannot configure device %s', query)
                res = False
        logging.debug('Devices configured')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
        res = None
    # Return True if all the devices have been configured,
    # False otherwise
    return res


# Change the state of a device
def change_device_state(deviceid, tenantid, new_state):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    if not DeviceState.has_value(new_state.value):
        logging.error(
            'Cannot change device state: invalid state %d', new_state.value
        )
        return False
    # Build the update
    update = {'$set': {'state': new_state.value}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'enabled' flag
        logging.debug('Change state for device %s', deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot change state: device not found')
        else:
            logging.debug('State updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Enable or disable a device
def set_device_enabled_flag(deviceid, tenantid, enabled):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the update
    update = {'$set': {'enabled': enabled}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'enabled' flag
        logging.debug('Change enabled flag for device %s' % deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot change enabled flag: device not found')
        else:
            logging.debug('Enabled flag updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Mark the device as configured / unconfigured
def set_device_configured_flag(deviceid, tenantid, configured):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the update
    update = {'$set': {'configured': configured}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'configured' flag
        logging.debug('Change configured flag for device %s', deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot change configured flag: device not found')
        else:
            logging.debug('Configured flag updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Set / unset 'connected' flag for a device
def set_device_connected_flag(deviceid, tenantid, connected):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the update
    update = {'$set': {'connected': connected}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'connected' flag
        logging.debug('Change connected flag for device %s', deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot change connected flag: device not found')
        else:
            logging.debug('Connected flag updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Device require reconciliation
def set_device_reconciliation_flag(deviceid, tenantid, flag=True):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the update
    update = {'$set': {'reconciliation_required': flag}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'reconciliation' flag
        logging.debug('Change reconciliation flag for device %s', deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error(
                'Cannot change reconciliation flag: device not found'
            )
        else:
            logging.debug('Reconciliation flag updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Get device reconciliation flag
def get_device_reconciliation_flag(deviceid, tenantid):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Find the device
    logging.debug('Retrieving device reconciliation flag %s', deviceid)
    flag = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the devices
        device = devices.find_one(query)
        # Get the flag
        flag = device['reconciliation_required']
        logging.debug('Device reconciliation flag: %s', flag)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the flag
    return flag


# Get the counter of a tunnel mode on a device and
# increase the counter
def get_and_inc_tunnel_mode_counter(tunnel_name, deviceid, tenantid):
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Getting the device %s (tenant %s)', deviceid, tenantid)
        # Build query
        query = {
            'deviceid': deviceid,
            'tenantid': tenantid,
            'stats.counters.tunnels.tunnel_mode': {'$ne': tunnel_name}
        }
        # Build the update
        update = {
            '$push': {
                'stats.counters.tunnels': {
                    'tunnel_mode': tunnel_name,
                    'counter': 0
                }
            }
        }
        # If the counter does not exist, create it
        devices.update_one(query, update)
        # Build the query
        query = {
            'deviceid': deviceid,
            'stats.counters.tunnels.tunnel_mode': tunnel_name
        }
        # Build the update
        update = {'$inc': {'stats.counters.tunnels.$.counter': 1}}
        # Increase the counter for the tunnel mode
        device = devices.find_one_and_update(query, update)
        # Return the counter if exists, 0 otherwise
        counter = 0
        for tunnel_mode in device['stats']['counters']['tunnels']:
            if tunnel_name == tunnel_mode['tunnel_mode']:
                counter = tunnel_mode['counter']
        logging.debug('Counter before the increment: %s', counter)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Decrease the counter of a tunnel mode on a device and
# return the counter after the decrement
def dec_and_get_tunnel_mode_counter(tunnel_name, deviceid, tenantid):
    # Build the query
    query = {
        'deviceid': deviceid,
        'tenantid': tenantid,
        'stats.counters.tunnels.tunnel_mode': tunnel_name
    }
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Getting the device %s (tenant %s)', deviceid, tenantid)
        # Decrease the counter for the tunnel mode
        device = devices.find_one_and_update(
            query, {'$inc': {'stats.counters.tunnels.$.counter': -1}},
            return_document=ReturnDocument.AFTER)
        if device is None:
            logging.error('Device not found or tunnel mode counter not found')
            return None
        # Return the counter
        counter = -1
        for tunnel_mode in device['stats']['counters']['tunnels']:
            if tunnel_name == tunnel_mode['tunnel_mode']:
                counter = tunnel_mode['counter']
        if counter == -1:
            logging.error('Cannot update counter')
            return None
        logging.debug('Counter after the decrement: %s', counter)
        # If counter is 0, remove the tunnel mode from the device stats
        if counter == 0:
            logging.debug('Counter set to 0, removing tunnel mode')
            devices.update_one(
                query,
                {
                    '$pull': {
                        'stats.counters.tunnels': {
                            'tunnel_mode': tunnel_name
                        }
                    }
                }
            )
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Reset the counter of a tunnel mode on a device
def reset_tunnel_mode_counter(tunnel_name, deviceid, tenantid):
    # Build the query
    query = {
        'deviceid': deviceid,
        'tenantid': tenantid,
        'stats.counters.tunnels.tunnel_mode': tunnel_name
    }
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Getting the device %s (tenant %s)', deviceid, tenantid)
        # Decrease the counter for the tunnel mode
        device = devices.find_one_and_update(
            query,
            {
                '$set': {
                    'stats.counters.tunnels.$.counter': 0
                }
            },
            return_document=ReturnDocument.AFTER)
        if device is None:
            logging.warning(
                'Device not found or tunnel mode counter not found'
            )
            return 0
        # Return the counter
        counter = -1
        for tunnel_mode in device['stats']['counters']['tunnels']:
            if tunnel_name == tunnel_mode['tunnel_mode']:
                counter = tunnel_mode['counter']
        if counter == -1:
            logging.error('Cannot update counter')
            return None
        logging.debug('Counter after the decrement: %s', counter)
        # If counter is 0, remove the tunnel mode from the device stats
        if counter == 0:
            logging.debug('Counter set to 0, removing tunnel mode')
            devices.update_one(
                query,
                {
                    '$pull': {
                        'stats.counters.tunnels': {
                            'tunnel_mode': tunnel_name
                        }
                    }
                }
            )
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Return the number of tunnels configured on a device
def get_num_tunnels(deviceid, tenantid):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    num = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Counting tunnels for device %s', deviceid)
        # Get the device
        device = devices.find_one(query)
        if device is None:
            logging.error('Device %s not found', deviceid)
        else:
            # Extract tunnel mode counter
            counters = device['stats']['counters']['tunnels']
            # Count the tunnels
            num = 0
            for tunnel_mode in counters:
                num += tunnel_mode['counter']
            logging.debug('%s tunnels found', num)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the number of tunnels if success,
    # None if an error occurred during the connection to the db
    return num


# Get the counter of tunnels on a device and increase the counter
def inc_and_get_tunnels_counter(overlayid, tenantid, deviceid, dest_slice):
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the device
        logging.debug(
            'Getting the overlay %s (tenant %s)',
            overlayid,
            tenantid
        )
        # Build query
        query = {
            '_id': ObjectId(overlayid),
            'tenantid': tenantid,
            'stats.counters.tunnels': {
                '$elemMatch': {
                    'deviceid': deviceid,
                    'dest_slice': dest_slice
                }
            }
        }
        # If the counter does not exist, create it
        if overlays.find_one(query) is None:
            query = {
                '_id': ObjectId(overlayid),
                'tenantid': tenantid
            }
            # Build the update
            update = {
                '$push': {
                    'stats.counters.tunnels': {
                        'deviceid': deviceid,
                        'dest_slice': dest_slice,
                        'counter': 0
                    }
                }
            }
            # If the counter does not exist, create it
            overlays.update_one(query, update)
        # Build the query
        query = {
            '_id': ObjectId(overlayid),
            'tenantid': tenantid,
            'stats.counters.tunnels': {
                '$elemMatch': {
                    'deviceid': deviceid,
                    'dest_slice': dest_slice
                }
            }
        }
        # Build the update
        update = {'$inc': {'stats.counters.tunnels.$.counter': 1}}
        # Increase the tunnels counter for the overlay
        overlay = overlays.find_one_and_update(
            query, update, return_document=ReturnDocument.AFTER
        )
        # Return the counter if exists, 0 otherwise
        counter = 0
        for tunnel in overlay['stats']['counters']['tunnels']:
            if deviceid == tunnel['deviceid'] and \
                    dest_slice == tunnel['dest_slice']:
                counter = tunnel['counter']
        logging.debug('Counter after the increment: %s', counter)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Decrease the counter of a tunnels on a overlay and
# return the counter after the decrement
def dec_and_get_tunnels_counter(overlayid, tenantid, deviceid, dest_slice):
    # Build the query
    query = {
        '_id': ObjectId(overlayid),
        'tenantid': tenantid,
        'stats.counters.tunnels': {
            '$elemMatch': {
                'deviceid': deviceid,
                'dest_slice': dest_slice
            }
        }
    }
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlay
        logging.debug(
            'Getting the overlay %s (tenant %s)', overlayid, tenantid
        )
        # Decrease the counter for the tunnel mode
        overlay = overlays.find_one_and_update(
            query,
            {
                '$inc': {
                    'stats.counters.tunnels.$.counter': -1
                }
            },
            return_document=ReturnDocument.AFTER)
        if overlay is None:
            logging.error('Overlay not found or tunnels counter not found')
            return None
        # Return the counter
        counter = -1
        for tunnel in overlay['stats']['counters']['tunnels']:
            if deviceid == tunnel['deviceid'] and \
                    dest_slice == tunnel['dest_slice']:
                counter = tunnel['counter']
        if counter == -1:
            logging.error('Cannot update counter')
            return None
        logging.debug('Counter after the decrement: %s', counter)
        # If counter is 0, remove the tunnel from the overlay stats
        if counter == 0:
            logging.debug('Counter set to 0, removing tunnel mode')
            overlays.update_one(
                query,
                {
                    '$pull': {
                        'stats.counters.tunnels': {
                            'deviceid': deviceid,
                            'dest_slice': dest_slice
                        }
                    }
                }
            )
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Reset the counter of a tunnels on a overlay
def reset_overlay_stats(tenantid, deviceid, overlayid=None):
    # Build the query
    query = {
        'tenantid': tenantid,
        'stats.counters.tunnels.deviceid': deviceid
    }
    if overlayid is not None:
        query['_id'] = ObjectId(overlayid)
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlay
        logging.debug(
            'Removing the overlay stats overlayid %s, deviceid %s (tenant %s)',
            overlayid,
            deviceid,
            tenantid
        )
        # Remove the overlay stats
        overlays.update_many(
            query,
            {
                '$set': {
                    'stats.counters.tunnels.$.counter': 0
                }
            }
        )
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success
    return True


# Update device VTEP MAC address
def update_device_vtep_mac(deviceid, tenantid, device_vtep_mac):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the update
    update = {'$set': {'mgmt_mac': device_vtep_mac}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug(
            'Update device %s (tenant %s) VTEP MAC address', deviceid, tenantid
        )
        logging.debug('New MAC address: %s', device_vtep_mac)
        # Get the device
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot update VTEP MAC address')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if error occurred in connection to the db
    return success


# Update device VTEP IP address
def update_device_vtep_ip(deviceid, tenantid, device_vtep_ip):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the update
    update = {'$set': {'mgmtip': device_vtep_ip}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug(
            'Update device %s (tenant %s) VTEP IP address', deviceid, tenantid
        )
        logging.debug('New IP address: %s', device_vtep_ip)
        # Get the device
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot update VTEP IP address')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if error occurred in connection to the db
    return success


# Get device VTEP MAC address
def get_device_vtep_mac(deviceid, tenantid):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    res = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug(
            'Get device %s (tenant %s) VTEP MAC address', deviceid, tenantid
        )
        # Get the device
        res = devices.find_one(query)['mgmt_mac']
        if res is None:
            logging.error('Device not found')
        else:
            logging.debug('Found VTEP MAC address: %s', res)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the device VTEP MAC address
    return res


def get_tunnel_mode(deviceid, tenantid):
    device = get_device(deviceid, tenantid)
    if device is None:
        return None
    return device['tunnel_mode']


def set_tunnel_mode(deviceid, tenantid, tunnel_mode):
    # Build the query
    query = {'deviceid': deviceid, 'tenantid': tenantid}
    # Build the update
    update = {'$set': {'tunnel_mode': tunnel_mode}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Update device %s tunnel mode', deviceid)
        logging.debug('New tunnel mode: %s', tunnel_mode)
        # Get the device
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot update tunnel mode')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if error occurred in connection to the db
    return success


''' Functions operating on the overlays collection '''


# Create overlay
def create_overlay(
    name,
    type,
    slices,
    tenantid,
    tunnel_mode,
    transport_proto='ipv6'
):
    # Build the document
    overlay = {
        'name': name,
        'tenantid': tenantid,
        'type': type,
        'slices': slices,
        'tunnel_mode': tunnel_mode,
        'vni': None,
        'transport_proto': transport_proto,
        'counters': {
            'reusable_tunnelid': [],
            'last_tunnelid': -1
        },
        'stats': {
            'counters': {
                'tunnels': []
            }
        }
    }
    overlayid = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Add the overlay to the collection
        logging.debug('Creating the overlay: %s', overlay)
        overlayid = overlays.insert_one(overlay).inserted_id
        if overlayid is not None:
            logging.debug('Overlay created successfully')
        else:
            logging.error('Cannot create the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return overlayid


# Remove overlay by ID
def remove_overlay(overlayid, tenantid):
    # Build the filter
    overlay = {'_id': ObjectId(overlayid), 'tenantid': tenantid}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Remove the overlay from the collection
        logging.debug('Removing the overlay: %s', overlayid)
        success = overlays.delete_one(overlay).deleted_count == 1
        if success:
            logging.debug('Overlay removed successfully')
        else:
            logging.error('Cannot remove the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success, False otherwise
    return success


# Remove all the overlays
def remove_all_overlays():
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Delete all the overlays in the collection
        logging.debug('Removing all overlays')
        success = overlays.delete_many({}).acknowledged
        if success:
            logging.debug('Overlays removed successfully')
        else:
            logging.error('Cannot remove the overlays')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success, False otherwise
    return success


# Remove all the overlays of a tenant
def remove_overlays_by_tenantid(tenantid):
    # Build the filter
    filter = {'tenantid': tenantid}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Delete all the overlays in the collection
        logging.debug('Removing all overlays of tenant: %s', tenantid)
        success = overlays.delete_many(filter).acknowledged
        if success:
            logging.debug('Overlays removed successfully')
        else:
            logging.error('Cannot remove the overlays')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success, False otherwise
    return success


# Get overlay
def get_overlay(overlayid, tenantid):
    # Build the query
    query = {'_id': ObjectId(overlayid), 'tenantid': tenantid}
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the device by device ID
        logging.debug('Retrieving overlay %s', overlayid)
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug('Overlay found: %s', overlay)
        else:
            logging.error('Overlay not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay if it exists,
    # None if it does not exist
    # None if an error occurred during the connection to the db
    return overlay


# Get overlays
def get_overlays(overlayids=None, tenantid=None):
    # Build the query
    query = dict()
    if tenantid is not None:
        query['tenantid'] = tenantid
    if overlayids is not None:
        query['_id'] = {
            '$in': [ObjectId(overlayid) for overlayid in overlayids]
        }
    overlays = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the device by device ID
        logging.debug('Retrieving overlays by tenant ID %s', tenantid)
        overlays = list(overlays.find(query))
        logging.debug('Overlays found: %s', overlays)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the list of the overlays if no errors or
    # None if an error occurred during the connection to the db
    return overlays


# Get a overlay by its name
def get_overlay_by_name(name, tenantid):
    # Build the query
    query = {'name': name, 'tenantid': tenantid}
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlay
        logging.debug('Searching the overlay %s, tenant ID %s', name, tenantid)
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug('Overlay found: %s', overlay)
        else:
            logging.debug('Cannot find the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay if it exists,
    # None if it does not exist or an error
    # occurred during the connection to the db
    return overlay


# Return True if an overlay exists
# with the provided name exists, False otherwise
def overlay_exists(name, tenantid):
    # Build the query
    query = {'name': name, 'tenantid': tenantid}
    overlay_exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Count the overlays with the given name and tenant ID
        logging.debug('Searching the overlay %s, tenant ID %s', name, tenantid)
        if overlays.count_documents(query, limit=1):
            logging.debug('The overlay exists')
            overlay_exists = True
        else:
            logging.debug('The overlay does not exist')
            overlay_exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the overlay exists,
    # False if the overlay does not exist
    # or None if an error occurred during the connection to the db
    return overlay_exists


# Add a slice to an overlay
def add_slice_to_overlay(overlayid, tenantid, _slice):
    # Build the query
    query = {'_id': ObjectId(overlayid), 'tenantid': tenantid}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Add the slice to the overlay
        logging.debug('Adding the slice to the overlay %s', overlayid)
        success = overlays.update_one(
            query,
            {
                '$push': {
                    'slices': _slice
                }
            }
        ).matched_count == 1
        if success:
            logging.debug('Slice added to the overlay')
        else:
            logging.error('Cannot add the slice to the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Add many slices to an overlay
def add_many_slices_to_overlay(overlayid, tenantid, slices):
    # Build the query
    query = {'_id': ObjectId(overlayid), 'tenantid': tenantid}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Add the slices to the overlay
        logging.debug('Adding the slice to the overlay %s', overlayid)
        success = overlays.update_one(
            query,
            {'$pushAll': {'slices': slices}}
        ).matched_count == 1
        if success:
            logging.debug('Slices added to the overlay')
        else:
            logging.error('Cannot add the slices to the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if all the slices added to the overlay
    # False if some slice has not been added to the overlay
    # None if an error occurred during the connection to the db
    return success


# Remove a slice from an overlay
def remove_slice_from_overlay(overlayid, tenantid, _slice):
    # Build the query
    query = {'_id': ObjectId(overlayid), 'tenantid': tenantid}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Remove the slice from the overlay
        logging.debug('Removing the slice from the overlay %s', overlayid)
        success = overlays.update_one(
            query,
            {
                '$pull': {
                    'slices': _slice
                }
            }
        ).matched_count == 1
        if success:
            logging.debug('Slice removed from the overlay')
        else:
            logging.error('Cannot remove the slice from the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure or
    # None if an error occurred during the connection to the db
    return success


# Remove many slices from an overlay
def remove_many_slices_from_overlay(overlayid, tenantid, slices):
    # Build the query
    query = {'_id': ObjectId(overlayid), 'tenantid': tenantid}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Remove the slices to the overlay
        logging.debug('Removing the slices from the overlay %s', overlayid)
        success = overlays.update_one(
            query,
            {'$pullAll': {'slices': slices}}
        ).matched_count == 1
        if success:
            logging.debug('Slices removed from the overlay')
        else:
            logging.error('Cannot remove the sices from the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure or
    # None if an error occurred during the connection to the db
    return success


# Retrieve the slices contained in a given overlay
def get_slices_in_overlay(overlayid, tenantid):
    # Get the overlays
    logging.debug('Getting the slices in the overlay %s', overlayid)
    overlay = get_overlay(overlayid, tenantid)
    # Extract the slices from the overlay
    slices = None
    if overlay is not None:
        slices = overlay['slices']
        logging.debug('Slices found: %s', slices)
    # Return the list of the slices if the overlay exists
    # None if the overlay does not exist
    # None if an error occurred during the connection to the db
    return


# Return the overlay which contains the slice,
# None the slice is not assigned to any overlay
def get_overlay_containing_slice(_slice, tenantid):
    # Build the query
    query = {
        'tenantid': tenantid,
        'slices.deviceid': _slice['deviceid'],
        'slices.interface_name': _slice['interface_name']
    }
    # Find the device
    logging.debug(
        'Checking if the slice %s (tenant %s) is assigned to an overlay',
        _slice,
        tenantid
    )
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlays
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug('Slice assigned to the overlay %s', overlay)
        else:
            logging.debug('The slice is not assigned to any overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay
    return overlay


# Return an overlay to which the device is partecipating,
# None the device is not part of any overlay
def get_overlay_containing_device(deviceid, tenantid):
    # Build the query
    query = {
        'tenantid': tenantid,
        'slices.deviceid': deviceid
    }
    # Find the device
    logging.debug(
        'Checking if the device %s (tenant %s) '
        'is partecipating to some overlay',
        deviceid,
        tenantid
    )
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlays
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug(
                'Device is partecipating to the overlay %s', overlay)
        else:
            logging.debug('The device is not partpartecipating to any overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay
    return overlay


# Return all the overlays common to two devices, an empty list if there are
# not common overlays between the two devices, None if an error occurred
def get_overlays_containing_devices(deviceid1, deviceid2, tenantid):
    # Find the overlays
    logging.debug(
        'Retrieving all the overlays containing device %s and '
        'device %s, tenant %s',
        deviceid1,
        deviceid2,
        tenantid
    )
    overlays_list = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlays containing the two devices
        overlays_list = overlays.aggregate(
            [
                {
                    "$match": {
                        'tenantid': tenantid,
                        'slices.deviceid': deviceid1,
                    }
                },
                {
                    "$match": {
                        'tenantid': tenantid,
                        'slices.deviceid': deviceid2,
                    }
                }
            ]
        )
        overlays_list = list(overlays_list)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlays
    return overlays_list


# Return all the overlays to which the device is partecipating,
# None the device is not part of any overlay
def get_overlays_containing_device(deviceid, tenantid):
    # Build the query
    query = {
        'tenantid': tenantid,
        'slices.deviceid': deviceid
    }
    # Find the device
    logging.debug(
        'Checking if the device %s (tenant %s) '
        'is partecipating to some overlay',
        deviceid,
        tenantid
    )
    overlays = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlays
        overlays = list(overlays.find(query))
        if overlays is not None:
            logging.debug(
                'Device is partecipating to the overlays %s', overlays
            )
        else:
            logging.debug('The device is not partpartecipating to any overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay
    return overlays


def reset_created_tunnels(tenantid, deviceid):
    # Build the query
    query = {'tenantid': tenantid}
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        _overlays = overlays.find(query)
        for overlay in _overlays:
            created_tunnels = overlay.get('created_tunnel', None)
            if created_tunnels is None:
                continue
            _created_tunnels = list(overlay['created_tunnel'])
            for idx in range(len(created_tunnels)):
                if created_tunnels[idx]['tunnel_key'].startswith(deviceid):
                    del _created_tunnels[idx]
            # Reset the counter
            query = {
                '_id': overlay['_id'],
                'tenantid': tenantid
            }
            overlays.update_one(
                query,
                {
                    '$set': {
                        'created_tunnel': _created_tunnels
                    }
                }
            )
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


''' Functions operating on the tenants collection '''


# Return the tenant configuration
def get_tenant_config(tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    config = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Find the tenant configuration
        logging.debug('Getting the configuration of the tenant %s', tenantid)
        tenant = tenants.find_one(query)
        if tenant is not None:
            config = tenant.get('config')
            if config is None:
                logging.error('Tenant %s is not configured', tenantid)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the tenant configuration if the tenant exists,
    # None if an error occurred during the connection to the db
    return config


# Return information about tenants
def get_tenant_configs(tenantids):
    # Build the query
    query = {'$in': list(tenantids)}
    configs = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Get the tenant configs
        logging.debug('Getting the tenants %s', tenantids)
        tenants = tenants.find(query, {'conf': 1})
        # Return the configs
        configs = dict()
        for tenant in tenants:
            tenantid = tenant['tenantid']
            if not tenant.get('configured', False):
                logging.error('Tenant %s is not configured', tenantid)
                return None
            configs[tenantid] = {
                'name': tenant['name'],
                'tenantid': tenant['tenantid'],
                'config': tenant['config'],
                'info': tenant['info']
            }
        logging.debug('Configs: %s', configs)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the configurations if no errors,
    # return None if an error occurred during the connection to the db
    return configs


# Return the VXLAN port used by the tenant
# or None if an error occurredduring the connection to the db
def get_tenant_vxlan_port(tenantid):
    # Extract the tenant configuration from the database
    config = get_tenant_config(tenantid)
    if config is not None:
        # Extract the VXLAN port from the tenant configuration
        return config.get('vxlan_port', DEFAULT_VXLAN_PORT)
    else:
        return None


# Get tenant ID by token
def get_tenantid(token):
    # Build the query
    query = {'token': token}
    tenantid = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Get the tenant ID
        logging.debug('Getting the tenant ID')
        tenant = tenants.find_one(query, {'tenantid': 1})
        if tenant is not None:
            # Return the tenant ID
            tenantid = tenant.get('tenantid', None)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the tenant ID if success,
    # return None if an error occurred during the connection to the db
    return tenantid


# Configure a tenant
def configure_tenant(tenantid, tenant_info=None, vxlan_port=None):
    logging.debug(
        'Configuring tenant %s (info %s, vxlan_port %s)',
        tenantid,
        tenant_info,
        vxlan_port
    )
    # Build the query
    query = {'tenantid': tenantid}
    # Build the update statement
    update = {'$set': {
        'configured': True,
        'vtep_ip_index': -1,
        'reu_vtep_ip_addr': [],
        'assigned_vtep_ip_addr': 0,
        'vtep_ipv6_index': -1,
        'reu_vtep_ipv6_addr': [],
        'assigned_vtep_ipv6_addr': 0,
        'vni_index': -1,
        'reu_vni': [],
        'assigned_vni': 0,
        'counters': {
            'tableid': {
                'reusable_tableids': [],
                'last_allocated_tableid': 0
            },
            'ssid': {
                'reusable_ssid': [],
                'last_ssid': 0
            }
        }
    }
    }
    if vxlan_port is not None:
        update['$set']['config.vxlan_port'] = vxlan_port
    if tenant_info is not None:
        update['$set']['info'] = tenant_info
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Configure the tenant
        success = tenants.update_one(query, update).matched_count == 1
        if success:
            logging.debug('Tenant configured successfully')
        else:
            logging.error('Error configuring the tenant')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # return False if failure or
    # return None if an error occurred during the connection to the db
    return success


# Return True if the tenant is configured,
# False otherwise,
# None if an error occurred to the connection to the db
def is_tenant_configured(tenantid):
    logging.debug(
        'Checking if tenant %s already received the configuration', tenantid
    )
    # Build the query
    query = {'tenantid': tenantid}
    is_config = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Configure the tenant
        tenant = tenants.find_one(query)
        if tenant is not None:
            logging.debug('The tenant is configured')
            is_config = tenant.get('configured', False)
        else:
            logging.error('Tenant not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the tenant is configured,
    # False otherwise,
    # None if an error occurred to the connection to the db
    return is_config


# Return True if a tenant exists,
# False otherwise
def tenant_exists(tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    tenant_exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Count the tenants with the given tenant ID
        logging.debug('Searching the tenant %s', tenantid)
        if tenants.count_documents(query, limit=1):
            logging.debug('The tenant exists')
            tenant_exists = True
        else:
            logging.debug('The tenant does not exist')
            tenant_exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the tenant exists,
    # False if the tenant does not exist
    # or None if an error occurred during the connection to the db
    return tenant_exists


def get_tenant(tenantid):
    """
    Return the tenant if the tenant exists, None otherwise.

    Parameters
    ----------
    tenantid : str
        The ID of the tenant.

    Returns
    -------
    dict
        Tenant.
    """
    # Build the query
    query = {'tenantid': tenantid}
    tenant = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Get the tenant
        logging.debug('Searching the tenant %s', tenantid)
        tenant = tenants.find_one(query)
        logging.debug('Found tenant: %s', tenant)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the tenant if the tenant exists, None otherwise
    return tenant


# Allocate and return a new table ID for a overlay
def get_new_tableid(overlayid, tenantid):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tenants collection
    tenants = db.tenants
    # Get a new table ID
    tableid = None
    logging.debug('Getting new table ID for the tenant %s', tenantid)
    try:
        # Build the query
        query = {'tenantid': tenantid}
        # Check if a reusable table ID is available
        tenant = tenants.find_one(query)
        if tenant is None:
            logging.debug('The tenant does not exist')
        else:
            reusable_tableids = (
                tenant['counters']['tableid']['reusable_tableids']
            )
            if len(reusable_tableids) > 0:
                # Get a table ID
                tableid = reusable_tableids.pop()
                # Assign it to the overlay
                if assign_tableid_to_overlay(overlayid, tenantid, tableid):
                    # Remove the table ID from the reusable_tableids list
                    update = {
                        '$set': {
                            'counters.tableid.reusable_tableids': (
                                reusable_tableids
                            )
                        }
                    }
                    if tenants.update_one(query, update).modified_count != 1:
                        logging.error(
                            'Error while updating reusable table IDs list'
                        )
                        tableid = None
                else:
                    tableid = None
            else:
                # No reusable ID, allocate a new table ID
                tenant = tenants.find_one(query)
                if tenantid is not None:
                    tableid = (
                        tenant['counters']['tableid']['last_allocated_tableid']
                    )
                    while True:
                        tableid += 1
                        if tableid not in RESERVED_TABLEIDS:
                            logging.debug('Found table ID: %s', tableid)
                            break
                        logging.debug(
                            'Table ID %s is reserved. Getting new table ID',
                            tableid
                        )
                    # Assign it to the overlay
                    if assign_tableid_to_overlay(overlayid, tenantid, tableid):
                        # Remove the table ID from the reusable_tableids list
                        update = {
                            '$set': {
                                'counters.tableid.last_allocated_tableid': (
                                    tableid
                                )
                            }
                        }
                        if tenants.update_one(
                            query, update
                        ).modified_count != 1:
                            logging.error(
                                'Error while updating reusable table IDs list'
                            )
                            tableid = None
                    else:
                        tableid = None
                else:
                    logging.error('Error in get_new_tableid')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the table ID
    return tableid


# Release a table ID and mark it as reusable
def release_tableid(overlayid, tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tenants collection
    tenants = db.tenants
    # Release the table ID
    logging.debug(
        'Release table ID for overlay %s, tenant %s', overlayid, tenantid
    )
    success = None
    try:
        # Get the table ID assigned to the overlay
        tableid = get_tableid(overlayid, tenantid)
        if tableid is None:
            logging.error(
                'Error while getting table ID assigned to the overlay %s',
                overlayid
            )
            success = False
        else:
            # Remove the table ID from the overlay
            success = remove_tableid_from_overlay(overlayid, tenantid, tableid)
            if success is not True:
                logging.error(
                    'Error while removing table ID %s from the overlay %s',
                    tableid,
                    overlayid
                )
                success = False
            else:
                # Get the overlay
                tenant = tenants.find_one(query)
                if tenant is None:
                    logging.debug('The tenant does not exist')
                else:
                    reusable_tableids = (
                        tenant['counters']['tableid']['reusable_tableids']
                    )
                    # Add the table ID to the reusable table IDs list
                    reusable_tableids.append(tableid)
                    update = {
                        '$set': {
                            'counters.tableid.reusable_tableids': (
                                reusable_tableids
                            )
                        }
                    }
                    if tenants.update_one(query, update).modified_count != 1:
                        logging.error(
                            'Error while updating reusable table IDs list'
                        )
                        success = False
                    else:
                        logging.debug(
                            'Table ID added to reusable_tableids list'
                        )
                        success = True
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Return the table ID assigned to the VPN
# If the VPN has no assigned table IDs, return None
def get_tableid(overlayid, tenantid):
    # Build the query
    query = {'tenantid': tenantid, '_id': ObjectId(overlayid)}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Release the table ID
    logging.debug('Get table ID for the overlay %s (%s)', overlayid, tenantid)
    tableid = None
    try:
        # Get the overlay
        overlay = overlays.find_one(query)
        # Get the table ID assigned to the overlay
        tableid = overlay.get('tableid')
        if tableid is None:
            logging.error('No table ID assigned to the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the table ID or None if error
    return tableid


# Assign a table ID to an overlay
def assign_tableid_to_overlay(overlayid, tenantid, tableid):
    # Build the query
    query = {'tenantid': tenantid, '_id': ObjectId(overlayid)}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Assign the table ID to the overlay
    success = None
    try:
        logging.debug(
            'Trying to assign the table ID %s to the overlay %s',
            tableid,
            overlayid
        )
        # Build the update
        update = {'$set': {'tableid': tableid}}
        # Assign the table ID
        success = overlays.update_one(query, update).modified_count == 1
        if success is False:
            logging.error('Cannot assign table ID')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Remove a table ID from an overlay
def remove_tableid_from_overlay(overlayid, tenantid, tableid):
    # TODO check if tableid is assigned to the overlay
    #
    # Build the query
    query = {'tenantid': tenantid, '_id': ObjectId(overlayid)}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Set the table ID to null for the overlay
    success = None
    try:
        logging.debug(
            'Trying to remove the table ID from the overlay %s', overlayid
        )
        # Build the update
        update = {'$unset': {'tableid': 1}}
        # Remove the table ID
        success = overlays.update_one(query, update).modified_count == 1
        if success is False:
            logging.error('Cannot remove table ID')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Allocate a new private IPv4 address for the device
# If the device already has a IPv4 address, return it
def get_new_mgmt_ipv4(deviceid):
    # Device ID = 0 is used for controller
    if deviceid == '0':
        return '169.254.0.1/16'
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Get a new mgmt IP
    mgmtip = None
    logging.debug('Getting new mgmt IPv4 for the tenant device %s', deviceid)
    try:
        # Build the query
        query = {'config': 'mgmt_counters'}
        # Check if a reusable mgmt IP is available
        mgmt_counters = config.find_one(query)
        if mgmt_counters is None:
            logging.debug('The tenant does not exist')
        else:
            reusable_ipv4_addresses = (
                mgmt_counters['mgmt_address_ipv4']['reusable_addrs']
            )
            if len(reusable_ipv4_addresses) > 0:
                # Get a mgmt IP
                mgmtip = reusable_ipv4_addresses.pop()
                # Remove the mgmt IP from the reusable_ipv4_addresses list
                update = {
                    '$set': {
                        'mgmt_address_ipv4.reusable_addrs': (
                            reusable_ipv4_addresses
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt IPs list'
                    )
                    mgmtip = None
            else:
                # No reusable IPv4, allocate a new mgmt IPv4 address
                net = IPv4Network(
                    mgmt_counters['mgmt_address_ipv4']['mgmt_net']
                )
                last_ip_index = mgmt_counters['mgmt_address_ipv4'][
                    'last_allocated_ip_index'
                ]
                last_ip_index += 1
                mgmtip = str(net[last_ip_index]) + '/' + str(net.prefixlen)
                update = {
                    '$set': {
                        'mgmt_address_ipv4.last_allocated_ip_index': (
                            last_ip_index
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating last_allocated_ip_index'
                    )
                    mgmtip = None
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the mgmt IP
    return mgmtip


# Allocate a new private IPv6 address for the device
# If the device already has a IPv6 address, return it
def get_new_mgmt_ipv6(deviceid):
    # Device ID = 0 is used for controller
    if deviceid == '0':
        return 'fcfa::1/16'
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Get a new mgmt IP
    mgmtip = None
    logging.debug(
        'Getting new mgmt IPv6 for the tenant %s and device %s', deviceid
    )
    try:
        # Build the query
        query = {'config': 'mgmt_counters'}
        # Check if a reusable mgmt IP is available
        mgmt_counters = config.find_one(query)
        if mgmt_counters is None:
            logging.debug('The mgmt_counters does not exist')
        else:
            reusable_ipv6_addresses = (
                mgmt_counters['mgmt_address_ipv6']['reusable_addrs']
            )
            if len(reusable_ipv6_addresses) > 0:
                # Get a mgmt IP
                mgmtip = reusable_ipv6_addresses.pop()
                # Remove the mgmt IP from the reusable_ipv6_addresses list
                update = {
                    '$set': {
                        'counters.mgmt_address_ipv6.reusable_addrs': (
                            reusable_ipv6_addresses
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt IPs list'
                    )
                    mgmtip = None
            else:
                # No reusable IPv6, allocate a new mgmt IPv6 address
                net = IPv6Network(
                    mgmt_counters['mgmt_address_ipv6']['mgmt_net']
                )
                last_ip_index = mgmt_counters['mgmt_address_ipv6'][
                    'last_allocated_ip_index'
                ]
                last_ip_index += 1
                mgmtip = str(net[last_ip_index]) + '/' + str(net.prefixlen)
                update = {
                    '$set': {
                        'mgmt_address_ipv6.last_allocated_ip_index': (
                            last_ip_index
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating last_allocated_ip_index'
                    )
                    mgmtip = None
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the mgmt IP
    return mgmtip


# Release the IPv4 address associated to the device
def release_ipv4_address(deviceid, tenantid):
    # Build the query
    query = {'config': 'mgmt_counters'}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Release the IPv4 adddress
    logging.debug('Release IPv4 address for device %s', deviceid)
    success = None
    try:
        # Find the device
        device = get_device(deviceid, tenantid)
        if device is not None:
            # Get the mgmtip
            mgmtip = device['mgmtip']
            # Get the tenant
            mgmt_counters = config.find_one(query)
            if mgmt_counters is None:
                logging.debug('The mgmt_counters does not exist')
            else:
                reusable_addrs = (
                    mgmt_counters['mgmt_address_ipv4']['reusable_addrs']
                )
                prefixlen = mgmt_counters['mgmt_address_ipv4'][
                    'mgmt_net'
                ].split('/')[1]
                # Add the mgmt IPv4 to the reusable addresses list
                reusable_addrs.append(mgmtip + '/' + str(prefixlen))
                update = {
                    '$set': {
                        'mgmt_address_ipv4.reusable_addrs': reusable_addrs
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt IPs list'
                    )
                    success = False
                else:
                    logging.debug('Mgmt IP added to reusable_addrs list')
                    success = True
        else:
            logging.error('Device not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Release the IPv6 address associated to the device
def release_ipv6_address(deviceid, tenantid):
    # Build the query
    query = {'config': 'mgmt_counters'}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Release the IPv6 adddress
    logging.debug('Release IPv6 address device %s', deviceid)
    success = None
    try:
        # Find the device
        device = get_device(deviceid, tenantid)
        if device is not None:
            # Get the mgmtip
            mgmtip = device['mgmtip']
            # Get the counters
            mgmt_counters = config.find_one(query)
            if mgmt_counters is None:
                logging.debug('The mgmt_counters does not exist')
            else:
                reusable_addrs = (
                    mgmt_counters['mgmt_address_ipv6']['reusable_addrs']
                )
                prefixlen = mgmt_counters['mgmt_address_ipv6'][
                    'mgmt_net'
                ].split('/')[1]
                # Add the mgmt IPv6 to the reusable addresses list
                reusable_addrs.append(mgmtip + '/' + str(prefixlen))
                update = {
                    '$set': {
                        'mgmt_address_ipv6.reusable_addrs': reusable_addrs
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt IPs list'
                    )
                    success = False
                else:
                    logging.debug('Mgmt IP added to reusable_addrs list')
                    success = True
        else:
            logging.error('Device not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Allocate a new private IPv4 net for the device
# If the device already has a IPv4 net, return it
def get_new_mgmt_ipv4_net(deviceid):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Get a new mgmt net
    mgmtnet = None
    logging.debug('Getting new mgmt IPv4 net for the device %s', deviceid)
    try:
        # Build the query
        query = {'config': 'mgmt_counters'}
        # Check if a reusable mgmt net is available
        mgmt_counters = config.find_one(query)
        if mgmt_counters is None:
            logging.debug('The mgmt_counters does not exist')
        else:
            reusable_ipv4_nets = (
                mgmt_counters['mgmt_subnet_ipv4']['reusable_subnets']
            )
            if len(reusable_ipv4_nets) > 0:
                # Get a mgmt net
                mgmtnet = reusable_ipv4_nets.pop()
                # Remove the mgmt net from the reusable_ipv4_nets list
                update = {
                    '$set': {
                        'counters.mgmt_subnet_ipv4.reusable_nets': (
                            reusable_ipv4_nets
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt nets list'
                    )
                    mgmtnet = None
            else:
                # No reusable IPv4, allocate a new mgmt IPv4 net
                net = IPv4Network(
                    mgmt_counters['mgmt_subnet_ipv4']['mgmt_net']
                )
                last_subnet_index = mgmt_counters['mgmt_subnet_ipv4'][
                    'last_allocated_subnet_index'
                ]
                last_subnet_index += 1
                mgmtnet = str(next(itertools.islice(
                    net.subnets(new_prefix=30), last_subnet_index, None
                )))
                update = {
                    '$set': {
                        'mgmt_subnet_ipv4.last_allocated_subnet_index': (
                            last_subnet_index
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating last_allocated_subnet_index'
                    )
                    mgmtnet = None
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the mgmt net
    return mgmtnet


# Allocate a new private IPv6 net for the device
# If the device already has a IPv6 net, return it
def get_new_mgmt_ipv6_net(deviceid):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Get a new mgmt net
    mgmtnet = None
    logging.debug('Getting new mgmt IPv6 net for the device %s', deviceid)
    try:
        # Build the query
        query = {'config': 'mgmt_counters'}
        # Check if a reusable mgmt net is available
        mgmt_counters = config.find_one(query)
        if mgmt_counters is None:
            logging.debug('The mgmt_counters does not exist')
        else:
            reusable_ipv6_nets = (
                mgmt_counters['mgmt_subnet_ipv6']['reusable_subnets']
            )
            if len(reusable_ipv6_nets) > 0:
                # Get a mgmt net
                mgmtnet = reusable_ipv6_nets.pop()
                # Remove the mgmt net from the reusable_ipv6_nets list
                update = {
                    '$set': {
                        'counters.mgmt_subnet_ipv6.reusable_nets': (
                            reusable_ipv6_nets
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt nets list'
                    )
                    mgmtnet = None
            else:
                # No reusable IPv6, allocate a new mgmt IPv6 net
                net = IPv6Network(
                    mgmt_counters['mgmt_subnet_ipv6']['mgmt_net']
                )
                last_subnet_index = mgmt_counters['mgmt_subnet_ipv6'][
                    'last_allocated_subnet_index'
                ]
                last_subnet_index += 1
                mgmtnet = str(next(itertools.islice(
                    net.subnets(new_prefix=30), last_subnet_index, None
                )))
                update = {
                    '$set': {
                        'mgmt_subnet_ipv6.last_allocated_subnet_index': (
                            last_subnet_index
                        )
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating last_allocated_subnet_index'
                    )
                    mgmtnet = None
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the mgmt net
    return mgmtnet


# Release the IPv4 net associated to the device
def release_ipv4_net(deviceid, tenantid):
    # Build the query
    query = {'config': 'mgmt_counters'}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Release the IPv4 net
    logging.debug('Release IPv4 for device %s', deviceid)
    success = None
    try:
        # Find the device
        device = get_device(deviceid, tenantid)
        if device is not None:
            # Get the mgmtip
            mgmtip = device['mgmtip']
            # Get the mgmt_counters
            mgmt_counters = config.find_one(query)
            if mgmt_counters is None:
                logging.debug('The mgmt_counters does not exist')
            else:
                reusable_nets = (
                    mgmt_counters['mgmt_subnet_ipv4']['reusable_subnets']
                )
                # Add the mgmt IPv4 to the reusable nets list
                reusable_nets.append(
                    str(IPv4Interface(mgmtip + '/30').network)
                )
                update = {
                    '$set': {
                        'mgmt_subnet_ipv4.reusable_nets': reusable_nets
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt IPs list'
                    )
                    success = False
                else:
                    logging.debug('Mgmt IP added to reusable_nets list')
                    success = True
        else:
            logging.error('Device not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Release the IPv6 net associated to the device
def release_ipv6_net(deviceid, tenantid):
    # Build the query
    query = {'config': 'mgmt_counters'}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Release the IPv6 net
    logging.debug(
        'Release IPv6 net for device %s and tenant %s', deviceid, tenantid
    )
    success = None
    try:
        # Find the device
        device = get_device(deviceid, tenantid)
        if device is not None:
            # Get the mgmtip
            mgmtip = device['mgmtip']
            # Get the mgmt_counters
            mgmt_counters = config.find_one(query)
            if mgmt_counters is None:
                logging.debug('The mgmt_counters does not exist')
            else:
                reusable_nets = (
                    mgmt_counters['mgmt_subnet_ipv6']['reusable_subnets']
                )
                # Add the mgmt IPv6 to the reusable nets list
                reusable_nets.append(
                    str(IPv6Interface(mgmtip + '/30').network)
                )
                update = {
                    '$set': {
                        'mgmt_subnet_ipv6.reusable_nets': reusable_nets
                    }
                }
                if config.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable mgmt IPs list')
                    success = False
                else:
                    logging.debug('Mgmt IP added to reusable_nets list')
                    success = True
        else:
            logging.error('Device not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Return the private IP of the device
def get_device_mgmtip(tenantid, deviceid):
    # Build the query
    query = {'deviceid': deviceid}
    if tenantid is not None:
        query['tenantid'] = tenantid
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Get management IP of device
    logging.debug(
        'Getting management IP of device %s (tenant %s)', deviceid, tenantid)
    mgmtip = None
    try:
        # Get the device
        device = devices.find_one(query)
        if device is None:
            logging.debug('The device does not exist')
        else:
            mgmtip = device['mgmtip']
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the management IP or None in case of failure
    return mgmtip


# Device authentication
def authenticate_device(token):
    tenantid = get_tenantid(token)
    return tenantid is not None, tenantid


# Allocate and return a new VNI for the overlay
def get_new_vni(overlay_name, tenantid):
    # Get reference to mongo DB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get overlays collection
    overlays = db.overlays
    # Get tenants collection
    tenants = db.tenants
    # The overlay of the considered tenant already has a VNI
    if overlays.find_one(
        {
            'name': overlay_name,
            'tenantid': tenantid
        },
        {
            'vni': 1
        }
    )['vni'] is not None:
        return -1
    # Overlay does not have a VNI
    else:
        # Check if a reusable VNI is available
        if not tenants.find_one(
            {
                'tenantid': tenantid,
                'reu_vni': {
                    '$size': 0
                }
            }
        ):
            # Pop vni from the array
            vnis = tenants.find_one({'tenantid': tenantid})['reu_vni']
            vni = vnis.pop()
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {
                        'reu_vni': vnis
                    }
                }
            )
        else:
            # If not, get a new VNI
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$inc': {
                        'vni_index': +1
                    }
                }
            )
            while tenants.find_one(
                {
                    'tenantid': tenantid
                },
                {
                    'vni_index': 1
                }
            )['vni_index'] in RESERVED_VNI:
                # Skip reserved VNI
                tenants.find_one_and_update(
                    {
                        'tenantid': tenantid
                    },
                    {
                        '$inc': {
                            'vni_index': +1
                        }
                    }
                )
            # Get VNI
            vni = tenants.find_one(
                {
                    'tenantid': tenantid
                },
                {
                    'vni_index': 1
                }
            )['vni_index']
        # Assign the VNI to the overlay
        overlays.find_one_and_update(
            {
                'tenantid': tenantid,
                'name': overlay_name
            },
            {
                '$set': {'vni': vni}
            }
        )
        # Increase assigned VNIs counter
        tenants.find_one_and_update(
            {
                'tenantid': tenantid
            },
            {
                '$inc': {'assigned_vni': +1}
            }
        )
        # And return
        return vni


# Return the VNI assigned to the Overlay
# If the Overlay has no assigned VNI, return -1
def get_vni(overlay_name, tenantid):
    # Get reference to mongo DB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get overlays collection
    overlays = db.overlays
    # Get VNI
    vni = overlays.find_one(
        {
            'name': overlay_name,
            'tenantid': tenantid
        },
        {'vni': 1}
    )['vni']
    if vni is None:
        return -1
    else:
        return vni


# Release VNI and mark it as reusable
def release_vni(overlay_name, tenantid):
    # Get reference to mongo DB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get overlays collection
    overlays = db.overlays
    # Get tenants collection
    tenants = db.tenants
    # Check if the overlay has an associated VNI
    vni = overlays.find_one(
        {
            'name': overlay_name,
            'tenantid': tenantid
        },
        {
            'vni': 1
        }
    )['vni']
    # If VNI is valid
    if vni is not None:
        # Unassign the VNI
        overlays.find_one_and_update(
            {
                'tenantid': tenantid,
                'name': overlay_name
            },
            {
                '$set': {'vni': None}
            }
        )
        # Decrease assigned VNIs counter
        tenants.find_one_and_update(
            {
                'tenantid': tenantid
            },
            {
                '$inc': {
                    'assigned_vni': -1
                }
            }
        )
        # Mark the VNI as reusable
        tenants.update_one(
            {
                'tenantid': tenantid
            },
            {
                '$push': {'reu_vni': vni}
            }
        )
        # If the tenant has no overlays
        if tenants.find_one(
            {
                'tenantid': tenantid
            },
            {
                'assigned_vni': 1
            }
        )['assigned_vni'] == 0:
            # reset counter
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'vni_index': -1}
                }
            )
            # empty reusable VNI list
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'reu_vni': []}
                }
            )
        return vni
    else:
        # The overlay has not associated VNI
        return -1


def get_new_vtep_ip(dev_id, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Devices collection
    devices = db.devices
    # Tenants collection
    tenants = db.tenants
    # ip address availale
    ip = IPv4Network('198.18.0.0/16')
    network_mask = 16
    # The device of the considered tenant already has an associated VTEP IP
    if devices.find_one(
        {
            'deviceid': dev_id,
            'tenantid': tenantid
        },
        {
            'vtep_ip_addr': 1
        }
    )['vtep_ip_addr'] is not None:
        return -1
    # The device does not have a VTEP IP address
    else:
        # Check if a reusable VTEP IP is available
        if not tenants.find_one(
            {
                'tenantid': tenantid,
                'reu_vtep_ip_addr': {'$size': 0}
            }
        ):
            # Pop VTEP IP adress from the array
            vtep_ips = tenants.find_one(
                {
                    'tenantid': tenantid
                }
            )['reu_vtep_ip_addr']
            vtep_ip = vtep_ips.pop()
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'reu_vtep_ip_addr': vtep_ips}
                }
            )
        else:
            # If not, get a VTEP IP address
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$inc': {'vtep_ip_index': +1}
                }
            )
            while tenants.find_one(
                {
                    'tenantid': tenantid
                },
                {
                    'vtep_ip_index': 1
                }
            )['vtep_ip_index'] in RESERVED_VTEP_IP:
                # Skip reserved VTEP IP address
                tenants.find_one_and_update(
                    {
                        'tenantid': tenantid
                    },
                    {
                        '$inc': {'vtep_ip_index': +1}
                    }
                )
            # Get IP address
            ip_index = tenants.find_one(
                {
                    'tenantid': tenantid
                },
                {
                    'vtep_ip_index': 1
                }
            )['vtep_ip_index']
            vtep_ip = "%s/%s" % (ip[ip_index], network_mask)
        # Assign the VTEP IP address to the device
        devices.find_one_and_update(
            {
                'tenantid': tenantid,
                'deviceid': dev_id
            },
            {
                '$set': {'vtep_ip_addr': vtep_ip}
            }
        )
        # Increase assigned VTEP IP addr counter
        tenants.find_one_and_update(
            {
                'tenantid': tenantid
            },
            {
                '$inc': {'assigned_vtep_ip_addr': +1}
            }
        )
        # And return
        return vtep_ip


def get_new_vtep_ipv6(dev_id, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Devices collection
    devices = db.devices
    # Tenants collection
    tenants = db.tenants
    # ip address availale
    ip = IPv6Network('fc00::/64')
    network_mask = 64
    # The device of the considered tenant already has an associated VTEP IP
    if devices.find_one(
        {
            'deviceid': dev_id,
            'tenantid': tenantid
        },
        {
            'vtep_ipv6_addr': 1
        }
    )['vtep_ipv6_addr'] is not None:
        return -1
    # The device does not have a VTEP IP address
    else:
        # Check if a reusable VTEP IP is available
        if not tenants.find_one(
            {
                'tenantid': tenantid,
                'reu_vtep_ipv6_addr': {'$size': 0}
            }
        ):
            # Pop VTEP IP adress from the array
            vtep_ips = tenants.find_one(
                {
                    'tenantid': tenantid
                }
            )['reu_vtep_ipv6_addr']
            vtep_ip = vtep_ips.pop()
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'reu_vtep_ipv6_addr': vtep_ips}
                }
            )
        else:
            # If not, get a VTEP IP address
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$inc': {'vtep_ipv6_index': +1}
                }
            )
            while tenants.find_one(
                {
                    'tenantid': tenantid
                },
                {
                    'vtep_ipv6_index': 1
                }
            )['vtep_ipv6_index'] in RESERVED_VTEP_IPV6:
                # Skip reserved VTEP IP address
                tenants.find_one_and_update(
                    {
                        'tenantid': tenantid
                    },
                    {
                        '$inc': {'vtep_ipv6_index': +1}
                    }
                )
            # Get IP address
            ip_index = tenants.find_one(
                {
                    'tenantid': tenantid
                },
                {
                    'vtep_ipv6_index': 1
                }
            )['vtep_ipv6_index']
            vtep_ip = "%s/%s" % (ip[ip_index], network_mask)
        # Assign the VTEP IP address to the device
        devices.find_one_and_update({
            'tenantid': tenantid,
            'deviceid': dev_id}, {
            '$set': {'vtep_ipv6_addr': vtep_ip}
        }
        )
        # Increase assigned VTEP IP addr counter
        tenants.find_one_and_update(
            {
                'tenantid': tenantid
            },
            {
                '$inc': {'assigned_vtep_ipv6_addr': +1}
            }
        )
        # And return
        return vtep_ip


# Return VTEP IP adress assigned to the device
# If device has no VTEP IP address return -1
def get_vtep_ip(dev_id, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Devices collection
    devices = db.devices
    # Get VTEP IP
    vtep_ip = devices.find_one(
        {
            'deviceid': dev_id,
            'tenantid': tenantid
        },
        {
            'vtep_ip_addr': 1
        }
    )['vtep_ip_addr']
    if vtep_ip is None:
        return -1
    else:
        return vtep_ip


# Return VTEP IP adress assigned to the device
# If device has no VTEP IP address return -1
def get_vtep_ipv6(dev_id, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Devices collection
    devices = db.devices
    # Get VTEP IP
    vtep_ip = devices.find_one(
        {
            'deviceid': dev_id,
            'tenantid': tenantid
        },
        {
            'vtep_ipv6_addr': 1
        }
    )['vtep_ipv6_addr']
    if vtep_ip is None:
        return -1
    else:
        return vtep_ip


# Release VTEP IP and mark it as reusable
def release_vtep_ip(dev_id, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Devices collection
    devices = db.devices
    # Tenants collection
    tenants = db.tenants
    # Get device VTEP IP address
    vtep_ip = devices.find_one(
        {
            'deviceid': dev_id,
            'tenantid': tenantid
        },
        {
            'vtep_ip_addr': 1
        }
    )['vtep_ip_addr']
    # If IP address is valid
    if vtep_ip is not None:
        # Unassign the VTEP IP addr
        devices.find_one_and_update(
            {
                'tenantid': tenantid,
                'deviceid': dev_id
            },
            {
                '$set': {'vtep_ip_addr': None}
            }
        )
        # Decrease assigned VTEP IP addr counter
        tenants.find_one_and_update(
            {
                'tenantid': tenantid
            },
            {
                '$inc': {'assigned_vtep_ip_addr': -1}
            }
        )
        # Mark the VTEP IP addr as reusable
        tenants.update_one(
            {
                'tenantid': tenantid
            },
            {
                '$push': {'reu_vtep_ip_addr': vtep_ip}
            }
        )
        # If all addresses have been released
        if tenants.find_one(
            {
                'tenantid': tenantid
            },
            {
                'assigned_vtep_ip_addr': 1
            }
        )['assigned_vtep_ip_addr'] == 0:
            # reset the counter
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'vtep_ip_index': -1}
                }
            )
            # empty reusable address list
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'reu_vtep_ip_addr': []}
                }
            )
        # Return the VTEP IP
        return vtep_ip
    else:
        # The device has no associeted VTEP IP
        return -1


# Release VTEP IP and mark it as reusable
def release_vtep_ipv6(dev_id, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Devices collection
    devices = db.devices
    # Tenants collection
    tenants = db.tenants
    # Get device VTEP IP address
    vtep_ip = devices.find_one(
        {
            'deviceid': dev_id,
            'tenantid': tenantid
        },
        {
            'vtep_ipv6_addr': 1
        }
    )['vtep_ipv6_addr']
    # If IP address is valid
    if vtep_ip is not None:
        # Unassign the VTEP IP addr
        devices.find_one_and_update(
            {
                'tenantid': tenantid,
                'deviceid': dev_id
            },
            {
                '$set': {'vtep_ipv6_addr': None}
            }
        )
        # Decrease assigned VTEP IP addr counter
        tenants.find_one_and_update(
            {
                'tenantid': tenantid
            },
            {
                '$inc': {'assigned_vtep_ipv6_addr': -1}
            }
        )
        # Mark the VTEP IP addr as reusable
        tenants.update_one(
            {
                'tenantid': tenantid
            },
            {
                '$push': {'reu_vtep_ipv6_addr': vtep_ip}
            }
        )
        # If all addresses have been released
        if tenants.find_one(
            {
                'tenantid': tenantid
            },
            {
                'assigned_vtep_ipv6_addr': 1
            }
        )['assigned_vtep_ipv6_addr'] == 0:
            # reset the counter
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'vtep_ipv6_index': -1}
                }
            )
            # empty reusable address list
            tenants.find_one_and_update(
                {
                    'tenantid': tenantid
                },
                {
                    '$set': {'reu_vtep_ipv6_addr': []}
                }
            )
        # Return the VTEP IP
        return vtep_ip
    else:
        # The device has no associeted VTEP IP
        return -1


def add_tunnel_to_overlay(overlayid, ldeviceid, rdeviceid, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Overlays collection
    overlays = db.overlays
    # Check if a reusable tunnel ID is available
    if not overlays.find_one(
        {
            '_id': ObjectId(overlayid),
            'tenantid': tenantid,
            'counters.reusable_tunnelid': {'$size': 0}
        }
    ):
        # Pop tunnel ID from the array
        tunnelid_array = overlays.find_one(
            {
                '_id': ObjectId(overlayid),
                'tenantid': tenantid
            }
        )['counters']['reusable_tunnelid']
        tunnelid = tunnelid_array.pop()
        overlays.find_one_and_update(
            {
                '_id': ObjectId(overlayid),
                'tenantid': tenantid
            },
            {
                '$set': {'counters.reusable_tunnelid': tunnelid_array}
            }
        )
    else:
        # If not, get a tunnel ID
        overlays.find_one_and_update(
            {
                '_id': ObjectId(overlayid),
                'tenantid': tenantid
            },
            {
                '$inc': {'counters.last_tunnelid': +1}
            }
        )
        while overlays.find_one(
            {
                '_id': ObjectId(overlayid),
                'tenantid': tenantid
            },
            {
                'counters.last_tunnelid': 1
            }
        )['counters']['last_tunnelid'] in RESERVED_TUNNELID:
            # Skip reserved tunnel IDs
            overlays.find_one_and_update(
                {
                    '_id': ObjectId(overlayid),
                    'tenantid': tenantid
                },
                {
                    '$inc': {'counters.last_tunnelid': +1}
                }
            )
        # Get tunnel ID
        tunnelid = overlays.find_one(
            {
                '_id': ObjectId(overlayid),
                'tenantid': tenantid
            },
            {
                'counters.last_tunnelid': 1
            }
        )['counters']['last_tunnelid']
    tunnel_name = 'tnl' + str(tunnelid)
    new_tunnel = {
        'tunnelid': tunnelid,
        'ldeviceid': ldeviceid,
        'rdeviceid': rdeviceid,
        'tunnel_name': tunnel_name
    }
    # Assign the VTEP IP address to the device
    overlays.find_one_and_update(
        {
            'tenantid': tenantid,
            '_id': ObjectId(overlayid)
        },
        {
            '$push': {'tunnels': new_tunnel}
        }
    )
    # And return
    return new_tunnel


def get_tunnel(overlayid, ldeviceid, rdeviceid, tenantid):
    # Build the query
    query = {'tenantid': tenantid, '_id': ObjectId(overlayid)}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Get the tunnel
    logging.debug('Get tunnel for the overlay %s (%s)', overlayid, tenantid)
    tunnel = None
    try:
        # Get the overlay
        overlay = overlays.find_one(query)
        # Get the table ID assigned to the overlay
        tunnels = overlay.get('tunnels')
        if tunnels is None:
            logging.error('No tunnels array available for the overlay')
        else:
            for _tunnel in tunnels:
                if (
                    _tunnel['ldeviceid'] == ldeviceid
                    and _tunnel['rdeviceid'] == rdeviceid
                ):
                    tunnel = _tunnel
                    break
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the tunnel or None if error
    return tunnel


# Release tunnel ID and mark it as reusable
def remove_tunnel_from_overlay(overlayid, ldeviceid, rdeviceid, tenantid):
    # Get the collections
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Overlays collection
    overlays = db.overlays
    # Get tunnel ID
    tunnel = get_tunnel(overlayid, ldeviceid, rdeviceid, tenantid)
    # If tunnel is valid
    if tunnel is not None:
        tunnelid = tunnel['tunnelid']
        # Get the overlay
        overlay = overlays.find_one(
            {
                'tenantid': tenantid,
                '_id': ObjectId(overlayid)
            }
        )
        # Remove the tunnel from the overlay
        tunnels = overlay['tunnels']
        for i in range(len(tunnels)):
            _tunnel = tunnels[i]
            if (
                _tunnel['ldeviceid'] == ldeviceid
                and _tunnel['rdeviceid'] == rdeviceid
            ):
                tunnel = _tunnel
                break
        if tunnel is None:
            logging.error('Tunnel not found')
            return None
        del tunnels[i]
        overlays.find_one_and_update(
            {
                'tenantid': tenantid,
                '_id': ObjectId(overlayid)
            },
            {
                '$set': {'tunnels': tunnels}
            }
        )
        # Mark the tunnel ID as reusable
        overlays.update_one(
            {
                '_id': ObjectId(overlayid),
                'tenantid': tenantid
            },
            {
                '$push': {'counters.reusable_tunnelid': tunnelid}
            }
        )
        # Return the tunnel
        return tunnel
    else:
        # The tunnel does not exist
        logging.error('Tunnel not found')
        return -1


# Get the counter of reconciliation failures for a device and increase the
# counter
def inc_and_get_reconciliation_failures(tenantid, deviceid):
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug(
            'Getting the device %s (tenant %s)', deviceid, tenantid
        )
        # Build query
        query = {
            'deviceid': deviceid,
            'tenantid': tenantid
        }
        # Build the update
        update = {'$inc': {'stats.counters.reconciliation_failures': 1}}
        # Increase the tunnels counter for the device
        device = devices.find_one_and_update(
            query, update, return_document=ReturnDocument.AFTER
        )
        # Return the counter
        counter = device['stats']['counters']['reconciliation_failures']
        logging.debug('Counter after the increment: %s' % counter)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Reset the counter of reconciliation failures for a device
def reset_reconciliation_failures(tenantid, deviceid):
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug(
            'Getting the device %s (tenant %s)', deviceid, tenantid
        )
        # Build query
        query = {
            'deviceid': deviceid,
            'tenantid': tenantid
        }
        # Build the update
        update = {'$set': {'stats.counters.reconciliation_failures': 0}}
        # Reset the tunnels counter for the device
        success = devices.update_one(query, update).matched_count == 1
        if success:
            logging.debug('Reset reconciliation failures successful')
            if success is not False:
                success = True
        else:
            logging.error('Cannot reset reconciliation failures counter')
            success = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return success


""" Topology """


# Return the topology
def get_topology():
    raise NotImplementedError


""" Init database """


def init_db():
    # Build the query
    query = {'config': 'mgmt_counters'}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the configuration collection
    config = db.configuration
    # Build document
    mgmt_counters = {
        '$set': {
            'mgmt_address_ipv4': {
                'mgmt_net': str(IPv4Network('169.254.0.0/16')),
                'last_allocated_ip_index': 1,
                'reusable_addrs': []
            },
            'mgmt_address_ipv6': {
                'mgmt_net': str(IPv6Network('fcfa::/16')),
                'last_allocated_ip_index': 1,
                'reusable_addrs': []
            },
            'mgmt_subnet_ipv4': {
                'mgmt_net': str(IPv4Network('198.19.0.0/16')),
                'last_allocated_subnet_index': 0,
                'reusable_subnets': []
            },
            'mgmt_subnet_ipv6': {
                'mgmt_net': str(IPv6Interface('fcfc::/16')),
                'last_allocated_subnet_index': 0,
                'reusable_subnets': []
            }
        }
    }
    success = None
    try:
        # Update document
        res = config.update_one(
            query, mgmt_counters, upsert=True)
        if res.matched_count == 1 or res.upserted_id is not None:
            success = True
            logging.debug('Database initialized successfull')
        else:
            logging.error('Error in database initialization')
            success = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Success
    return success
