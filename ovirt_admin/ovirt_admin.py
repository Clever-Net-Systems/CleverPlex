#! /usr/bin/python
# coding: utf-8
################################################################################
#   Clever Net Systems [~]                                                     #
#   Clément Hampaï <clement.hampai@clevernetsystems.com>                       #
#   oVirt administration script using oVirt api                                #
################################################################################
# oVirt SDK required
# Installation:
#   yum install http://resources.ovirt.org/pub/yum-repo/ovirt-release35.rpm
#   yum install ovirt-engine-sdk-python

import argparse, thread, sys, json, inspect, time, random, os, paramiko, ConfigParser
from ovirtsdk.api import API
from ovirtsdk.xml import params
from paramiko import SSHClient
from scp import SCPClient

VERSION = params.Version()
def init():
    configuration_file_path = "/etc/ovirt_admin/settings.conf"
    settings = ConfigParser.ConfigParser()
    settings.read(configuration_file_path)
    api_url = settings.get('authent', "api_url")
    api_username = settings.get('authent', "api_username")
    api_password = settings.get('authent', "api_password")
    VERSION = params.Version(major=settings.get('api_version', 'major'), minor=settings.get('api_version', 'minor'))
    api = API(url=api_url, username=api_username, password=api_password,insecure=True)
    print "\n"
    return api

# DATACENTERS ------------------------------------------------------------------
def create_datacenter(datacentername, storagetype):
    display_title("Creating a new data center "+str(datacentername))
    try:
        print '\t[~] Creating datacenter...'
        if api.datacenters.add(params.DataCenter(name=datacentername, storage_type=storagetype, version=VERSION)):
            print '\t[~] Data Center was created successfully'
    except Exception as e:
        print '\t[!] Failed to create '+str(storagetype)+' Data Center:'
        print  "\t "+str(e)

def destroy_datacenter(datacentername):
    display_title("Destroying data center "+str(datacentername))
    try:
        print '\t[~] Destroying datacenter...'
        dtcenter = api.datacenters.get(name=datacentername)
        if dtcenter.delete():
            print '\t[~] Data Center was destroyed successfully'
    except Exception as e:
        print '\t[!] Failed to destroy Data Center:'
        print  "\t "+str(e)
# ------------------------------------------------------------------------------

# CLUSTERS ------------------------------------------------------------------
def create_cluster(clustername, datacentername, cputype):
    display_title("Creating cluster "+str(clustername))
    try:
        print '\t[~] Creating cluster...'
        cluster = api.clusters.add(params.Cluster(name=clustername, cpu=params.CPU(id=cputype), data_center=api.datacenters.get(datacentername), version=VERSION))
        if cluster:
            print '\t[~] Cluster was created successfully'
    except Exception as e:
        print '\t[!] Failed to create the new cluster:'
        print  "\t "+str(e)

def destroy_cluster(clustername):
    display_title("Destroying cluster "+str(clustername))
    try:
        print '\t[~] Destroying cluster...'
        cluster = api.clusters.get(name=clustername)
        if cluster.delete():
            print '\t[~] Cluster was destroyed successfully'
    except Exception as e:
        print '\t[!] Failed to destroy the cluster:'
        print  "\t "+str(e)
# ------------------------------------------------------------------------------

# HOSTS ------------------------------------------------------------------------
def create_new_host_in_cluster(hostname, hostaddr, clustername, rootpwd):
    display_title("Creating a new oVirt Host "+str(hostname))
    try:
        print '\t[~] Installing new host...'
        host = api.hosts.add(params.Host(name=hostname, address=hostaddr, cluster=api.clusters.get(clustername), root_password=rootpwd))
        if host:
            print '\t[~] Host was installed successfully'
            print '\t[~] Waiting for host to reach the "up" status'
            wait_host_for_state(host, "up")
            print "\t[~] Host is up"
            print '\t\t Can...you...heaheahear...me ?'
    except Exception as e:
        print '\t[!] Failed to install Host:'
        print  "\t "+str(e)

def set_host_deactive(hostname):
    display_title("Deactivating host "+str(hostname))
    try:
        host = api.hosts.get(name=hostname)
        if host.deactivate():
            print '\t[~] Waiting for host to reach the "maintenance" status'
            wait_host_for_state(host, "maintenance")
            print '\t[~] Host was deactivated successfully'
    except Exception as e:
        print '\t[!] Failed to deactivate Host:'
        print  "\t "+str(e)

def set_host_active(hostname):
    display_title("Activating host "+str(hostname))
    try:
        host = api.hosts.get(name=hostname)
        if host.activate():
            print '\t[~] Waiting for host to reach the "up" status'
            wait_host_for_state(host, "up")
            print '\t[~] Host was activaed successfully'
            print '\t\t Can...you...heaheahear...me ?'
    except Exception as e:
        print '\t[!] Failed to activate Host:'
        print  "\t "+str(e)

def destroy_host(hostname):
    display_title("Destroying host "+str(hostname))
    try:
        print '\t[~] Destroying host...'
        host = api.hosts.get(name=hostname)
        if host.delete():
            print '\t[~] Host was destroyed successfully'
    except Exception as e:
        print '\t[!] Failed to destroy Host:'
        print  "\t "+str(e)
# ------------------------------------------------------------------------------


# STORAGE DOMAINS --------------------------------------------------------------
def create_posixfs_domain(storage_addr, storage_path, mnt_options, storage_type, data_type, storagename, datacentername, hostname):
    st_format = 'v3'
    if data_type == "iso":
        st_format = 'v1'
    display_title("Creating new storage domain "+str(storagename))
    sdParams = params.StorageDomain(name=storagename,
                      data_center=api.datacenters.get(datacentername),
                      storage_format=st_format,
                      type_=data_type,
                      host=api.hosts.get(hostname),
                      storage = params.Storage(type_='posixfs', address=storage_addr, path=storage_path, mount_options=mnt_options, vfs_type=storage_type)
                      )
    print '\t[~] Creating storage...'
    try:
        if api.storagedomains.add(sdParams):
            print '\t[~] Storage domain was created successfully'

    except Exception as e:
        print '\t[!] Failed to create storage domain:'
        print  "\t "+str(e)

def link_storage_domain(storagename, datacentername):
    display_title("linking storage domain "+str(storagename))
    try:
        datacenter = api.datacenters.get(name=datacentername)
        storage_domain = api.storagedomains.get(name=storagename)
        print '\t[~] Linking storage...'
        if datacenter.storagedomains.add(storage_domain):
            print '\t[~] Storage Domain was linked successfully'
    except Exception as e:
        print '\t[!] Failed to link storage domain:'
        print  "\t "+str(e)

def unlink_storage_domain(storagename, datacentername):
    display_title("Unlinking storage domain "+str(storagename))
    try:
        datacenter = api.datacenters.get(name=datacentername)
        print '\t[~] Unlinking storage...'
        storagedomains = datacenter.storagedomains.list()
        for storage_domain in storagedomains:
            if storage_domain.get_name() == storagename:
                if storage_domain.delete():
                    print '\t[~] Storage Domain was unlinked successfully'
    except Exception as e:
        print '\t[!] Failed to unlink storage domain:'
        print  "\t "+str(e)

def up_storage_domain(storagename):
    display_title("Activating storage domain "+str(storagename))
    try:
        storage_domain_object = get_storage_domain_by_name(storagename)
        print '\t[~] Activating storage domain '+str(storage_domain_object.get_name())
        thread.start_new(storage_domain_object.activate, ())
        wait_storage_for_state(storage_domain_object, "active")
        print '\t[~] Storage was activated successfully'
    except Exception as e:
        print '\t[!] Failed to activate storage domain:'
        print  "\t "+str(e)

def down_storage_domain(storagename):
    display_title("Disabling storage domain "+str(storagename))
    try:
        storage_domain_object = get_storage_domain_by_name(storagename)
        print '\t[~] Deactivating storage domain '+str(storage_domain_object.get_name())
        thread.start_new(storage_domain_object.deactivate, ())
        wait_storage_for_state(storage_domain_object, "maintenance")
        print '\t[~] Storage was deactivated successfully'
    except Exception as e:
        print '\t[!] Failed to desactivate storage domain:'
        print  "\t "+str(e)

def del_posix_storage_domain(storagename):
    display_title("Deleting storage domain "+str(storagename))
    try:
        storage_domain = api.storagedomains.get(name=storagename)
        print '\t[~] Deleting storage domain...'
        host = api.hosts.get(get_random_host_name())
        storage_domain.set_host(host)
        if storage_domain.delete(storage_domain):
            print '\t[~] Posixfs Storage Domain was deleted successfully'
    except Exception as e:
        print '\t[!] Failed to delete Posixfs Storage Domain:'
        print  "\t "+str(e)

def get_storage_domains(datacentername):
    display_title("Getting storage domains "+str(datacentername))
    try:
        datacenter = api.datacenters.get(name=datacentername)
        storagedomains = datacenter.storagedomains.list()
        if storagedomains:
            print '\t[~] Displaying storage domains for '+str(datacentername)
            print '\t\tName\tId\t\t\t\t\tStatus'
            for storage_domain in storagedomains:
                print '\t\t'+str(storage_domain.get_name())+"\t"+str(storage_domain.get_id())+"\t"+storage_domain.get_status().state
    except Exception as e:
        print '\t[!] Failed to get storage Domain:'
        print  "\t "+str(e)
# ------------------------------------------------------------------------------


# ISO --------------------------------------------------------------------------
def upload_iso(iso_path, storage_name):
    host_ip = get_mgmt_ip_by_storagename(storage_name)
    ssh = createSSHClient(host_ip, 22, "root", "arbre1234")
    scp = SCPClient(ssh.get_transport())
    if os.path.isfile(iso_path):
        scp.put(iso_path)
    else:
        return False
# ------------------------------------------------------------------------------

# Misc -------------------------------------------------------------------------
def wait_host_for_state(host, state):
    host = api.hosts.get(name=host.name)
    sys.stdout.write('\t[')
    while host.get_status().state != state:
        host = api.hosts.get(name=host.name)
        sys.stdout.write('~')
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write(']')
    sys.stdout.write('\n')
    return True

def wait_storage_for_state(storage_domain, state):
    sys.stdout.write('\t[')
    sys.stdout.flush()
    storage_domain_name = storage_domain.get_name()
    storage_domain_object = storage_domain
    while storage_domain_object.get_status().state != state:
        storage_domain_object = get_storage_domain_by_name(storage_domain_name)
        sys.stdout.write('~')
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write(']')
    sys.stdout.write('\n')
    return True

def get_storage_domain_by_name(storagename):
    storage_domain = api.storagedomains.get(storagename)
    datacenter_id = storage_domain.get_data_centers().data_center.pop().get_id()
    datacenter = api.datacenters.get(id=datacenter_id)
    storage_domain_object = datacenter.storagedomains.get(storagename)
    return storage_domain_object

def get_data_center_by_storage_name(storagename):
    storage_domain = api.storagedomains.get(storagename)
    datacenter_id = storage_domain.get_data_centers().data_center.pop().get_id()
    datacenter = api.datacenters.get(id=datacenter_id)
    return datacenter

def get_first_cluster_by_storage_name(storagename):
    datacenter = get_data_center_by_storage_name(storagename)
    clusters = datacenter.clusters.list()
    for cluster in clusters:
        return cluster

def get_host_by_storage_domain_name(storagename):
    datacenter = get_data_center_by_storage_name(storagename)
    cluster = get_first_cluster_by_storage_name(storagename)
    cluster_id = cluster.get_id()
    hosts = api.hosts.list()
    for host in hosts:
        host_cluster_id = host.get_cluster().get_id()
        if cluster_id == host_cluster_id:
            return host

def get_mgmt_ip_by_hostname(hostname):
    host = api.hosts.get(name=hostname)
    for nic in host.nics.list():
        nic_ip = nic.get_ip().get_address()
        networkattachments = nic.networkattachments.list()
        for netattach in networkattachments:
            netattach_net_id = netattach.network.id
            net_name = api.networks.get(id=netattach_net_id).get_name()
            if net_name == "ovirtmgmt":
                return nic_ip

def get_mgmt_ip_by_storagename(storagename):
    host = get_host_by_storage_domain_name(storagename)
    return get_mgmt_ip_by_hostname(host.get_name())

def get_random_host_name():
    random_hosts_list = api.hosts.list()
    rnd_host = random.choice(random_hosts_list)
    rnd_host_name = rnd_host.get_name()
    return rnd_host_name

def display_title(title):
    print " "+str(title)
    print "-------------------------------------------"

def createSSHClient(server, port, user, password):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, password)
    return client
# ------------------------------------------------------------------------------

# Args management --------------------------------------------------------------
def handle_args():
    parser = argparse.ArgumentParser(description='[~] oVirt python admin ')
    subparsers = parser.add_subparsers(help="sub-command help")
    # ------
    new_datacenter_parser = subparsers.add_parser('ndc', help='Create an oVirt DataCenter')
    new_datacenter_parser.set_defaults(which='ndc')
    new_datacenter_parser.add_argument('data_center_name', help='oVirt DataCenter\'s name')
    new_datacenter_parser.add_argument('storage_type', help='oVirt DataCenter\'s storage type (iscsi, fcp, nfs, localfs, posixfs, glusterfs, glance, cinder)')
    # ------
    destroy_datacenter_parser = subparsers.add_parser('deldc', help='Destroy an oVirt DataCenter')
    destroy_datacenter_parser.set_defaults(which='deldc')
    destroy_datacenter_parser.add_argument('data_center_name', help='oVirt DataCenter\'s name')
    # ------
    new_cluster_parser = subparsers.add_parser('ncluster', help='Create an oVirt cluster')
    new_cluster_parser.set_defaults(which='ncluster')
    new_cluster_parser.add_argument('cluster_name', help='oVirt cluster\'s name')
    new_cluster_parser.add_argument('data_center_name', help='oVirt cluster\'s datacenter name')
    new_cluster_parser.add_argument('cpu_type', help='oVirt cluster\'s cpu type ("Intel Penryn Family", "Intel Conroe Family", ...)')
    # ------
    destroy_cluster_parser = subparsers.add_parser('delcluster', help='Destroy an oVirt cluster')
    destroy_cluster_parser.set_defaults(which='delcluster')
    destroy_cluster_parser.add_argument('cluster_name', help='oVirt cluster\'s name')
    # ------
    new_host_parser = subparsers.add_parser('nhost', help='Create an oVirt Host')
    new_host_parser.set_defaults(which='nhost')
    new_host_parser.add_argument('host_name', help='oVirt Host\'s name')
    new_host_parser.add_argument('host_addr', help='oVirt Host\'s ip addr')
    new_host_parser.add_argument('cluster_name', help='oVirt Host\'s cluster name')
    new_host_parser.add_argument('root_pwd', help='oVirt Host\'s root password')
    # ------
    activate_host_parser = subparsers.add_parser('uphost', help='Activate an oVirt Host')
    activate_host_parser.set_defaults(which='uphost')
    activate_host_parser.add_argument('host_name', help='oVirt Host\'s name')
    # ------
    deactivate_host_parser = subparsers.add_parser('downhost', help='Deactivate an oVirt Host')
    deactivate_host_parser.set_defaults(which='downhost')
    deactivate_host_parser.add_argument('host_name', help='oVirt Host\'s name')
    # ------
    destroy_host_parser = subparsers.add_parser('delhost', help='Remove an oVirt Host')
    destroy_host_parser.set_defaults(which='delhost')
    destroy_host_parser.add_argument('host_name', help='oVirt Host\'s name')
    # ------
    new_storage_domain_parser = subparsers.add_parser('nstdomain', help='Create an oVirt posixfs storage domain')
    new_storage_domain_parser.set_defaults(which='nstdomain')
    new_storage_domain_parser.add_argument('storage_addr', help='oVirt storage domain\'s name')
    new_storage_domain_parser.add_argument('storage_path', help='oVirt storage domain\'s name')
    new_storage_domain_parser.add_argument('mnt_options', help='oVirt storage domain\'s monting options')
    new_storage_domain_parser.add_argument('storage_type', help='oVirt storage domain\'s storage type (ext4|ceph|...)')
    new_storage_domain_parser.add_argument('data_type', help='oVirt storage domain\'s data type (data|iso|export)')
    new_storage_domain_parser.add_argument('storagename', help='oVirt storage domain\'s name')
    new_storage_domain_parser.add_argument('data_center_name', help='oVirt storage domain\'s datacenter target')
    new_storage_domain_parser.add_argument('host_name', help='oVirt storage domain\'s first hosting node')
    # ------
    lnk_storage_domain_parser = subparsers.add_parser('lnkstdomain', help='Attach an oVirt storage domain')
    lnk_storage_domain_parser.set_defaults(which='lnkstdomain')
    lnk_storage_domain_parser.add_argument('storagename', help='oVirt storage domain\'s name')
    lnk_storage_domain_parser.add_argument('data_center_name', help='oVirt storage domain data center\'s name')
    # ------
    unlnk_storage_domain_parser = subparsers.add_parser('unlnkstdomain', help='Unattach an oVirt storage domain')
    unlnk_storage_domain_parser.set_defaults(which='unlnkstdomain')
    unlnk_storage_domain_parser.add_argument('storagename', help='oVirt storage domain\'s name')
    unlnk_storage_domain_parser.add_argument('data_center_name', help='oVirt storage domain data center\'s name')
    # ------
    up_storage_domain_parser = subparsers.add_parser('upstdomain', help='Attach an oVirt storage domain')
    up_storage_domain_parser.set_defaults(which='upstdomain')
    up_storage_domain_parser.add_argument('storagename', help='oVirt storage domain\'s name')
    # ------
    down_storage_domain_parser = subparsers.add_parser('downstdomain', help='Detach an oVirt storage domain')
    down_storage_domain_parser.set_defaults(which='downstdomain')
    down_storage_domain_parser.add_argument('storagename', help='oVirt storage domain\'s name')
    # ------
    del_posix_storage_domain_parser = subparsers.add_parser('delstdomain', help='Remove an oVirt storage domain')
    del_posix_storage_domain_parser.set_defaults(which='delstdomain')
    del_posix_storage_domain_parser.add_argument('storagename', help='oVirt storage domain\'s datacenter target')
    # ------
    get_storage_domains_parser = subparsers.add_parser('getstdomain', help='Get info about an oVirt storage domain')
    get_storage_domains_parser.set_defaults(which='getstdomain')
    get_storage_domains_parser.add_argument('data_center_name', help='oVirt storage domain\'s datacenter target')
    # ------
    upload_iso_parser = subparsers.add_parser('uploadiso', help='Upload an iso to the oVirt right oVirt Host')
    upload_iso_parser.set_defaults(which='uploadiso')
    upload_iso_parser.add_argument('isopath', help='ISO\'s path that you want to upload')
    upload_iso_parser.add_argument('storage_name', help='oVirt ISO storage domain\'s name')
    # ------
    args = parser.parse_args()
    if args.which == "deldc":
        destroy_datacenter(args.data_center_name)
    elif args.which == "ndc":
        create_datacenter(args.data_center_name, args.storage_type)
    elif args.which == "ncluster":
        create_cluster(args.cluster_name, args.data_center_name, args.cpu_type)
    elif args.which == "delcluster":
        destroy_cluster(args.cluster_name)
    elif args.which == "nhost":
        create_new_host_in_cluster(args.host_name, args.host_addr, args.cluster_name, args.root_pwd)
    elif args.which == "delhost":
        destroy_host(args.host_name)
    elif args.which == "uphost":
        set_host_active(args.host_name)
    elif args.which == "downhost":
        set_host_deactive(args.host_name)
    elif args.which == "nstdomain":
        create_posixfs_domain(args.storage_addr, args.storage_path, args.mnt_options, args.storage_type, args.data_type, args.storagename, args.data_center_name, args.host_name)
    elif args.which == "lnkstdomain":
        link_storage_domain(args.storagename, args.data_center_name)
    elif args.which == "unlnkstdomain":
        unlink_storage_domain(args.storagename, args.data_center_name)
    elif args.which == "upstdomain":
        up_storage_domain(args.storagename)
    elif args.which == "downstdomain":
        down_storage_domain(args.storagename)
    elif args.which == "delstdomain":
        del_posix_storage_domain(args.storagename)
    elif args.which == "getstdomain":
        get_storage_domains(args.data_center_name)
    elif args.which == "getrndhost":
        get_random_host_name()
    elif args.which == "uploadiso":
        upload_iso(args.isopath, args.storage_name)
    return parser.parse_args()
# ------------------------------------------------------------------------------

# MAIN -------------------------------------------------------------------------
api = init()
handle_args()
# ------------------------------------------------------------------------------
