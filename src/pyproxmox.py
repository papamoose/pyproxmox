# coding: utf-8

"""
A python wrapper for the Proxmox 2.x API.

Example usage:

1) Create an instance of the PyproxmoxAPI class by passing ip or hostname
of a server, username and password:

proxmox = PyproxmoxAPI('vnode01.example.org','apiuser@pve','examplePassword')

3) Run the pre defined methods of the PypeoxmoxAPI class.
NOTE: they all return data, usually in JSON format

status = proxmox.getClusterStatus('vnode01')

4) You also easy can define your own method by deriving PyproxmoxAPI class and
using methods: get, post, put, delete
Example:

def createOpenvzContainer(self, node, post_data):
    return self.post('nodes/%s/openvz' % (node), data=post_data)

For more information see https://github.com/Daemonthread/pyproxmox.
"""

import logging
import urlparse

import requests

from tools import extract_code_and_json

PROXMOX_URL = "https://%s:8006/api2/json/"
TICKET_PATH = "access/ticket"
TICKET_COOKIE_NAME = "PVEAuthCookie"
TOKEN_HEADER_NAME = "CSRFPreventionToken"

logger = logging.getLogger("pyproxmox")


class PyproxmoxAPI(object):
    """
    A class that acts as a python wrapper for the Proxmox 2.x API.
    GET and POST methods are currently implemented along with quite a few
    custom API methods.
    """
    def __init__(self, host, user, password):
        """Create session for work with Proxmox API
        :param host: hostname of machine with proxmox installed
        :param user: username for proxmox API
        :param password: password for proxmox API
        """
        self.url = PROXMOX_URL % host
        self.session = requests.Session()
        self.session.verify = False
        ticket, token = self.get_tokens(user, password)
        self.authorize(ticket, token)

    def authorize(self, ticket, token):
        """Adds header with token and cookie with ticket to session"""
        self.session.headers.update({TOKEN_HEADER_NAME: token})
        self.session.cookies.update({TICKET_COOKIE_NAME: ticket})

    def get_url(self, path):
        return urlparse.urljoin(self.url, path)

    def get_tokens(self, user, password):
        """Get authentification tokens"""
        data = {"username": user, "password": password}
        result = self.post(TICKET_PATH, data=data)
        ticket = result["data"]["ticket"]
        token = result['data']['CSRFPreventionToken']
        return ticket, token

    def execute(self, path, method='get', params=None, data=None):
        url = self.get_url(path)
        method = method.lower()
        method_fun = getattr(self.session, method, None)
        if method_fun is None:
            logger.error("Unknown HTTP method: %s", method)
            return
        result = method_fun(url, params=params, data=data)
        code, content = extract_code_and_json(result)
        if code == 500:
            logger.error("Internal Proxmox Error: %s", content)
            return
        else:
            logger.info("Status Code: %s, Answer: %s", code, content)
            return content

    def get(self, path, params=None):
        return self.execute(path, params=params)

    def delete(self, path, params=None):
        return self.execute(path, method='delete', params=params)

    def post(self, path, data=None):
        return self.execute(path, method='post', data=data)

    def put(self, path, data=None):
        return self.execute(path, method='put', data=data)

    # Methods using the GET protocol to communicate with the Proxmox API.

    # Cluster Methods
    def getClusterStatus(self):
        """Get cluster status information. Returns JSON"""
        return self.get('cluster/status')

    def getClusterBackupSchedule(self):
        """List vzdump backup schedule. Returns JSON"""
        return self.get('cluster/backup')

    # Node Methods
    def getNodeNetworks(self, node):
        """List available networks. Returns JSON"""
        return self.get('nodes/%s/network' % (node))

    def getNodeInterface(self, node, interface):
        """Read network device configuration. Returns JSON"""
        return self.get('nodes/%s/network/%s' % (node, interface))

    def getNodeContainerIndex(self, node):
        """OpenVZ container index (per node). Returns JSON"""
        return self.get('nodes/%s/openvz' % (node))

    def getNodeVirtualIndex(self, node):
        """Virtual machine index (per node). Returns JSON"""
        return self.get('nodes/%s/qemu' % (node))

    def getNodeServiceList(self, node):
        """Service list. Returns JSON"""
        return self.get('nodes/%s/services' % (node))

    def getNodeServiceState(self, node, service):
        """Read service properties"""
        return self.get('nodes/%s/services/%s/state' % (node, service))

    def getNodeStorage(self, node):
        """Get status for all datastores. Returns JSON"""
        return self.get('nodes/%s/storage' % (node))

    def getNodeFinishedTasks(self, node):
        """Read task list for one node (finished tasks). Returns JSON"""
        return self.get('nodes/%s/tasks' % (node))

    def getNodeDNS(self, node):
        """Read DNS settings. Returns JSON"""
        return self.get('nodes/%s/dns' % (node))

    def getNodeStatus(self, node):
        """Read node status. Returns JSON"""
        return self.get('nodes/%s/status' % (node))

    def getNodeSyslog(self, node):
        """Read system log. Returns JSON"""
        return self.get('nodes/%s/syslog' % (node))

    def getNodeRRD(self, node):
        """Read node RRD statistics. Returns PNG"""
        return self.get('nodes/%s/rrd' % (node))

    def getNodeRRDData(self, node):
        """Read node RRD statistics. Returns RRD"""
        return self.get('nodes/%s/rrddata' % (node))

    def getNodeBeans(self, node):
        """Get user_beancounters failcnt for all active containers.
        Returns JSON"""
        return self.get('nodes/%s/ubfailcnt' % (node))

    def getNodeTaskByUPID(self, node, upid):
        """Get tasks by UPID. Returns JSON"""
        return self.get('nodes/%s/tasks/%s' % (node, upid))

    def getNodeTaskLogByUPID(self, node, upid):
        """Read task log. Returns JSON"""
        return self.get('nodes/%s/tasks/%s/log' % (node, upid))

    def getNodeTaskStatusByUPID(self, node, upid):
        """Read task status. Returns JSON"""
        return self.get('nodes/%s/tasks/%s/status' % (node, upid))

    # Scan

    def getNodeScanMethods(self, node):
        """Get index of available scan methods"""
        return self.get('nodes/%s/scan' % (node))

    def getRemoteiSCSI(self, node):
        """Scan remote iSCSI server."""
        return self.get('nodes/%s/scan/iscsi' % (node))

    def getNodeLVMGroups(self, node):
        """Scan local LVM groups"""
        return self.get('nodes/%s/scan/lvm' % (node))

    def getRemoteNFS(self, node):
        """Scan remote NFS server"""
        return self.get('nodes/%s/scan/nfs' % (node))

    def getNodeUSB(self, node):
        """List local USB devices"""
        return self.get('nodes/%s/scan/usb' % (node))

    # OpenVZ Methods

    def getContainerIndex(self, node, vmid):
        """Directory index. Returns JSON"""
        return self.get('nodes/%s/openvz/%s' % (node, vmid))

    def getContainerStatus(self, node, vmid):
        """Get virtual machine status. Returns JSON"""
        return self.get('nodes/%s/openvz/%s/status/current' % (node, vmid))

    def getContainerBeans(self, node, vmid):
        """Get container user_beancounters. Returns JSON"""
        return self.get('nodes/%s/openvz/%s/status/ubc' % (node, vmid))

    def getContainerConfig(self, node, vmid):
        """Get container configuration. Returns JSON"""
        return self.get('nodes/%s/openvz/%s/config' % (node, vmid))

    def getContainerInitLog(self, node, vmid):
        """Read init log. Returns JSON"""
        return self.get('nodes/%s/openvz/%s/initlog' % (node, vmid))

    def getContainerRRD(self, node, vmid):
        """Read VM RRD statistics. Returns PNG"""
        return self.get('nodes/%s/openvz/%s/rrd' % (node, vmid))

    def getContainerRRDData(self, node, vmid):
        """Read VM RRD statistics. Returns RRD"""
        return self.get('nodes/%s/openvz/%s/rrddata' % (node, vmid))

    # KVM Methods

    def getVirtualIndex(self, node, vmid):
        """Directory index. Returns JSON"""
        return self.get('nodes/%s/qemu/%s' % (node, vmid))

    def getVirtualStatus(self, node, vmid):
        """Get virtual machine status. Returns JSON"""
        return self.get('nodes/%s/qemu/%s/status/current' % (node, vmid))

    def getVirtualConfig(self, node, vmid):
        """Get virtual machine configuration. Returns JSON"""
        return self.get('nodes/%s/qemu/%s/config' % (node, vmid))

    def getVirtualRRD(self, node, vmid):
        """Read VM RRD statistics. Returns JSON"""
        return self.get('nodes/%s/qemu/%s/rrd' % (node, vmid))

    def getVirtualRRDData(self, node, vmid):
        """Read VM RRD statistics. Returns JSON"""
        return self.get('nodes/%s/qemu/%s/rrddata' % (node, vmid))

    # Storage Methods

    def getStorageVolumeData(self, node, storage, volume):
        """Get volume attributes. Returns JSON"""
        return self.get('nodes/%s/storage/%s/content/%s' %
                        (node, storage, volume))

    def getStorageConfig(self, storage):
        """Read storage config. Returns JSON"""
        return self.get('storage/%s' % (storage))

    def getNodeStorageContent(self, node, storage):
        """List storage content. Returns JSON"""
        return self.get('nodes/%s/storage/%s/content' % (node, storage))

    def getNodeStorageRRD(self, node, storage):
        """Read storage RRD statistics. Returns JSON"""
        return self.get('nodes/%s/storage/%s/rrd' % (node, storage))

    def getNodeStorageRRDData(self, node, storage):
        """Read storage RRD statistics. Returns JSON"""
        return self.get('nodes/%s/storage/%s/rrddata' % (node, storage))

    # Methods using the POST protocol to communicate with the Proxmox API.

    # OpenVZ Methods

    def createOpenvzContainer(self, node, post_data):
        """
        Create or restore a container. Returns JSON
        Requires a dictionary  or list of tuples
        formatted [('postname1','data'),('postname2','data')]
        """
        return self.post('nodes/%s/openvz' % (node), data=post_data)

    def mountOpenvzPrivate(self, node, vmid):
        """Mounts container private area. Returns JSON"""
        return self.post('nodes/%s/openvz/%s/status/mount' % (node, vmid))

    def shutdownOpenvzContainer(self, node, vmid):
        """Shutdown the container. Returns JSON"""
        return self.post('nodes/%s/openvz/%s/status/shutdown' % (node, vmid))

    def startOpenvzContainer(self, node, vmid):
        """Start the container. Returns JSON"""
        return self.post('nodes/%s/openvz/%s/status/start' % (node, vmid))

    def stopOpenvzContainer(self, node, vmid):
        """Stop the container. Returns JSON"""
        return self.post('nodes/%s/openvz/%s/status/stop' % (node, vmid))

    def unmountOpenvzPrivate(self, node, vmid):
        """Unmounts container private area. Returns JSON"""
        return self.post('nodes/%s/openvz/%s/status/unmount' % (node, vmid))

    def migrateOpenvzContainer(self, node, vmid, target):
        """Migrate the container to another node.
        Creates a new migration task. Returns JSON"""
        post_data = {'target': target}
        return self.post('nodes/%s/openvz/%s/migrate' % (node, vmid),
                         data=post_data)

    # KVM Methods

    def createVirtualMachine(self, node, post_data):
        """
        Create or restore a virtual machine. Returns JSON
        Requires a dictionary  or list of tuples
        formatted [('postname1','data'),('postname2','data')]
        """
        return self.post("nodes/%s/qemu" % (node), data=post_data)

    def resetVirtualMachine(self, node, vmid):
        """Reset a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/status/reset" % (node, vmid))

    def resumeVirtualMachine(self, node, vmid):
        """Resume a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/status/resume" % (node, vmid))

    def shutdownVirtualMachine(self, node, vmid):
        """Shut down a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/status/shutdown" % (node, vmid))

    def startVirtualMachine(self, node, vmid):
        """Start a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/status/start" % (node, vmid))

    def stopVirtualMachine(self, node, vmid):
        """Stop a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/status/stop" % (node, vmid))

    def suspendVirtualMachine(self, node, vmid):
        """Suspend a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/status/suspend" % (node, vmid))

    def migrateVirtualMachine(self, node, vmid, target):
        """Migrate a virtual machine. Returns JSON"""
        post_data = {'target': target}
        return self.post("nodes/%s/qemu/%s/status/start" % (node, vmid),
                         data=post_data)

    def monitorVirtualMachine(self, node, vmid, command):
        """Send monitor command to a virtual machine. Returns JSON"""
        post_data = {'command': command}
        return self.post("nodes/%s/qemu/%s/monitor" % (node, vmid),
                         data=post_data)

    def vncproxyVirtualMachine(self, node, vmid):
        """Creates a VNC Proxy for a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/vncproxy" % (node, vmid))

    def rollbackVirtualMachine(self, node, vmid, snapname):
        """Rollback a snapshot of a virtual machine. Returns JSON"""
        return self.post("nodes/%s/qemu/%s/snapshot/%s/rollback" %
                         (node, vmid, snapname))

    def getSnapshotConfigVirtualMachine(self, node, vmid, snapname):
        """Get snapshot config of a virtual machine. Returns JSON"""
        return self.get("nodes/%s/qemu/%s/snapshot/%s/config" %
                        (node, vmid, snapname))

    # Methods using the DELETE protocol to communicate with the Proxmox API.

    # OPENVZ

    def deleteOpenvzContainer(self, node, vmid):
        """Deletes the specified openvz container"""
        return self.delete("nodes/%s/openvz/%s" % (node, vmid))

    # NODE

    def deleteNodeNetworkConfig(self, node):
        """Revert network configuration changes."""
        return self.delete("nodes/%s/network" % (node))

    def deleteNodeInterface(self, node, interface):
        """Delete network device configuration"""
        return self.delete("nodes/%s/network/%s" % (node, interface))

    #KVM

    def deleteVirtualMachine(self, node, vmid):
        """Destroy the vm (also delete all used/owned volumes)."""
        return self.delete("nodes/%s/qemu/%s" % (node, vmid))

    # POOLS
    def deletePool(self, pool_id):
        """Delete Pool"""
        return self.delete("pools/%s" % (pool_id))

    # STORAGE
    def deleteStorageConfiguration(self, storage_id):
        """Delete storage configuration"""
        return self.delete("storage/%s" % (storage_id))

    # Methods using the PUT protocol to communicate with the Proxmox API.

    # NODE
    def setNodeDNSDomain(self, node, domain):
        """Set the nodes DNS search domain"""
        post_data = {'search': domain}
        return self.put("nodes/%s/dns" % (node), data=post_data)

    def setNodeSubscriptionKey(self, node, key):
        """Set the nodes subscription key"""
        post_data = {'key': key}
        return self.put("nodes/%s/subscription" % (node), data=post_data)

    def setNodeTimeZone(self, node, timezone):
        """Set the nodes timezone"""
        post_data = {'timezone': timezone}
        return self.put("nodes/%s/time" % (node), data=post_data)

    # OPENVZ
    def setOpenvzContainerOptions(self, node, vmid, post_data):
        """Set openvz virtual machine options."""
        return self.put("nodes/%s/openvz/%s/config" % (node, vmid),
                        data=post_data)

    # KVM
    def setVirtualMachineOptions(self, node, vmid, post_data):
        """Set KVM virtual machine options."""
        return self.put("nodes/%s/qemu/%s/config" % (node, vmid),
                        data=post_data)

    def sendKeyEventVirtualMachine(self, node, vmid, key):
        """Send key event to virtual machine"""
        post_data = {'key': key}
        return self.put("nodes/%s/qemu/%s/sendkey" % (node, vmid),
                        data=post_data)

    def unlinkVirtualMachineDiskImage(self, node, vmid, post_data):
        """Unlink disk images"""
        return self.put("nodes/%s/qemu/%s/unlink" % (node, vmid),
                        data=post_data)

    # POOLS
    def setPoolData(self, pool_id, post_data):
        """Update pool data."""
        return self.put("pools/%s" % (pool_id), data=post_data)

    # STORAGE
    def updateStorageConfiguration(self, storage_id, post_data):
        """Update storage configuration"""
        return self.put("storage/%s" % (storage_id), data=post_data)
