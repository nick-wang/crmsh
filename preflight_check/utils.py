import os
import re
import glob
import json
import logging
import socket
from datetime import datetime
from contextlib import contextmanager
from crmsh import utils as crmshutils
from crmsh import xmlutil, corosync
from . import config


logger = logging.getLogger('cpc')

CRED = '\033[31m'
CYELLOW = '\033[33m'
CGREEN = '\033[32m'
CEND = '\033[0m'

LEVEL = {
    "info": logging.INFO,
    "warn": logging.WARNING,
    "error": logging.ERROR
}


class MyLoggingFormatter(logging.Formatter):
    """
    Class to change logging formatter
    """

    FORMAT_FLUSH = "[%(asctime)s]%(levelname)s: %(message)s"
    FORMAT_NOFLUSH = "%(timestamp)s%(levelname)s: %(message)s"

    COLORS = {
        'WARNING': CYELLOW,
        'INFO': CGREEN,
        'ERROR': CRED
    }

    def __init__(self, flush=True):
        fmt = self.FORMAT_FLUSH if flush else self.FORMAT_NOFLUSH
        logging.Formatter.__init__(self, fmt=fmt, datefmt='%Y/%m/%d %H:%M:%S')

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            levelname_color = self.COLORS[levelname] + levelname + CEND
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


def now(form="%Y/%m/%d %H:%M:%S"):
    return datetime.now().strftime(form)


@contextmanager
def manage_handler(_type, keep=True):
    """
    Define a contextmanager to remove specific logging handler temporarily
    """
    try:
        handler = get_handler(logger, _type)
        if not keep:
            logger.removeHandler(handler)
        yield
    finally:
        if not keep:
            logger.addHandler(handler)


def msg_raw(level, msg, to_stdout=True):
    with manage_handler("stream", to_stdout):
        logger.log(level, msg)


def msg_info(msg, to_stdout=True):
    msg_raw(logging.INFO, msg, to_stdout)


def msg_warn(msg, to_stdout=True):
    msg_raw(logging.WARNING, msg, to_stdout)


def msg_error(msg, to_stdout=True):
    msg_raw(logging.ERROR, msg, to_stdout)


def json_dumps():
    """
    Dump the json results to file
    """
    from . import main
    with open(main.ctx.jsonfile, 'w') as f:
        f.write(json.dumps(main.ctx.task_list, indent=2))
        f.flush()
        os.fsync(f)


def get_property(name):
    """
    Get cluster properties
    """
    cmd = "crm configure get_property " + name
    rc, stdout, _ = crmshutils.get_stdout_stderr(cmd)
    if rc != 0:
        return None
    else:
        return stdout


class FenceInfo(object):
    """
    Class to collect fence info
    """
    @property
    def fence_enabled(self):
        enable_result = get_property("stonith-enabled")
        if not enable_result or enable_result.lower() != "true":
            return False
        return True

    @property
    def fence_action(self):
        action_result = get_property("stonith-action")
        if action_result is None or action_result not in ["off", "poweroff", "reboot"]:
            msg_error("Cluster property \"stonith-action\" should be reboot|off|poweroff")
            return None
        return action_result

    @property
    def fence_timeout(self):
        timeout_result = get_property("stonith-timeout")
        if timeout_result and re.match(r'[1-9][0-9]*(s|)$', timeout_result):
            return timeout_result.strip("s")
        return config.FENCE_TIMEOUT


def check_node_status(node, state):
    """
    Check whether the node has expected state
    """
    rc, stdout, stderr = crmshutils.get_stdout_stderr('crm_node -l')
    if rc != 0:
        msg_error(stderr)
        return False
    pattern = re.compile(r'^.* {} {}'.format(node, state), re.MULTILINE)
    if not pattern.search(stdout):
        return False
    return True


def online_nodes():
    """
    Get online node list
    """
    rc, stdout, stderr = crmshutils.get_stdout_stderr('crm_mon -1')
    if rc == 0 and stdout:
        res = re.search(r'Online:\s+\[\s(.*)\s\]', stdout)
        if res:
            return res.group(1).split()
    return []


def peer_node_list():
    """
    Get online node list except self
    """
    online_nodelist = online_nodes()
    if online_nodelist:
        online_nodelist.remove(this_node())
        return online_nodelist
    return []


def this_node():
    """
    Try to get the node name from crm_node command
    If failed, use its hostname
    """
    rc, stdout, stderr = crmshutils.get_stdout_stderr("crm_node --name")
    if rc != 0:
        msg_error(stderr)
        return crmshutils.this_node()
    return stdout


def _query_internet_server(hname):
    """
    Non-interactively query Internet domain name servers
    hname: Hostname of the server, can't use IP address
    """
    # nslookup will put err msg into stdout
    rc, stdout, _ = crmshutils.get_stdout_stderr("nslookup {}".format(hname))
    if rc != 0:
        msg_error(stdout)
        return None

    flag = False
    for line in stdout.split("\n"):
        tmp = re.match(r'Name:\s+.*{}\.+.*'.format(hname), line)
        if tmp:
            flag = True
            continue

        # Check the next line after matched hostname
        if flag:
            tmp = re.match(r'Address:\s+(.*)', line)

            if tmp:
                ip = tmp.groups()[0].split("#")[0].strip()
                return ip

        flag = False

    return None


def _get_bind_addr_with_local_network(ipaddr):
    """
    Find corresponding bind address based on local network
    """
    is_ipv6 = crmshutils.IP.is_ipv6(ipaddr)
    interface_list = crmshutils.InterfacesInfo.get_local_interface_list(is_ipv6)

    bind_addr = None
    for interface in interface_list:
        if interface.ip_in_network(ipaddr):
            bind_addr = interface.network
            break

    return bind_addr


def str_to_datetime(str_time, fmt):
    return datetime.strptime(str_time, fmt)


def corosync_port_list():
    """
    Get corosync ports using corosync-cmapctl
    """
    ports = []
    rc, out, _ = crmshutils.get_stdout_stderr("corosync-cmapctl totem.interface")
    if rc == 0 and out:
        ports = re.findall(r'(?:mcastport.*) ([0-9]+)', out)
    return ports


def get_handler(logger, _type):
    """
    Get logger specific handler
    """
    for h in logger.handlers:
        if getattr(h, '_name') == _type:
            return h


def is_root():
    return os.getuid() == 0


def get_process_status(s):
    """
    Returns true if argument is the name of a running process.

    s: process name
    returns Boolean and pid
    """
    # find pids of running processes
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        try:
            pid_file = os.path.join('/proc', pid, 'cmdline')
            with open(pid_file, 'rb') as f:
                data = f.read()
                procname = os.path.basename(crmshutils.to_ascii(data).replace('\x00', ' ').split(' ')[0])
                if procname == s or procname == s + ':':
                    return True, int(pid)
        except EnvironmentError:
            # a process may have died since we got the list of pids
            pass
    return False, -1


def _find_match_count(str1, str2):
    """
    Find the max match number of s1 and s2
    """
    leng = min(len(str1), len(str2))
    num = 0

    for i in range(leng):
        if str1[i] == str2[i]:
            num += 1
        else:
            break

    return num


def is_valid_sbd(dev):
    """
    Check whether the device is a initialized SBD device

    dev: dev path
    return 'True' if 'dev' is a initialized SBD device
    """
    if not os.path.exists(dev):
        return False

    rc, out, err = crmshutils.get_stdout_stderr(config.SBD_CHECK_CMD.format(dev=dev))
    if rc != 0 and err:
        msg_error(err)
        return False

    return True


def find_candidate_sbd(dev):
    """
    Find the devices that already have SBD header

    return the path of candidate SBD device
    """
    ddir = os.path.dirname(dev)
    dname = os.path.basename(dev)

    dev_list = glob.glob(ddir + "/*")
    if len(dev_list) == 0:
        return ""

    can_filter = filter(is_valid_sbd, dev_list)
    candidates = list(can_filter)

    if len(candidates) == 0:
        return ""

    index = 0
    i = 0
    max_match = -1
    num_list = map(_find_match_count, [dev] * len(candidates), candidates)
    for num in num_list:
        if num > max_match:
            max_match = num
            index = i
        i += 1

    return candidates[index]


class Node(object):
    """
    Class to describe (cluster) node
    """

    def __init__(self, name):
        self.name = name
        self._nodeid = None
        self._old_IP = None
        self._cur_IP = None
        self._bind_addr = None

    @property
    def nodeid(self):
        """
        Get nodeid
        """
        return self._nodeid

    @nodeid.setter
    def nodeid(self, nodeid):
        """
        Set nodeid
        """
        self._nodeid = nodeid

    @property
    def old_IP(self):
        """
        Get original IP list
        """
        return self._old_IP

    @old_IP.setter
    def old_IP(self, ip_list):
        """
        Set original IP list
        """
        self._old_IP = ip_list

    @property
    def cur_IP(self):
        """
        Get current IP list
        """
        return self._cur_IP

    @cur_IP.setter
    def cur_IP(self, ip_list):
        """
        Set current IP list
        """
        self._cur_IP = ip_list

    @property
    def bind_addr(self):
        """
        Get bind address
        """
        return self._bind_addr

    @bind_addr.setter
    def bind_addr(self, bindaddr):
        """
        Set bind address
        """
        self._bind_addr = bindaddr

    @property
    def need_repair(self):
        """
        Check if the IP value need repair
        """
        # Make sure old_IP no longer in current interface network
        if (self._cur_IP and self._old_IP and self._cur_IP != self._old_IP
                and not _get_bind_addr_with_local_network(self._old_IP)):
            return True

        return False


class ClusterInfo(object):
    """
    Class to get old cluster information.
    eg. corosync.conf, cib.xml, etc...
    """

    def __init__(self):
        self.hostname = socket.gethostname()
        # hostip maybe unreal if /etc/hosts configured with a stale one
        self.hostip = socket.gethostbyname(self.hostname)
        self.cib_path = os.getenv('CIB_file',
                                  config.CIB_FILE)
        self.coro_conf = os.getenv('COROSYNC_MAIN_CONFIG_FILE',
                                   config.COROSYNC_CONF)
        self._nodes = self._init_cluster_nodes

    @property
    def _init_cluster_nodes(self):
        """
        Get cluster nodes (including remote) from cib.xml
        Not yet has old IP
        """
        nodes = []
        if not os.path.isfile(self.cib_path):
            return []

        cib_elem = xmlutil.file2cib_elem(self.cib_path)

        name_id_tuple = [(x.get("uname"), x.get("id", None))
                         for x in cib_elem.xpath("/cib/configuration/nodes/node")]

        for name, nid in name_id_tuple:
            tmp = Node(name)
            tmp.nodeid = nid
            nodes.append(tmp)

        return nodes

    @property
    def was_cluster(self):
        """
        Check whether this node belong to a cluster
        """
        if not os.path.isfile(self.cib_path) or not os.path.isfile(
                self.coro_conf) or not self._nodes or not self.corosync_nodes:
            return False

        return True

    @property
    def is_unicast(self):
        """
        Check the cluster use unicast transport
        """
        return corosync.is_unicast()

    @property
    def is_autoid(self):
        """
        Check the cluster use auto node ID
        """
        length = len(corosync.get_values("nodelist.node.nodeid"))
        if not length:
            return True

        return length != len(self.corosync_nodes)

    @property
    def is_dual_ring(self):
        """
        Check the cluster use multiple ring
        """
        return len(corosync.get_values("nodelist.node.ring1_addr")) != 0

    @property
    def corosync_nodes(self):
        """
        Get the cluster node IP. Only ring0.
        """
        return crmshutils.list_corosync_nodes()

    @property
    def get_cluster_nodes(self):
        """
        Fill in nodes with corresponding old IP(corosync.conf) and new IP(nslookup)
        """
        length = len(self.corosync_nodes)
        if length != len(self._nodes):
            return []

        # Fill in old IP
        if self.is_autoid:
            # Impossible to match without a nodeid configured in corosync.conf
            # Random match old IP to node
            for i in range(length):
                self._nodes[i].old_IP = self.corosync_nodes[i]
        else:
            coro_nodes_ids = corosync.get_values("nodelist.node.nodeid")
            coro_nodes_ips = self.corosync_nodes

            for n in self._nodes:
                for i in range(length):
                    if coro_nodes_ids[i] == n.nodeid:
                        n.old_IP = coro_nodes_ips[i]
                        break
                    # TODO: else: Exception when no nodeid matched

        # Fill in current IP of peer node
        for n in self._nodes:
            ip = _query_internet_server(n.name)

            if ip:
                n.cur_IP = ip

        # Set bind address based on the current IP
        # All nodes should have same bind address based on cur_IP
        # so maybe don't need to run _get_bind_addr_with_local_network on all nodes
        for n in self._nodes:
            n.bind_addr = _get_bind_addr_with_local_network(n.cur_IP)

        return self._nodes
