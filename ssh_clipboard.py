#!/usr/bin/env python
import paramiko
import os
import sys
from binascii import hexlify
import getpass
import logging
from ConfigParser import ConfigParser
from optparse import OptionParser
from textwrap import dedent
#paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)
#logging.basicConfig(level=logging.DEBUG)


def write_default_config(configfile):
    """ Write a default config to the given filename """
    with open(configfile, 'w') as fh:
        fh.write(dedent("""
        [DEFAULT]

        # Server on which to store buffer.
        server = localhost

        # Buffer file in which to store clipbaord data. If server is localhost,
        # this is a local file. Otherwise, it is a remote file (accessed via
        # SSH).  Relative paths on a remote file are relative to the home
        # directory. If not given, defaults to '.ssh_clipboard.buffer'
        buffer = {buffer}

        # User name on the remote server. If not given, use value from
        # ssh-config or the local username.
        user = {user}

        # Private key file, for SSH access to the server. Must be a RSA private
        # key file. If not given, use value from ssh-config or ~/.ssh/id_rsa
        private_key = {private_key}

        """.format(
        buffer = os.path.join(os.environ['HOME'], '.ssh_clipboard.buffer'),
        user = os.environ['USER'],
        private_key = '~/.ssh/id_rsa'
        )))


def get_params(configfile):
    """ Get a dictionary with keys 'user', 'server', 'private_key',
        'buffer' from the given INI-style config file. Missing
        values are taken from the ssh-config if available, or else are returned
        with the following defaults:

        user: current username
        server: localhost
        private_key: ~/.ssh/id_rsa
        buffer:.ssh_clipboard.buffer

        Note that for the server 'localhost', SSH will not be used, so the
        ssh-config will be ignored as well
    """

    config = ConfigParser()
    config.read(configfile)

    SSHConfigParser = paramiko.SSHConfig()
    SSHConfigParser.parse(open(os.path.expanduser('~/.ssh/config')))

    if config.has_option('DEFAULT', 'server'):
        server = config.get('DEFAULT', 'server')
    else:
        server = 'localhost'
    if server == 'localhost':
        ssh_config = {}
    else:
        ssh_config = SSHConfigParser.lookup(server)
    if 'hostname' in ssh_config:
        server = ssh_config['hostname']

    if config.has_option('DEFAULT', 'user'):
        user = config.get('DEFAULT', 'user')
    else:
        user = os.environ['USER']
        if 'user'in ssh_config:
            user = ssh_config['user']

    if config.has_option('DEFAULT', 'private_key'):
        private_key = os.path.expanduser(config.get('DEFAULT', 'private_key'))
    else:
        private_key = os.path.expanduser('~/.ssh/id_rsa')
        if 'identityfile' in ssh_config:
            private_key = ssh_config['identityfile']

    if config.has_option('DEFAULT', 'buffer'):
        buffer = config.get('DEFAULT', 'buffer')
    else:
        if server == 'localhost':
            buffer = os.path.join(os.environ['HOME'], '.ssh_clipboard.buffer')
        else:
            buffer = '.ssh_clipboard.buffer'

    return({ 'user': user, 'server': server, 'private_key': private_key,
             'buffer': buffer})


def agent_auth(transport, username):
    """ Attempt to authenticate the given transport session using any of the
        private keys available from an SSH agent. Success of the authentication
        can be checked with transport.is_authenticated(); failure will be
        silent
    """
    logging.debug("Trying to authenticate as %s using SSH agent", username)
    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        logging.debug('No keys in agent')
        return

    for key in agent_keys:
        logging.debug('Trying ssh-agent key %s',
                      hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            logging.debug('... success!')
            return
        except paramiko.SSHException, error:
            logging.debug('... nope.')
            logging.debug(error)


def key_auth(transport, username, private_key):
    """ Attempt to authenticate the transport session with the given private
        RSA key file. If the key is encrypted, the user will be asked for a
        password.  Success of the authentication can be checked with
        transport.is_authenticated(); failure will be silent
    """
    logging.debug("Trying to authenticate using private key")
    try:
        key = paramiko.RSAKey.from_private_key_file(private_key)
    except paramiko.PasswordRequiredException:
        password = getpass.getpass('RSA key password: ')
        key = paramiko.RSAKey.from_private_key_file(private_key, password)
    logging.debug("Authenticating as %s with key %s", username, private_key)
    try:
        transport.auth_publickey(username, key)
    except paramiko.SSHException, error:
        logging.debug('Failure')
        logging.debug(error)


def ssh_error_msg(msg, *args):
    """ Print an error message for SSH Error to stderr. Args will be
        interpolated into the given msg
    """
    msg = "*** ERROR: " + msg
    print >> os.sys.stderr, msg % args


def get_authenticated_transport(server, user, private_key, port=22):
    """ Return an authenticated transport session to the given server. The
        authentication will be attempted for the given user name though a
        running ssh-agent. If that fails, authentication with the given
        private_key is attempted.  If all attempts at authentication fail, or
        if the server identity cannot be verified, print an error message and
        return None
    """
    transport = paramiko.Transport((server, port))
    try:
        transport.start_client()
        # Check server identification. We do this with maximum paranoia. Log in
        # manually via SSH to make sure that known_hosts is up to date
        try:
            keys = paramiko.util.load_host_keys(
                   os.path.expanduser('~/.ssh/known_hosts'))
        except IOError:
            logging.debug('Unable to open ~/.ssh/known_hosts')
            keys = {}
        key = transport.get_remote_server_key()
        if not server in keys:
            ssh_error_msg('Server %s not in known hosts!!!', server)
            print >> os.sys.stderr, '*** ERROR: server not in known hosts!'
            return None
        elif not key.get_name() in keys[server]:
            ssh_error_msg('Unknown host key for %s!!!', server)
            return None
        elif keys[server][key.get_name()] != key:
            ssh_error_msg('Host key for %s has changed!!!', server)
            return None
    except paramiko.SSHException:
        ssh_error_msg('SSH negotiation failed')
        return None
    agent_auth(transport, user)
    if not transport.is_authenticated():
        key_auth(transport, user, private_key)
    if not transport.is_authenticated():
        ssh_error_msg('AUTH on server %s with username %s failed', server,
        user)
        ssh_error_msg('AUTH failed')
        return None
    return transport


def write_to_server(server, user, private_key, buffer_file, data):
    """ Connect to given server via SSH and store data in remote buffer_file
    """
    transport = get_authenticated_transport(server, user, private_key)
    if transport is None:
        return 1
    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        fh = sftp.open(buffer_file, 'wb')
        fh.write(data)
        fh.close()
    except IOError, error:
        ssh_error_msg('Cannot write to remote buffer %s: %s',
        buffer_file, error)
        return 1
    transport.close()
    return 0


def write_to_localhost(buffer_file, data):
    """ Store data in the given buffer_file
    """
    try:
        fh = open(buffer_file, 'wb')
        fh.write(data)
        fh.close()
    except IOError, error:
        ssh_error_msg('Cannot write to local buffer %s: %s',
        buffer_file, error)
        return 1
    return 0


def read_from_server(server, user, private_key, buffer_file):
    """ Connect to given server via SSH, read remote buffer_file, and returned
        the data stored there. If there is any error, return None
    """
    transport = get_authenticated_transport(server, user, private_key)
    if transport is None:
        return 1
    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        fh = sftp.open(buffer_file, 'rb')
        data = fh.read()
        transport.close()
        return data
    except IOError, error:
        ssh_error_msg('Cannot read from remote buffer %s: %s',
        buffer_file, error)
        return None


def read_from_localhost(buffer_file):
    """ Read data from the given buffer_file
    """
    try:
        fh = open(buffer_file, 'rb')
        data = fh.read()
        fh.close()
        return data
    except IOError, error:
        ssh_error_msg('Cannot read from local buffer %s: %s',
        buffer_file, error)
        return None


def main(argv=None):
    """ Main program """
    if argv is None:
        argv = sys.argv
    arg_parser = OptionParser(
    usage = "usage: %prog [options]",
    description = __doc__)
    arg_parser.add_option(
        '-c', action='store_true', dest='copy',
        default=False, help="copy STDIN data to the remote buffer")
    arg_parser.add_option(
        '-p', action='store_true', dest='paste',
        default=False, help="paste STDIN data from the remote buffer")
    arg_parser.add_option(
        '--config', default= os.path.expanduser('~/.ssh_clipboard.ini'),
        help="Location of config file. Default is ~/.ssh_clipbaord.ini")
    arg_parser.add_option(
        '--write-config', metavar='CONFIG', default=None,
        help="Write a default config file to CONFIG. ")
    options, args = arg_parser.parse_args(argv)
    params = get_params(options.config)
    if options.write_config is not None:
       write_default_config(options.write_config)
    if options.copy:
        data = os.sys.stdin.read()
        if options.paste:
            os.sys.stdout.write(data)
        if params['server'] == 'localhost':
            return write_to_localhost(params['buffer'], data)
        else:
            return write_to_server(params['server'], params['user'],
            params['private_key'], params['buffer'], data)
    elif options.paste:
        if params['server'] == 'localhost':
            data = read_from_localhost(params['buffer'])
        else:
            data = read_from_server(params['server'], params['user'],
            params['private_key'], params['buffer'])
        if data is not None:
            os.sys.stdout.write(data)
            return 0
        else:
            return 1


if __name__ == "__main__":
    sys.exit(main())

