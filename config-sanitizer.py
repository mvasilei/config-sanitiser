#! /usr/bin/env python2.7
import sys, os, signal, re, getpass, time, subprocess
from zipfile import ZipFile
from optparse import OptionParser
sys.path.append(os.path.expanduser('~')+'/.local/lib/python2.7/site-packages/')
import paramiko

def signal_handler(sig, frame):
    print('Exiting gracefully Ctrl-C detected...')
    sys.exit()

def connection_establishment(USER, PASS, host):
    try:
        print('Processing HOST: ' + host)
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, 22, username=USER, password=PASS)
        channel = client.invoke_shell()
        while not channel.recv_ready():
            time.sleep(0.5)

        output = channel.recv(8192)
    except paramiko.AuthenticationException as error:
        print ('Authentication Error on host: ' + host)
        exit()
    except IOError as error:
        print (error)
        exit()

    return (channel, client)

def execute_command(command, channel, host):
    cbuffer = []
    data = ''

    channel.send(command)
    while True:
        if channel.recv_ready():
            data = channel.recv(1000)
            cbuffer.append(data)

        time.sleep(0.02)
        data_no_trails = data.strip()

        if len(data_no_trails) > 0: #and
            if data_no_trails.upper().endswith(host+'#'):
                break

    if channel.recv_ready():
        data = channel.recv(1000)
        cbuffer.append(data)

    rbuffer = ''.join(cbuffer)
    return rbuffer

def get_user_password():
    sys.stdin = open('/dev/tty')
    USER = raw_input("Username:")
    PASS = getpass.getpass(prompt='Enter user password: ')
    return USER, PASS

def main():
    pattern = ''

    #create command line options menu
    usage = 'usage: %prog options [arg]'
    parser = OptionParser(usage)
    parser.add_option('-d', '--device', dest='device',
                            help='Specify device name')
    parser.add_option('-z', '--zipassword', dest='zipassword',
                            help='Password to encrypt zipfile')
    parser.add_option('-m', '--email', dest='email',
                            help='Email address to send the sanitised file')

    (options, args) = parser.parse_args()

    if not len(sys.argv) > 1:
        parser.print_help()
        exit()

    if not (options.device and options.zipassword and options.email):
        parser.print_help()
        parser.error('Please specify device, zip password and email address')

    username, password = get_user_password()
    channel, client = connection_establishment(username, password, options.device)
    output = execute_command('show version | i Version\n', channel, options.device.upper())
    if 'Cisco' in output:
        execute_command('term len 0\n', channel, options.device.upper())
        output = execute_command('show run\n', channel, options.device.upper())
        pattern = '(?<=password\s).*|(?<=key-string\s).*|(?<=secret\s).*|(?<=\sauth\s).*|(?<=priv\s).*|(?<=key\s).*|(?<=authentication\s).*'
    else:
        execute_command('environment no more\n', channel, options.device.upper())
        output = execute_command('admin display-config\n', channel, options.device.upper())
        pattern = '(?<=password).*|(?<=authentication-key).*|(?<=secret).*|(?<=authentication hash md5).*|(?<=usm-community).*'

    with open(options.device+'.cfg', 'w') as outfile:
        pass_free = re.sub(pattern, '### Password Removed ###', output)
        outfile.writelines(pass_free)

    #No python modules install to support encryption as such use standard linux commands
    result = subprocess.Popen(
        ['zip -P ' + options.zipassword + ' -9 ' + options.device + '.zip' + ' ' + options.device + '.cfg'],
        stdout=subprocess.PIPE,
        shell=True)

    time.sleep(10)

    result = subprocess.Popen(
        ['uuencode ' + options.device+'.zip' + ' ' + options.device+'.zip' + ' | mailx -s "Sanitised config" ' + options.email],
        stdout=subprocess.PIPE,
        shell=True)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)  #catch ctrl-c and call handler to terminate the script
    main()
