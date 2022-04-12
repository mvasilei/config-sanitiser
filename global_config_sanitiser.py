#! /usr/bin/env python2.6
import sys
import signal, re, xlrd, subprocess
from optparse import OptionParser

def signal_handler(sig, frame):
    print('Exiting gracefully Ctrl-C detected...')
    sys.exit()

def read_from_book(filename):
    book = xlrd.open_workbook(filename)
    epe_list = book.sheet_by_name('PE List')
    agn = book.sheet_by_name('Core AGN')

    return epe_list.col_slice(0,1), agn.col_slice(2,1)

def sanitise(devices, pattern):
    for i in range(len(devices)):
        result = subprocess.Popen(
            ['cat /curr/' + devices[i].value.lower() + '.cfg'],
            stdout=subprocess.PIPE,
            shell=True)
        with open(devices[i].value +'.cfg', 'w') as outfile:
            print('Sanitising ' + devices[i].value)
            pass_free = re.sub(pattern, '### Password Removed ###', ''.join(result.stdout.readlines()))
            outfile.writelines(pass_free)
def main():
    #create command line options menu
    usage = 'usage: %prog options [arg]'
    parser = OptionParser(usage)
    parser.add_option('-z', '--zipassword', dest='zipassword',
                            help='Password to encrypt zipfile')
    parser.add_option('-f', '--filename', dest='filename',
                      help='xls file with device names')
    parser.add_option('-m', '--email', dest='email',
                            help='Email address to send the sanitised file')

    (options, args) = parser.parse_args()

    if not len(sys.argv) > 1:
        parser.print_help()
        exit()

    if not (options.filename and options.zipassword and options.email):
        parser.print_help()
        parser.error('Please specify filename, zip password and email address')

    epe, agn = read_from_book(options.filename)

    pattern = '(?<=password).*|(?<=authentication-key).*|(?<=secret).*|(?<=authentication hash md5).*|(?<=usm-community).*'
    sanitise(epe, pattern)

    pattern = '(?<=password\s).*|(?<=key-string\s).*|(?<=secret\s).*|(?<=\sauth\s).*|(?<=priv\s).*|(?<=key\s).*|(?<=authentication\s).*'
    sanitise(agn, pattern)

    #No python modules install to support encryption as such use standard linux commands
    print('Compressing config files...')
    result = subprocess.call(
        ['zip -P ' + options.zipassword + ' -9 all_devices.zip *.cfg'],
        stdout=subprocess.PIPE,
        shell=True)

    result = subprocess.call(
        ['uuencode all_devices.zip all_devices.zip | mailx -s "Sanitised config" ' + options.email],
        stdout=subprocess.PIPE,
        shell=True)

    result = subprocess.Popen(
        ['rm -f *.cfg'],
        stdout=subprocess.PIPE,
        shell=True)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)  #catch ctrl-c and call handler to terminate the script
    main()
