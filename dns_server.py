import sys

def run_dns_server(configpath):
    # your code here
    print(configpath)


# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]
    run_dns_server(configpath)