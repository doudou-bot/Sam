import requests
from bs4 import BeautifulSoup as bs
import json
import argparse
import threading
from alive_progress import alive_bar,showtime,show_spinners,show_bars
from colorama import Fore, Back, Style
import os
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def add_target(tar):    #添加扫描任务
    """
    功能：新增扫描目标接口
        Method : POST
        URL : /api/v1/targets
        发送参数:
            发送参数     类型     说明
            address     string   目标网址:需要http或https开头
            criticality int      危险程度;范围:[30,20,10,0];默认为10
            description string   备注
    """
    api_url = 'https://192.168.0.36:3443/api/v1/targets'  # AWVS添加任务API接口
    data = {"address": tar,
            "description": "create_by_IntSig",
            "criticality": "10"}
    data = json.dumps(data)
    request = requests.post(url=api_url, data=data, headers=headers, verify=False)
    r = request.json()
    target_id = r['target_id']
    # print(target_id)
    print("[+]目标已经添加任务：" + tar)
    return target_id

def scan_speed(target_id):   #设置扫描速率
    """
     URL：api/v1/targets/{target_id}/configuration
    Method：patch
    PATCH参数类型：目标已开始扫描
    scan_speed string：slow(慢)、moderate(中)、fasts(快) 三种模式（str类型）
    """
    api_url = 'https://192.168.0.36:3443/api/v1/targets/' + target_id + '/configuration'
    data = json.dumps({"scan_speed":"slow"})
    r = requests.patch(url=api_url,headers=headers,data=data,verify=False)
    # print(r.status_code)

def start_target(target_id):  #开始扫描任务
    """
    功能:启动扫描任务接口
    Method : POST
    URL : /api/v1/scans
    发送参数:
        发送参数         类型     说明
        profile_id      string   扫描类型
        ui_session_i    string   可不传
        schedule        json     扫描时间设置（默认即时）
        report_template string   扫描报告类型（可不传）
        target_id       string   目标id
    """
    api_url = 'https://192.168.0.36:3443/api/v1/scans' #AWVS开始扫描任务API接口
    data = {
        "profile_id":"11111111-1111-1111-1111-111111111111",
        "schedule":{
            "disable":False,
            "start_date":None,
            "time_sensitive":False},
        "target_id":target_id}
    data= json.dumps(data)
    r = requests.post(url=api_url,data=data,headers=headers,verify=False)
    # res = r.json()
    # print("[+]目标已经开始扫描：" + )
    # print(json.dumps(res,indent=4))
    # return res

def get_scan_id():    #获取扫描任务的扫描ID
    id = []
    api_url = 'https://192.168.0.36:3443/api/v1/scans?l=100'
    r = requests.get(url=api_url,headers=headers,verify=False)
    res = json.loads(r.content.decode('utf-8'))
    res = res['scans']
    for final_res in res:
        scan_id = final_res['scan_id']
        id.append(scan_id)
    return id

def check_status():      #检查所有的扫描任务状态
    api_url = 'https://192.168.0.36:3443/api/v1/scans'
    print("[+]正在持续检查目标扫描任务状态.......")
    time.sleep(5)
    while True:
        r = requests.get(url=api_url, headers=headers, verify=False)
        r = r.json()
        r2 = json.dumps(r, indent=4)
        if ('processing' in r2) or ('Queued' in r2):
            time.sleep(2)
            continue
        else:
            del_scans()
            print(Back.RED + '[+]扫描任务已全部完成，请生成报告！')
            break

def del_scans():   #扫描完成后，对全部扫描任务进行甄别，删除高中危漏洞数量为0的扫描任务
    check_url = 'https://192.168.0.36:3443/api/v1/scans'
    r = requests.get(url=check_url, headers=headers, verify=False)
    r = r.content.decode('utf-8').strip('\n')
    r = json.loads(r)
    for i in r['scans']:
        if (i['current_session']['severity_counts']['medium'] == 0) and (
                i['current_session']['severity_counts']['high'] == 0):
            scan_id = i['scan_id']
            del_url = 'https://192.168.0.36:3443/api/v1/scans/' + scan_id
            r = requests.delete(url=del_url, headers=headers, verify=False)
            if r.status_code == 204:
                del_add = i['target']['address']
                print('\n')
                print('[+]该地址高中危漏洞数量为0，扫描任务已删除：' + del_add)

def generate_report(scan_id):     #生成扫描报告
    """
        生成扫描报告
            Method:POST
            URL: /api/v1/reports
            template_id	String	扫描报名模板类型
            list_type	String	值为: scans / targets
            id_list	String	值为: scan_id / target_id
            Affected Items	11111111-1111-1111-1111-111111111115
    """
    api_url = 'https://192.168.0.36:3443/api/v1/reports'
    data = {"template_id": "11111111-1111-1111-1111-111111111115",
                   "source": {"list_type": "scans", "id_list": [scan_id]}}
    data = json.dumps(data)
    # print(data)
    r = requests.post(url=api_url, headers=headers, data=data, verify=False)
    # print(r.status_code)
    res = r.json()
    # print(res)

def ectract_report(path):   #解析扫描报告，剔除信息类、低危、中危漏洞
    path = path
    path_list = os.listdir(path)
    items = path_list
    with alive_bar(len(items),title='[+]报告提取进度') as bar:
        for html in items:
            html = path + '\\' + html
            soup = bs(open(html, encoding='utf-8',errors='ignore'), features='html.parser')
            t1 = time.time()
            for doc in soup.find_all('table'):
                for type in doc.find_all('tr'):
                    if 'Total alerts found' in type.text:
                        break
                    if ('Low' in type.text) or ('Informational' in type.text) and ('Total alerts found' not in type.text):
                        doc.extract()
                    # elif 'TLS/SSL Sweet32 attack'
            os.remove(html)
            f = open(html, 'a+')
            f.write(str(soup))
            bar()
            t2 = time.time()
            time.sleep(t2-t1)
    print(Back.RED + "[+]扫描报告已全部提取完成！！")

def download_report(**tar):   #下载扫描报告
    # print(r['reports'])
    # print(r['reports'][0]['source']['description'])
    file = tar['source']['description']
    # print(file)
    file = file.replace('.', '_').replace('://', '_').replace(';create_by_IntSig', '').replace('/', '')
    file_name = file + '.html'
    down_url = 'https://192.168.0.36:3443' + tar['download'][0]
    r2 = requests.get(url=down_url, headers=headers, verify=False)
    # print(r2.status_code)
    f = open(file_name, 'w')
    f.write(r2.content.decode('utf-8'))
    f.close()
    if r2.status_code == 200:
        print('[+]报告下载完毕：' + file_name)
    else:
        print(Back.RED + '[+]报告下载失败：' + file_name)

def main():
    parser = argparse.ArgumentParser(usage='[+]扫描目标：python3 -f 扫描目标文件（绝对路径）' + '\n' + '       [+]生成报告：python3 -g 任意字符' + '\n' + '       [+]下载报告：python3 -d html' + '\n' + '       [+]解析报告：python3 -p 报告所在文件夹的绝对路径') #实例化一个对象
	parser.add_argument('-f','--file',help='请输入目标文件路径') #调用parser.parse_args()进行解析，将变量以标签-值的字典形式存入args字典
    parser.add_argument('-g','--report',help='此选项在全部目标扫描完成后使用，生成扫描报告')
    parser.add_argument('-d', '--download', help='此选项用于下载已经生成的扫描报告，需指定生成报告格式"html"')
    parser.add_argument('-p', '--path', help='此选项用于指定解析报告的报告所在路径，可以为绝对路径、相对路径')
    args = parser.parse_args()
    # if (args.file == None) and (args.report == None):
    #     print("请使用-f参数指定目标文件")
    if args.file != None:
        if args.report == None:
            Tar = args.file
            file = open(Tar, 'r')  # 打开需要扫描的目标文件
            target_list = []
            for target in file.readlines():
                t1 = time.time()
                target = target.strip('\n')
                target_id = add_target(target)  # 调用添加目标函数,调用开始任务函数
                scan_speed(target_id)
                t2 = time.time()
                target_list.append(target_id)
                print("[+]目标已开始扫描：" + target)
            thread_list = []
            for t_id in target_list:#多线程开始扫描任务
                t = threading.Thread(target=start_target(t_id), args=(t_id,))
                thread_list.append(t)
            for t in thread_list:
                t.start()
            for t in thread_list:
                t.join()
            time.sleep(1)
            check_status()
        else:
            print("[+]添加扫描任务时，请勿使用-g参数")

    if args.report != None:
        if args.file == None:
            print("[+]正在生成漏洞报告！")
            id = get_scan_id()  # 获取任务的扫描id 用于生成报告
            thread_list = []
            for scan_id in id:      #多线程开始生成报告
                t = threading.Thread(target=generate_report(scan_id), args=(scan_id,))
                thread_list.append(t)
            items = thread_list
            with alive_bar(len(items),title='[+]报告生成进度条',spinner='waves2') as bar:
                for item in items:
                    item.start()
                for item in items:
                    item.join()
                    t = time.thread_time()
                    bar()
            print(Back.RED + "[+]报告生成完毕！" + str(len(id)) + "份报告！")

    if args.path != None:
        path = args.path
        ectract_report(path)

    if args.download != None:
        if args.download == 'html':
            print("+---------------------------------+------+---------+-----+---------------+")
            print("|                Address          | High |  Mediun | Low |  Information  |")
            print("+---------------------------------+------+---------+-----+---------------+")
            check_url = 'https://192.168.0.36:3443/api/v1/scans'
            r2 = requests.get(url=check_url, headers=headers, verify=False)
            r2 = r2.content.decode('utf-8').strip('\n')
            r2 = json.loads(r2)
            res = r2['scans']
            for i in res:
                address = i['target']['address']
                High = i['current_session']['severity_counts']['high']
                Medium = i['current_session']['severity_counts']['medium']
                Low = i['current_session']['severity_counts']['low']
                Information = i['current_session']['severity_counts']['info']
                print("|%-33s|%-6s|%-9s|%-5s|%-15s|" % (address, High, Medium, Low, Information))
                print("+---------------------------------+------+---------+-----+---------------+")
            url = 'https://192.168.0.36:3443/api/v1/reports'  # url中不设置l参数，这样get请求可获取所有已经生成的报告下载链接，无需考虑数量过多，需要翻页问题
            r = requests.get(url=url, headers=headers, verify=False)
            r = r.content.decode('utf-8').strip('\n')
            r = json.loads(r)
            items = r['reports']
            with alive_bar(len(items), title='[+]报告下载进度条', bar='smooth') as bar:
                thread_list = []
                num = 0
                for tar in items:
                    t = threading.Thread(target=download_report, kwargs=tar)
                    thread_list.append(t)
                for i in thread_list:
                    i.start()
                    bar()
                    num = num + 1
                    time.sleep(time.thread_time())
                for i in thread_list:
                    i.join()
            print('[+]全部扫描报告下载完成！！共下载"' + str(num) + '"份报告')

if __name__ == '__main__':
    print("""
    \033[0;31m
     █████╗ ██╗    ██╗██╗   ██╗███████╗       █████╗ ██████╗ ██╗
    ██╔══██╗██║    ██║██║   ██║██╔════╝      ██╔══██╗██╔══██╗██║
    ███████║██║ █╗ ██║██║   ██║███████╗█████╗███████║██████╔╝██║
    ██╔══██║██║███╗██║╚██╗ ██╔╝╚════██║╚════╝██╔══██║██╔═══╝ ██║
    ██║  ██║╚███╔███╔╝ ╚████╔╝ ███████║      ██║  ██║██║     ██║
    ╚═╝  ╚═╝ ╚══╝╚══╝   ╚═══╝  ╚══════╝      ╚═╝  ╚═╝╚═╝     ╚═╝
                            Author By Sam
     \033[0m                                                                      
    """)

    headers = {
        'X-Auth': '1986ad8c0a5b3df4d7028d5f3c06e936c715c2e5579754d5982904423ae2eb373',
        'Content-type': 'application/json'
    }
    main()


