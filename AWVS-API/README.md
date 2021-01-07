1.使用时，请用文本编辑器打开代码文件，并搜索https://192.168.0.36:3443，全部替换成你自己的AWVS地址，当时是为了公司扫描方便临时撸了个脚本，本人比较懒，就不添加-u参数了，还得加判断逻辑。

2.代码末尾，请将X-Auth参数改成你自己的API-KEY（个人-配置文件-APIKAY）

    headers = {
        'X-Auth': '1986ad8c0a5b3df4d7028d5f3c06e936c715c2e5579754d5982904423ae2eb373',
        'Content-type': 'application/json'
    }
    
3.参数说明

  -f FILE, --file FILE  请输入目标文件路径
  
  -g REPORT, --report REPORT    此选项在全部目标扫描完成后使用，生成扫描报告
  
  -d DOWNLOAD, --download DOWNLOAD        此选项用于下载已经生成的扫描报告，需指定生成报告格式"html"
  
  -p PATH, --path PATH  此选项用于指定解析报告的报告所在路径，可以为绝对路径、相对路径（剔除多余信息，只留漏洞详情）
