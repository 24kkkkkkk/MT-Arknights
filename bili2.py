import time
import json
import socket
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web.master import WebMaster
from mitmproxy.tools.console.master import ConsoleMaster
from mitmproxy.http import HTTPFlow, Request, Response
from mitmproxy import master, http
from configparser import ConfigParser

Config = {'port': 12450, 'mode': 'dump'}


def run_web(options):
    webserver = WebMaster(options)
    return webserver


def run_dump(options):
    server = DumpMaster(options, with_termlog=False, with_dumper=False)
    return server


def run_console(options):
    server = ConsoleMaster(options)
    return server


def get_config():
    global Config
    parser = ConfigParser()
    try:
        parser.read('.\config.ini', encoding='utf-8')
        Config['port'] = int(parser.get("default", "port"))
        Config['mode'] = parser.get("default", "mode")
        return True
    except Exception as e:
        print(repr(e))
        return False


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


class fcm:
    def __init__(self):
        print('明日方舟防沉迷破解已在端口%s开启' % Config['port'])

    def http_connect(self, flow: HTTPFlow):
        flow.kill()

    def response(self, flow: HTTPFlow):
        if "/app/v2/time/heartbeat" in flow.request.url:
            flow.kill()


addons = [
    fcm()
]

if __name__ == "__main__":
    if get_config():
        ops = Options(listen_host='0.0.0.0',
                      listen_port=Config['port'], http2=False, ssl_insecure=True)
        if Config['mode'].lower() == "web":
            master = run_web(ops)
        elif Config['mode'].lower() == "console":
            master = run_console(ops)
        else:  # dump
            master = run_dump(ops)
    else:
        ops = Options(listen_host='0.0.0.0',
                      listen_port=Config['port'], http2=False, ssl_insecure=True)
        master = run_dump(ops)
    print("""
请在手机或模拟器中完成以下配置：
1.确保手机或模拟器和电脑在同一局域网下。
2.在游戏开始唤醒时进行以下操作，防止拦截游戏更新。
3.进入手机或模拟器 WLAN(Wi-Fi) 设置配置手机代理。
    安卓：修改网络--高级选项--代理--手动
    iOS：HTTP 代理--配置代理--手动
        服务器(存在多个本机ip时，请输入和手机同一局域网的 ip)：
        %s
        端口：%s
    保存/储存
4.进入网站 http://mitm.it 下载证书(iOS为描述文件)并安装。
    iOS 多一步：设置--通用--关于本机--证书信任设置--mitmproxy--打开
5.重新进入游戏。
如果手机为安卓7.0及以上，请参考:
    方法1：使用安卓7.0以下版本的手机。
    方式2：Root 手机，安装 Xposed + JustTrustMe。
    方式3：不Root，使用 VirtualXposed、太极等 + JustTrustMe。或将游戏安装到安卓内模拟器 如: VMOS 等。
""" % (get_host_ip(), str(Config['port'])))
    input('按[回车]继续...')
    master.addons.add(fcm())
    master.run()
