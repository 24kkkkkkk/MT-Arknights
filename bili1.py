import time,json,socket,requests
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
        self.User = {'name': '未知', 'uid': '-1', 'secret': '-1',
                     'seqnum': '-1', 'lastLoginTime': '-1'}
        self.FirstLogin = True
        print('明日方舟防沉迷破解已在端口%s开启\n' % Config['port'])
        self.fklist = ["time/heartbeat",
                       "api/client/session.renewal",
                       "api/client/notice.list",
                       "api/client/user.info",
                       "user.token.oauth.login"]
        if self.check_user():
            while True:
                j = input("确定这是正确的吗?[输入 Y(是) 或 N(否)]:").lower()
                if j == "y":
                    self.load_user()
                    self.FirstLogin = False
                    break
                elif j == "n":
                    break

    def request(self, flow: HTTPFlow):
        for cgi in self.fklist:
            if cgi in flow.request.url and "biligame.net" in flow.request.host and not self.FirstLogin:
                ttime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                print("[%s]拦截请求防沉迷验证请求: %s" %
                      (ttime,flow.request.url))
                flow.kill()
        if "api/client/can_pay" in flow.request.url and "biligame.net" in flow.request.host:
            ttime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print("[%s]修改充值限制" %
                      (ttime,flow.request.url))
            flow.response.set_text('{code":0,"message":"ok","is_adult":1,"server_message":""}')
        if flow.request.url.startswith("https://ak-gs-b.hypergryph.com/account/login"):
            if self.FirstLogin:
                j = json.loads(flow.request.get_text())
                self.User["uid"] = j['uid']
            else:
                flow.request.host = "fuckfcm.hypergryph.com"
        if "ak-gs-b.hypergryph.com" in flow.request.url and not self.FirstLogin:
            ttime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            if "/account/login" in flow.request.url:
                flow.request.headers["secret"] = self.User['secret']
                flow.response.headers["seqnum"] = self.User['seqnum']
                self.User['lastLoginTime'] = ttime
                print("[%s]记录用户操作: 登录操作请求, 与服务器通信频道: %s,封包编号: %s" %
                      (ttime, self.User['secret'], self.User['seqnum']))
        if flow.request.host == "fuckfcm.hypergryph.com" and not self.FirstLogin:
            j = {
                "result": 0,
                "secret": self.User["secret"],
                "serviceLicenseVersion": 0,
                "uid": self.User["uid"]
            }
            flow.response = Response.make(200, json.dumps(
                j), {"seqnum": self.User['seqnum'], "Content-Type": "application/json; charset=utf-8", "cache-control": "no-cache", "Connection": "keep-alive", "Date": time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(time.time()-8*3600))})

    def response(self, flow: HTTPFlow):
        if "ak-gs-b.hypergryph.com" in flow.request.url and not self.FirstLogin:
            j = json.loads(flow.response.get_text())
            if "info" in j:
                if "curSeqNum" in j['info']:
                    ttime = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime())
                    info = json.loads(j['info'])
                    print("[%s]客户端封包编号 %s 小于或等于服务器,正在尝试自动修复" %
                          (ttime, self.User['seqnum']))
                    tseqnum = str(info['curSeqNum']+1).encode()
                    self.User['seqnum'] = tseqnum
                    header = {
                        "uid": flow.request.headers["uid"],
                        "X-Unity-Version": flow.request.headers["X-Unity-Version"],
                        "secret": flow.request.headers["secret"],
                        "Content-Type": flow.request.headers["Content-Type"],
                        "seqnum": tseqnum,
                        "User-Agent": flow.request.headers["User-Agent"],
                        "Host": flow.request.headers["Host"],
                        "Connection": flow.request.headers["Connection"],
                        "Accept-Encoding": flow.request.headers["Accept-Encoding"]
                    }
                    try:
                        res = self.post_to_gs(
                            header, flow.request.url, flow.request.get_text())
                        flow.response = Response.make(200, res, {"seqnum": self.User['seqnum'], "Content-Type": "application/json; charset=utf-8", "cache-control": "no-cache",
                                                      "Connection": "keep-alive", "Date": time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(time.time()-8*3600))})
                    except Exception as e:
                        print(repr(e))
            ttime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            if "/account/login" in flow.request.url:
                self.User['seqnum'] = flow.response.headers["seqnum"]
                print("[%s]记录用户操作: 登录操作回应, 与服务器通信频道: %s,封包编号: %s" %
                      (ttime, self.User['secret'], self.User['seqnum']))
            else:
                self.User['secret'] = flow.request.headers["secret"]
                self.User['seqnum'] = flow.response.headers["seqnum"]
                self.User['lastLoginTime'] = ttime
                self.save_user()
                print("[%s]记录用户操作: 游戏操作回应, 与服务器通信频道: %s,封包编号: %s" %
                      (ttime, self.User['secret'], self.User['seqnum']))
        if flow.request.url.startswith("https://ak-gs-b.hypergryph.com/account/syncData") and self.FirstLogin:
            j = json.loads(flow.response.get_text())
            self.User['name'] = j['user']['status']['nickName']
            self.FirstLogin = False

    def post_to_gs(self, header, url, data):
        retry_cnt = 3
        while retry_cnt > 0:
            retry_cnt -= 1
            try:
                request = requests.post(
                    url, data=data.encode('utf8'), headers=header)
                return request.text
            except Exception as e:
                ttime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                print("[%s]%s 请求失败: data:%s err_msg:%s" %
                      (ttime, url, data, str(e)))
                break

    def save_user(self):
        try:
            f = open('user_data.json', 'w')
            f.write(json.dumps(self.User))
        except Exception as e:
            print(repr(e))

    def check_user(self):
        try:
            f = open('user_data.json', 'r')
            tuser = json.load(f)
            if tuser['seqnum'] != "null" and tuser['seqnum'] != "-1" and tuser['secret'] != "-1":
                print(
                    """检测到有已经保存的用户信息:
用户名      : %s
UID         : %s
上次登录    : %s
通信频道    : %s
封包编号    : %s""" % (tuser['name'], tuser['uid'], tuser['lastLoginTime'], tuser['secret'], tuser['seqnum']))
                return True
        except Exception as e:
            print(repr(e))
            return False

    def load_user(self):
        try:
            f = open('user_data.json', 'r')
            self.User = json.load(f)
        except Exception as e:
            print(repr(e))


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

使用方法:在节假日时间内保持该脚本打开游戏登录获取到 通信频道 和 封包编号 即可在非节假日登录。
""" % (get_host_ip(), str(Config['port'])))
    input('按[回车]继续...')
    master.addons.add(fcm())
    master.run()


addons = [
    fcm()
]
