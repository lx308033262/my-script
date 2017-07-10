#!/usr/bin/python
# -*- coding: utf-8 -*-
#########################
#   Auther:zhanghao     #
####################################################
#2014-7-23新增一键更新功能                           #
#主要原理为从source host中拷贝目录，然后同步到线上     #
#暂时未添加替换配置文件的功能                         #
####################################################

####################################################
#2016-3-16新增服务无间断发版                         #
#主要原理为启动发版服务前后在nginx里将它加注释解注     #
#释，保证用户访问无间断                              #
####################################################


####################################################
#2016-3-18新增自动上传文件功能                        #
#主要原理为调用fab go:模块名来实现自动git切换分支，     #
#拉取代码，编译并上传到发版目录                        #
####################################################
####################################################
#2016-4-15fab go模块新增远程仓库克隆功能              #
#主要原理为fab go模块下新增一个clone函数,在新部署发版  #
#系统时如果有需要的话就克隆                           #
####################################################

#####本更新程序包括5个文件
#####update.py 更新脚本
#####nginx.py 服务无间断发版
#####fabfile.py 自动上传文件
#####mod.ini 更新服务器及模块 等配置信息
#####exclude.txt 同步时需要排除的文件 一行一个文件名称

#####配置文件中如果是jar包 mod_name必须和jar包名一样
#####本地文件夹名称必须和模块名称一样，可以是文件夹也可以是tar.gz或者zip包

import sys,os,pexpect,fileinput,paramiko,datetime,time,commands,pycurl,subprocess
from ConfigParser import ConfigParser

##########变量设置#################
#开始时间（结束后有个结束时间，两者相减即程序运行时间）
starttime=datetime.datetime.now()
#today="2014-5-21-101110"
today=time.strftime("%Y-%-m-%-d-%-H%-M",time.localtime())

#程序及配置文件所在路径
src_dir_prefix="/home/update/"
#模块信息配置文件
mod_file=src_dir_prefix + "conf/mod.ini"
#日志信息配置文件
log_conf=src_dir_prefix + "conf/logging.conf"
#同步需要排除的文件
exclude_file=src_dir_prefix + "conf/exclude.txt"
#读取配置文件
#模块IP/路径/模块类型
#PS:如果有tomcat 还需指定tomcat路径（重启tomcat服务用）
os.path.exists(mod_file) or sys.exit('can not find module config file %s' % mod_file)
cf=ConfigParser()
cp=ConfigParser()
cf.read(mod_file)
cp.read(log_conf)
#本地主机同步目录(备份目录）
if cf.has_option('common',"local_backup_dir_prefix"):
    local_backup_dir_prefix=cf.get("common","local_backup_dir_prefix")
else:
    local_backup_dir_prefix="/home/backup/"

#程序上传目录(上传目录不需加日期 每次替换上次上传的版本)
if cf.has_option("common","path"):
    upload_dir=cf.get("common","path")
else:
    upload_dir="/home/update/"
if upload_dir.endswith("/"):
    pass
else:
    upload_dir = upload_dir + "/"

#配置文件多IP分隔符
if cf.has_option("common","s_field"):
    s_field=cf.get("common","s_field")
else:
    s_field='|'



def helpFunc(a,b,c,d):
    print ""
    print "usage: update.py -m module_name -a action_type"
    print ""
    print "-l will only print all of the mod_name and exit"
    print "module_name provide module_name to update"
    print ""
    print "-A will sync file from  source server to dest server"
    print ""
    print "action type is update|backup|rollback|full_update|test_update"
    print ""
    print "example:  ./update.py -m mod -a update -A"   #A就是页面上的一键更新按钮
    print ""
    print "list mod:"
    print cf.sections()
    sys.exit(3)

def verFunc(a,b,c,d):
    print "Ver 0.0.1"
    sys.exit(3)

#日志文件
log_file=('.logfile')
######## 日志装饰器 #########
#from time import ctime
def log_fun(func):
    def wrappedFunc(*args,**kwargs):
        log_str='[%s] %s([%s],[%s]) executed \n' % (time.ctime(),func.__name__,args,kwargs)
        open(log_file,'a').writelines(log_str)
        #hist_str='%s(%s,%s) \n' % (func.__name__,args,kwargs)
        #open(hist_file,'a').writelines(hist_str)
        return func(*args,**kwargs)
    return wrappedFunc
######## 日志装饰器 #########


from optparse import OptionParser
parser = OptionParser(add_help_option=0)
parser.add_option("-h", "--help", action="callback", callback=helpFunc)
parser.add_option("-v", "--version", action="callback", callback=verFunc)
parser.add_option("-m", "--module", action="store", type="string",dest="mod",default="")
parser.add_option("-a", "--action", action="store", type="string",dest="act",default="")
parser.add_option("-A", "--auto", action="store_true",dest="auto")
parser.add_option("-V", "--rollback_version", action="store",dest="version",default="")
parser.add_option("-l", "--list", action="store_true", dest="list")

(options, args) = parser.parse_args()
mod_name=options.mod
action=options.act
version=options.version
auto=options.auto
#print options
print version
try:
    print auto
except:
    auto=False

#如果指定-l，仅列出模块列表 安全退出
if options.list:
    print cf.sections()
    sys.exit(0)

cp.set("handler_filehander","args",('/home/update/log/%s.log' % mod_name, 'a'))
cp.write(open(log_conf,"w"))
from lib.log import logger_root,logger_console
from lib.addserver import AddServer
from lib.nginx import nginx
from lib.docker import docker
from lib.check_status import CheckStatus,check_all_server

cmd="ps aux|grep update.py |grep %s|grep %s|grep -v grep|wc -l" % (mod_name,action)
out=subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
if int(out.stdout.read()) > 1:
    logger_console.error("[%s]进程id已经存在,请不要重复[%s]!如需了解详情,请查看日志!" % (mod_name,action))
    logger_root.error("[%s]进程id已经存在,请不要重复[%s]!如需了解详情,请查看日志!" % (mod_name,action))
    sys.exit(0)

logger_root.info("开始发版!!!!!")
#如果没有指定模块名或者动作,打印错误并退出
if mod_name or action:
    pass
else:
    logger_root.error('''you don't have mod_name and action!\nuse -h get some help''')
    logger_logger_console.error('''you don't have mod_name and action!\nuse -h get some help''')
    sys.exit()

#如果模块不在模块列表中，打印错误信息并退出
if not cf.has_section(mod_name):
    logger_root.error("mod_name %s not in mod_list\nmod_list must in \n %s \n\n see %s get more information" % (mod_name,cf.sections(),mod_file))
    logger_console.error("mod_name %s not in mod_list\nmod_list must in \n %s \n\n see %s get more information" % (mod_name,cf.sections(),mod_file))
    sys.exit()


print starttime

class haixuan():

    def __init__(self,mod_name='',host='',port='',upload_file_prefix='',local_backup_dir='',user='',password='',is_compress=''):
        self.mod_name = mod_name
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.is_compress = is_compress
        self.upload_file_prefix = upload_file_prefix
        self.local_backup_dir = local_backup_dir
        #print "upload_dir",upload_dir,"upload_file_prefix",upload_file_prefix,"local_backup_dir",local_backup_dir,"local_backup_dir_prefix",local_backup_dir_prefix,"remote_dst_file",remote_dst_file,"is_compress",is_compress,user,port,host

    @log_fun
    def scp_source_package_to_local(self):
        #一键更新，从远程主机拷贝模块目录 同步到线上目录
        self.is_compress = 'False'
        logger_root.info("scp_source_package_to_local")
        #如果本地主机有模块目录/jar包或者备份目录有更新包，则可以直接更新 无需从远程主机拷贝目录
        if os.path.exists("%s" %  upload_unzip_dir) or os.path.exists("%s" % upload_dir + mod_name + ".jar") or os.path.exists(local_backup_file_prefix):
            return 0
        #获取source server变量
        if cf.has_option(mod_name,'source_host') and cf.has_option(mod_name,'source_path') and cf.has_option(mod_name,'source_user') and cf.has_option(mod_name,'source_password'):
            if cf.has_option(mod_name,'source_port'):
                source_port = cf.get(mod_name,'source_port')
            else:
                source_port = 22
            source_host = cf.get(mod_name,'source_host')
            source_user = cf.get(mod_name,'source_user')
            source_password = cf.get(mod_name,'source_password')
            source_path =cf.get(mod_name,'source_path')
        #从source_host拷贝jar包（只拷贝时间最近的一个包）
            if type == "jar" or type == "war":
                cmd="cd %s;echo $(ls -rt *.%s|tail -1)" % (source_path,type)
                filename=run_command(cmd,user=source_user,port=source_port,password=source_password,host=source_host,stdout="file")
                source_path = cf.get(mod_name,'source_path') + filename
                backup_cmd="scp -q -P%s -r %s@%s:%s %s" % (source_port,source_user,source_host,source_path,upload_dir + mod_name + "." + type)
        #从source_host拷贝模块目录
            else:
                source_path = cf.get(mod_name,'source_path')
                #backup_cmd="scp -q -P %s -r %s@%s:%s %s" % (source_port,source_user,source_host,source_path,upload_unzip_dir)
                backup_cmd="rsync -q -e 'ssh -p %s' -avz --exclude=logs/ --exclude=log/ %s@%s:%s %s" % (source_port,source_user,source_host,source_path+"/",upload_unzip_dir)
            logger_root.info(backup_cmd)
            try:
                outfile=pexpect.run (backup_cmd, events={'(?i)password': source_password+'\n','continue connecting (yes/no)?':'yes\n'},timeout=None)
                logger_root.info(outfile)
            except Exception as e:
                print e
        else:
            logger_root.error("You want make it auto update ,Make sure you define source_host/source_path/source_user/source_password")
            logger_console.error("You want make it auto update ,Make sure you define source_host/source_path/source_user/source_password")
            sys.exit()


    @log_fun
    def mv_upload_file_to_backup_dir(self):
        #判断上传目录中是否有压缩包
        #if cf.has_option(mod_name,'is_compress') and cf.get(mod_name,'is_compress') == 'True':
        logger_root.info("mv_upload_file_to_backup_dir %s" % self.host)
        #如果备份目录有更新包 则不用拷贝
        if os.path.exists(local_backup_file_prefix):
            return 0
        else:
            os.path.exists(local_backup_file_prefix) or os.makedirs(local_backup_file_prefix)
        if self.is_compress == 'True':
            if os.path.exists("%s" % self.upload_file_prefix+".tar.gz") or os.path.exists("%s" % self.upload_file_prefix+".zip"):
        #如果是压缩包先解压
        #复制文件到本地同步目录
                if type == "java":
                    os.path.exists(local_backup_dir) or os.makedirs(local_backup_dir)
                    logger_root.info("chdir",local_backup_dir)
                    os.chdir(local_backup_dir)
                    logger_root.info('mv %s.tar.gz %s 2>/dev/null||mv %s.zip %s 2>/dev/null' % (self.upload_file_prefix,local_backup_dir,self.upload_file_prefix,local_backup_dir))
                    os.system("mv %s.tar.gz %s 2>/dev/null||mv %s.zip %s 2>/dev/null " % (self.upload_file_prefix,local_backup_dir,self.upload_file_prefix,local_backup_dir))
                elif type == "jar" or type == "war":
                    os.chdir(local_backup_file_prefix)
                    logger_root.info("chdir",local_backup_dir)
                    os.system("mv  %s %s" % (upload_dir + mod_name + "." + type,local_backup_file_prefix))
                    logger_root.info("mv %s %s" % (upload_dir + mod_name + "." + type,local_backup_file_prefix))
                elif type == "c" or type == "php" or type == "nodejs":
                    os.path.exists(self.local_backup_dir) or os.makedirs(self.local_backup_dir)
                    os.chdir(self.local_backup_dir)
                    os.system("mv %s.tar.gz %s 2>/dev/null||mv %s.zip %s 2>/dev/null " % (self.upload_file_prefix,self.local_backup_dir,self.upload_file_prefix,self.local_backup_dir))
                    logger_root.info("mv %s.tar.gz %s 2>/dev/null||mv %s.zip %s 2>/dev/null")
                else:
                    logger_root.error("mod_type error")
                    logger_console.error("mod_type error")
                    sys.exit()
                #print os.path.abspath(os.path.curdir)
                os.chdir(local_backup_dir)
                logger_root.info("tar xzf %s.tar.gz 2> /dev/null||unzip %s.zip 2>/dev/null" % (mod_name,mod_name))
                os.system("tar xzf %s.tar.gz 2> /dev/null||unzip %s.zip >/dev/null 2>&1" % (self.mod_name,self.mod_name))
                os.system("rm -f %s.tar.gz 2>/dev/null;rm -f %s.zip >/dev/null 2>&1" % (self.mod_name,self.mod_name))
                logger_root.info("rm -f %s.tar.gz 2>/dev/null;rm -f %s.zip 2>/dev/null" % (mod_name,mod_name))
                if type == "c":
                    os.system("[ -d %s ] && mv %s/* ./ && rmdir %s" % (self.mod_name,self.mod_name,self.mod_name))
            else:
                logger_root.error("You compress flag is True,but your " + upload_dir + "can't find " + self.mod_name + ".zip or " + self.mod_name + ".tar.gz")
                logger_console.error("You compress flag is True,but your " + upload_dir + "can't find " + self.mod_name + ".zip or " + self.mod_name + ".tar.gz")
                sys.exit()
        elif type == "jar" or type == "war" or type == "nodejs":
            #如果没有压缩包 探测是否有jar或者war包
            os.chdir(local_backup_file_prefix)
            logger_root.info("chdir",local_backup_dir)
            if type == "war":
                java_file="."
            elif type == "jar":
                java_file="-1.0-SNAPSHOT."
            if os.path.exists("%s" % upload_dir + mod_name + java_file + type):
                logger_root.info("mv %s %s" % (upload_dir + mod_name + java_file + type,local_backup_file_prefix))
                os.system("mv %s %s" % (upload_dir + mod_name + java_file + type,local_backup_file_prefix))
            else:
                logger_root.error(upload_dir + " can't find " + self.mod_name + java_file + type)
                logger_console.error(upload_dir + " can't find " + self.mod_name + java_file + type)
                sys.exit()
        else:
            #如果没有压缩包 是否有文件夹
            if os.path.exists("%s" %  upload_unzip_dir):
                os.system("mv  %s %s" % (upload_unzip_dir,self.local_backup_dir))
            #如果都没有 退出
            else:
                logger_root.error("You compress flag is  False,But " +upload_dir + " can't find " + self.mod_name + " directory")
                logger_console.error("You compress flag is  False,But " +upload_dir + " can't find " + self.mod_name + " directory")
                sys.exit()



    @log_fun
    def stop_program(self):
        #调用nginx加注释方法，在发版主机stop之前先在nginx的配置文件里将其注释
        logger_root.info("[%s]执行加注释函数!" % self.host)
        nginx_mod.add(self.host)
        time.sleep(40)
        logger_root.info('start sleep')
        #time.sleep(10)
        #time.sleep(180)
        #关闭应用
        if stop_cmd:
            rcmd=stop_cmd
        if type == "java" or type == "war":
            self.webapp=cf.get(self.mod_name,"tomcat_path")
            rcmd='''pid=`ps aux|grep %s|grep -v grep|awk '{print $2}'`;[ -n "$pid" ] && kill -9 $pid ; rm -rf %s/work/Catalina/''' % (self.webapp,self.webapp)
        elif type == "jar":
            rcmd='''pid=`ps aux|grep %s|grep -v grep|awk '{print $2}'`;[ -n "$pid" ] && kill -9 $pid ''' % (self.mod_name)
        elif type == "c":
            self.pname=remote_dst_file.split("/")[-1]
            rcmd='''pid=`ps aux|grep %s|grep -v grep|awk '{print $2}'`;[ -n "$pid" ] && kill -9 $pid '''  % self.pname
        elif type == "php":
            rcmd='''sh /home/kkb/start.sh'''
        elif type == "nodejs":
            rcmd='''ps aux|grep  $(ls -rt  %s/*.js|awk -F'/' '{print $NF}')|grep -v grep |awk '{print $2}'|xargs -I A kill -9 A '''  % remote_dst_file
        else:
            return 1
        logger_root.info(rcmd)
        run_command(rcmd)


    @log_fun
    def start_program(self):
        #启动应用
        if start_cmd:
            rcmd=start_cmd
        elif type == "java":
            rcmd='source /etc/profile ; %s/bin/startup.sh' % self.webapp
        elif type == "war" and action == "find_file_replace":
            rcmd='source /etc/profile ;cd %s ;./bin/startup.sh' % self.webapp
        elif type == "war":
            rcmd='rm -rf %s ;source /etc/profile ;cd %s ;./bin/startup.sh' % (remote_dst_file +  "{" + self.mod_name + ",ROOT}",self.webapp)
        elif type == "c":
            rcmd='''cd %s ;find ./bin  -path "*bak" -prune -o  -type f -exec test -x {} \; -a -exec ls {} \;|xargs -I a nohup a>nohup.out 2>&1 &''' % remote_dst_file
        elif type == "jar":
            rcmd='''source /etc/profile ; cd %s ; nohup java -jar $(ls -rt *.jar|tail -1)>nohup.out 2>&1 &''' % remote_dst_file
        elif type == "php":
            rcmd='''sh /home/kkb/start.sh'''
        elif type == "nodejs":
            rcmd='''cd %s ; nohup node $(ls -rt *.js|tail -1)>nohup.out 2>&1 &''' % remote_dst_file
        else:
            return 1
        run_command(rcmd)
        self.check_start_status()

    def check_start_status(self):
        if self.start_check() and self.check_status():
            time.sleep(3)
            for i in range(5):
                if mod_name == "gxb-sso" and check_mod.check_login():
                    logger_root.info("[%s] API 调用成功!" % self.host)
                    start_flag = True
                    break
                elif check_mod.check_status():
                    logger_root.info("[%s] API 调用成功!" % self.host)
                    start_flag = True
                    break
                else:
                    start_flag = False
                    time.sleep(10)
                    continue
            if not start_flag:
                logger_root.error("[%s] API 调用不成功!" % self.host)
                logger_console.error("[%s] API 调用不成功!" % self.host)
            if action != "gray_update" and start_flag:
                if mod_name != "gxb-scheduler":
                    # 调用nginx减注释方法，在发版主机启动后取消nginx注释
                    logger_root.info("[%s]执行解注释函数!" % self.host)
                    nginx_mod.dec(self.host)
        else:
            logger_root.error("[%s]未检测到程序端口[%s]或者API调用失败,程序启动失败!" % (self.host, ser_port))
            logger_console.error("[%s]未检测到程序端口[%s]或者API调用失败,程序启动失败!" % (self.host, ser_port))

    def start_check(self):
        if ser_port == "":
            return True
        for i in range(40):
            rcmd="sudo /usr/sbin/lsof -i:%s | grep -i LISTEN" % ser_port
            out = run_command(rcmd)
            if out == "":
                time.sleep(1)
                continue
            else:
                logger_root.info("[%s] 服务起来啦!" % self.host)
                return True

    @log_fun
    def check_status(self):
        #检测应用启动后是否报错
        logger_root.info("执行check_status函数!")
        if docker_flag == "1" or docker_flag == "2":
            for i in range(15):
                rcmd = '''sudo sh -c "docker exec -i %s ls /usr/local/tomcat/logs/|grep catalina.`date "+%%Y-%%m-%%d"`.log"|grep -v old''' % mod_name
                logger_root.info(rcmd)
                out = run_command(rcmd)
                if out != "":
                    rcmd='''sudo sh -c " docker exec -i %s tail -n 10 /usr/local/tomcat/logs/catalina.`date "+%%Y-%%m-%%d"`.log|grep 'Server startup'" ''' % mod_name
                    logger_root.info(rcmd)
                    out=run_command(rcmd)
                    if out == "":
                        if i == 14:
                            logger_root.error("[%s] 启动失败,未检测到'Server startup'" % self.host)
                            return False
                        time.sleep(10)
                    else:
                        return True
                else:
                    if i == 14:
                        logger_root.error("[%s] 启动失败,未生成日志文件catalina" % self.host)
                        return False
                    time.sleep(5)
        else:
            if type == "java" or type == "war":
                self.webapp=cf.get(self.mod_name,"tomcat_path")
                logger_root.info(self.webapp)
                rcmd="ps aux|grep %s|grep -v grep|awk '{print $2}'" % (self.webapp)
                out = run_command(rcmd)
                if out != '':
                #rcmd='grep -e -i -A500 '%s' %s/logs/catalina.out|grep -e 'Exception|error' %s/logs/catalina.out ' % (self.time,self.webapp)
                    #rcmd='''tail -n 2000  %s/logs/catalina.out|egrep -i -A50 -B30 'Exception|error'  ''' % (self.webapp)
                    rcmd='''while :; do tail -n 10  %s/logs/catalina.out|grep -i -A20 'Exception|error';  tail -n 10  %s/logs/catalina.out |grep 'Server startup' && exit; done  ''' % (self.webapp,self.webapp)
                    outlog=run_command(rcmd)
                    logger_root.info(outlog)
            elif type == "jar":
                rcmd="ps aux|grep %s|grep -v grep|awk '{print $2}'" % (self.mod_name)
                out = run_command(rcmd)
                if out != '':
                    rcmd='''tail -n 2000  %s/logs/err|egrep -i -A50 -B30 'Exception|error' ''' % (self.webapp)
                    outlog=run_command(rcmd)
                    logger_root.error(outlog)
                    logger_console.error(outlog)
            elif type == "nodejs":
                pass
            else:
                return 1

    def git_mod(self):
        api_type = self.mod_name
        if cf.has_option(api_type, "git_ip"):
            git_host = cf.get(api_type, "git_ip")
        else:
            logger_root.error("必须设置本地仓库机器的ip!")
            logger_console.error("必须设置本地仓库机器的ip!")
            sys.exit()
        (status,output)=commands.getstatusoutput('fab -H %s -f %slib/fabfile.py go:%s' % (git_host,src_dir_prefix,api_type))
        if log_detail == "True":
            logger_root.info(output)
            logger_root.info("#"*30)
        if status == 0:
            logger_root.info("模块%s上传war包成功！" % mod_name)
        else:
            logger_root.error("模块%s上传war包失败！" % mod_name)
            logger_console.error("模块%s上传war包失败！" % mod_name)
            sys.exit()

    @log_fun
    def update(self):
        #同步更新到远程服务器
        if auto:
            if docker_flag == "1" or docker_flag == "2":
                if mod_name != "gxb-scheduler":
                    logger_root.info("[%s]执行加注释函数!" % self.host)
                    nginx_mod.add(self.host)
                    time.sleep(2)
                if docker_git == "1":
                    ver=container_run.image2_func()
                elif docker_git == "2":
                    if not os.path.exists(local_backup_file_prefix):
                        self.git_mod()
                    self.mv_upload_file_to_backup_dir()
                    if image_flag == 0:
                        remote_dst = docker_path + "/" + mod_name
                        rcmd = "rsync -e 'ssh -p %s' -avz %s %s@%s:%s" % (
                            docker_port, local_backup_file_prefix, docker_user, docker_ip, remote_dst + "/")
                        logger_root.info(rcmd)
                        outfile = pexpect.run(rcmd, events={'(?i)password': docker_pwd + '\n',
                                                            'continue connecting (yes/no)?': 'yes\n'}, timeout=None)
                        ver = image.image_func()
                    container_run.container_func(ver)
                if show_flag:
                    ver_path=src_dir_prefix + "/log/version.txt"
                    with open(ver_path,"a+") as f:
                        f.write("%s:%s\n" % (self.mod_name,ver))
                if type == "war":
                    self.check_start_status()
                self.confirm()
            elif docker_flag == "3":
                if docker_git == "1":
                    ver = k8s_container.k8s_image_func()
                elif docker_git == "2":
                    if not os.path.exists(local_backup_file_prefix):
                        self.git_mod()
                    self.mv_upload_file_to_backup_dir()
                    if image_flag == 0:
                        remote_dst = docker_path + "/" + mod_name
                        rcmd = "rsync -e 'ssh -p %s' -avz %s %s@%s:%s" % (
                            docker_port, local_backup_file_prefix, docker_user, docker_ip, remote_dst + "/")
                        logger_root.info(rcmd)
                        outfile = pexpect.run(rcmd, events={'(?i)password': docker_pwd + '\n',
                                                            'continue connecting (yes/no)?': 'yes\n'}, timeout=None)
                        ver = image.image_func()
                k8s_container.k8s_func(ver)
            else:
                if git_enabled == "yes":
                    if not os.path.exists(local_backup_file_prefix):
                        self.git_mod()
                else:
                    self.scp_source_package_to_local()
                self.mv_upload_file_to_backup_dir()
                logger_root.info('start stop program')
                self.stop_program()
                logger_root.info('stop program ok')
                rcmd='[ -d %s ] || mkdir -p %s' %  (remote_dst_file,remote_dst_file)
                logger_root.info(rcmd)
                run_command(rcmd)
                rcmd="rsync -e 'ssh -p %s' -avz --exclude-from=%s %s %s@%s:%s" % (self.port,exclude_file,local_backup_file_prefix,self.user,self.host,remote_dst_file+"/")
                logger_root.info(rcmd)
                outfile=pexpect.run (rcmd, events={'(?i)password': self.password+'\n','continue connecting (yes/no)?':'yes\n'},timeout=None)
                self.confirm(remote_dst_file)
                if mod_name == "gxb-web" and self.host == "web1":
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*api/100.98.139.47\tapi/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                    rcmd = "sudo sed -i '/cas.gaoxiaobang.com/d' /etc/hosts"
                elif mod_name == "cms-web" and self.host == "cms1":
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*cms-api/100.98.139.47\tcms-api/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                    rcmd = "sudo sed -i '/cas.gaoxiaobang.com/d' /etc/hosts"
                elif mod_name == "cms-user" and self.host == "user1":
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*cms-api/100.98.139.47\tcms-api/g' /etc/hosts"
                elif mod_name == "hybird-web" and self.host == "hybird1":
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*api/100.98.139.47\tapi/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*cms-api/100.98.139.47\tcms-api/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*app/100.98.139.47\tapp/g' /etc/hosts"
                elif mod_name == "wechat" and self.host == "chat1":
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*api/100.98.139.47\tapi/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*app/100.98.139.47\tapp/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*cms-api/100.98.139.47\tcms-api/g' /etc/hosts"
                elif mod_name == "bi-web" and self.host == "bi1":
                    rcmd = "sudo sed -i 's/10.44.145.219[ \t]*bi-api/100.98.139.47\tbi-api/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                    rcmd = "sudo sed -i '/cas.gaoxiaobang.com/d' /etc/hosts"
                else:
                    rcmd = ""
                logger_root.info(rcmd)
                if rcmd != "": run_command(rcmd)
                self.start_program()

    def gray_update(self):
        # 灰度发版
        if auto:
            if docker_flag == "1":
                if not os.path.exists(local_backup_file_prefix):
                    self.git_mod()
                self.mv_upload_file_to_backup_dir()
                if image_flag == 0:
                    remote_dst = docker_path + "/" + mod_name
                    rcmd = "rsync -e 'ssh -p %s' -avz %s %s@%s:%s" % (
                    docker_port, local_backup_file_prefix, docker_user, docker_ip, remote_dst + "/")
                    logger_root.info(rcmd)
                    outfile = pexpect.run(rcmd, events={'(?i)password': docker_pwd + '\n',
                                                            'continue connecting (yes/no)?': 'yes\n'}, timeout=None)
                global ver
                ver = image.image_func()
                container_run.container_func(ver)
                self.check_start_status()
                self.confirm()
            if docker_flag == "2":
                if not os.path.exists(local_backup_file_prefix):
                    self.git_mod()
                self.mv_upload_file_to_backup_dir()
                if image_flag == 0:
                    remote_dst = docker_path + "/" + mod_name
                    rcmd = "rsync -e 'ssh -p %s' -avz %s %s@%s:%s" % (
                    docker_port, local_backup_file_prefix, docker_user, docker_ip, remote_dst + "/")
                    logger_root.info(rcmd)
                    outfile = pexpect.run(rcmd, events={'(?i)password': docker_pwd + '\n',
                                                            'continue connecting (yes/no)?': 'yes\n'}, timeout=None)
                global ver
                ver = image.image_func()
                k8s_container.k8s_func(ver)
            else:
                if git_enabled == "yes":
                    if not os.path.exists(local_backup_file_prefix):
                        self.git_mod()
                else:
                    self.scp_source_package_to_local()
                self.mv_upload_file_to_backup_dir()
                self.stop_program()
                rcmd = '[ -d %s ] || mkdir -p %s' % (remote_dst_file, remote_dst_file)
                run_command(rcmd)
                rcmd = "rsync -e 'ssh -p %s' -avz --exclude-from=%s %s %s@%s:%s" % (
                self.port, exclude_file, local_backup_file_prefix, self.user, self.host, remote_dst_file + "/")
                logger_root.info(rcmd)
                outfile = pexpect.run(rcmd, events={'(?i)password': self.password + '\n',
                                                    'continue connecting (yes/no)?': 'yes\n'}, timeout=None)
                self.confirm(remote_dst_file)
                if mod_name == "gxb-web" or mod_name == "hybird-web" or mod_name == "cms-web" or mod_name == "wechat":
                    rcmd="sudo sed -i 's/100.98.139.47[ \t]*api/10.44.145.219\tapi/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                if mod_name == "cms-web" or mod_name == "cms-user" or mod_name == "wechat" or mod_name == "hybird-web":
                    rcmd="sudo sed -i 's/100.98.139.47[ \t]*cms-api/10.44.145.219\tcms-api/g' /etc/hosts"
                    run_command(rcmd)
                    logger_root.info(rcmd)
                if mod_name == "hybird-web" or mod_name == "wechat":
                    rcmd = "sudo sed -i 's/100.98.139.47[ \t]*app/10.44.145.219\tapp/g' /etc/hosts"
                    logger_root.info(rcmd)
                    run_command(rcmd)
                if mod_name == "gxb-web" or mod_name == "cms-web" or mod_name == "bi-web":
                    rcmd = "sudo sed -i '$a 10.44.145.219\tcas.gaoxiaobang.com' /etc/hosts"
                    logger_root.info(rcmd)
                    run_command(rcmd)
                if mod_name == "bi-web":
                    rcmd = "sudo sed -i 's/100.98.139.47[ \t]*bi-api/10.44.145.219\tbi-api/g' /etc/hosts"
                    logger_root.info(rcmd)
                    run_command(rcmd)
                self.start_program()

    def confirm(self,remote_dst=""):
        if docker_flag == "1" or docker_flag == "2":
            rcmd="sudo docker ps | grep %s| awk '{print $2}'|awk -F':' '{print $2}'" % mod_name
        else:
            rcmd = "ls -d --full-time %s | awk '{print $6,$7}'" % remote_dst
        out = run_command(rcmd)
        mod_list.append((self.host, out))

    @log_fun
    def backup(self):
        #备份操作
        logger_root.info("backup start")
        os.path.exists(local_backup_file_prefix) or os.makedirs(local_backup_file_prefix)
        #backup_cmd="scp -P %s -r %s@%s:%s %s" % (self.port,self.user,self.host,remote_dst_file,local_backup_file_prefix)
        backup_cmd="rsync -e 'ssh -p %s' -avz --exclude=logs/  %s@%s:%s %s" % (self.port,self.user,self.host,remote_dst_file,local_backup_file_prefix)
        logger_root.info(backup_cmd)
        outfile=pexpect.run (backup_cmd, events={'(?i)password': self.password+'\n','continue connecting (yes/no)?':'yes\n'},timeout=None)
        logger_root.info(outfile)
        logger_root.info("%s backup successful!" % self.mod_name)
        sys.exit()

    @log_fun
    def rollback(self,version=version):
        #回滚
        #如果没有指定版本，找出时间最近的一次版本进行回滚
        logger_root.info("start rollback")
        if docker_flag == "1":
            container_run.rollback_func(version,docker_flag)
        elif docker_flag == "2":
            k8s_container.rollback_func(version,docker_flag)
        else:
            if not version:
                local_backup_mod_dir=local_backup_dir_prefix + mod_name + "/"
                cmd='''ls -rt %s|tail -2|head -1''' % local_backup_mod_dir
                version=os.popen(cmd).read().rstrip()
            #回滚目录
            self.back_dir=local_backup_dir_prefix + mod_name + "/" + version + "/"
            self.stop_program()
            rcmd="rsync -e 'ssh -p %s' -avz  --exclude-from=%s %s %s@%s:%s" % (self.port,exclude_file,self.back_dir + mod_name + "/",self.user,self.host,remote_dst_file+"/")
            logger_root.info(rcmd)
            outfile=pexpect.run (rcmd, events={'(?i)password': self.password+'\n','continue connecting (yes/no)?':'yes\n'},timeout=None)
            logger_root.info(outfile)
            self.start_program()

    def restart(self):
        # 重启模块
        if auto:
            if docker_flag == "1":
                #logger_root.info("[%s]执行加注释函数!" % self.host)
                #nginx_mod.add(self.host)
                #time.sleep(20)
                #restart方式:
                rcmd = "sudo docker restart %s" % mod_name
                logger_root.info(rcmd)
                run_command(rcmd)
                #run方式(备用):
                #container_run.restart_func()
                #self.check_start_status()
            else:
                self.stop_program()
                self.start_program()

    def check_server(self):
        if auto:
            logger_root.info("*"*10)
            if mod_name == "common":
                check_all_server()
            if mod_name == "mysql":
                logger_root.info("[%s] 开始检测!" % self.host)
                check_mod.check_mysql()
            elif mod_name == "redis":
                logger_root.info("[%s] 开始检测!" % self.host)
                check_mod.check_redis()
            elif mod_name == "gxb-sso" and check_mod.check_login():
                logger_root.info("[%s] API 调用成功!" % self.host)
            elif check_mod.check_status():
                logger_root.info("[%s] API 调用成功!" % self.host)
            else:
                logger_root.error("[%s] API 调用不成功!" % self.host)
                logger_console.error("[%s] API 调用不成功!" % self.host)
    def Addserver(self):
        if auto and add_flag:
            if docker_flag == "1":
                Add_Server.add_server()
            elif docker_flag == "2":
                k8s_container.add_dec_server()
    def Decserver(self):
        if auto and add_flag:
            if docker_flag == "1":
                Add_Server.dec_server()
            elif docker_flag == "2":
                k8s_container.add_dec_server()

    def find_file_replace(self):
        if auto:
            grep_list=[]
            rootdir = cf.get(self.mod_name,"tomcat_path")
            rcmd = "find %s -name %s -type f" %(rootdir,file_name)
            out = run_command(rcmd)
            if out == "":sys.exit("dont find files!")
            FileList = out.split("\n")
            logger_root.info("filename: %s" % str(FileList))
            for filename in FileList:
                if filename != "":
                    rcmd = "grep %s %s" % (old_content,filename)
                    grep_out = run_command(rcmd)
                    if grep_out != "":grep_list.append(grep_out)
                    rcmd = "sed -i 's;%s;%s;g' %s" %(old_content,new_content,filename)
                    logger_root.info(rcmd)
                    run_command(rcmd)
            self.stop_program()
            self.start_program()
            logger_root.info(grep_list)

global mod_list
mod_list=[]
if action == "gray_update":
    if cf.has_option(mod_name, 'gray_ip'):
        host_list = cf.get(mod_name, 'gray_ip').split(s_field)
    else:
        logger_root.error("[%s]此模块没有设置gray_ip" % mod_name)
        logger_console.error("[%s]此模块没有设置gray_ip" % mod_name)
        sys.exit()
else:
    host_list=cf.get(mod_name,'ip').split(s_field)
logger_root.info("主机列表: %s" % str(host_list))
if cf.has_option(mod_name,'user'):
    user_list=cf.get(mod_name,'user').split(s_field)
if cf.has_option(mod_name,'password'):
    password_list=cf.get(mod_name,'password').split(s_field)
if cf.has_option(mod_name,'port'):
    port_list=cf.get(mod_name,'port').split(s_field)
if cf.has_option(mod_name,'ser_port'):
    ser_port_list=cf.get(mod_name,'ser_port').split(s_field)
if cf.has_option(mod_name,"git_enabled"):
    git_enabled=cf.get(mod_name,'git_enabled')
else:
    git_enabled="yes"
if cf.has_option("common","log_detail"):
    log_detail = cf.get("common","log_detail")
else:
    log_detail = "False"


k=0
for host in host_list:
    if k == 0:
        image_flag=0
        add_flag=True
        show_flag=True
    else:
        image_flag=1
        add_flag=False
        show_flag=False
    k += 1
    #获取给定模块的主机IP、路径和程序类型
    #获取文件路径和cp路径必须获取模块名后才能确定 所以没写在上面的变量设定中
    host_index=host_list.index(host)
    try:
        remote_dst_file=cf.get(mod_name,"path")
        type=cf.get(mod_name,"type")
        #如果有端口/用户/密码选项则读取，没有则默认为37815/root/123456
        #如果有多个IP/端口/用户/密码 则根据list中的index查找
        if cf.has_option(mod_name,'user') and len(user_list)>host_index:
            user=user_list[host_index]
        elif cf.has_option(mod_name,'user'):
            user=cf.get(mod_name,'user')
        else:
            logger_root.error("必须设置%s的登录用户名!" % host)
            logger_console.error("必须设置%s的登录用户名!" % host)
            sys.exit()
        if cf.has_option(mod_name,'password') and len(password_list)>host_index:
            password=password_list[host_index]
        elif cf.has_option(mod_name,'password'):
            password=cf.get(mod_name,'password')
        else:
            logger_root.error("必须设置%s的登录密码!" % host)
            logger_console.error("必须设置%s的登录密码!" % host)
            sys.exit()
        if cf.has_option(mod_name,'port') and len(port_list)>host_index:
            port=port_list[host_index]
        elif cf.has_option(mod_name,'port'):
            port=cf.get(mod_name,'port')
        else:
            port=22
        if cf.has_option(mod_name,'ser_port') and len(ser_port_list)>host_index:
            ser_port=ser_port_list[host_index]
        elif cf.has_option(mod_name,'ser_port'):
            ser_port=cf.get(mod_name,'ser_port')
        else:
            logger_root.error("没有设置%s %s程序的监听端口!" % (host,mod_name))
        #判断上传文件是否是压缩包
        if cf.has_option(mod_name,'is_compress') and cf.get(mod_name,'is_compress') == 'True':
            is_compress='True'
        else:
            is_compress='False'
        if cf.has_option(mod_name,'start_cmd'):
            start_cmd=cf.get(mod_name,'start_cmd')
        else:
            start_cmd=False
        if cf.has_option(mod_name,'stop_cmd'):
            stop_cmd=cf.get(mod_name,'stop_cmd')
        else:
            stop_cmd=False
        if cf.has_option(mod_name, "file_name"):
            file_name = cf.get(mod_name, "file_name")
        else:
            file_name = ""
        if cf.has_option(mod_name, "old_content"):
            old_content = cf.get(mod_name, "old_content")
        else:
            old_content = ""
        if cf.has_option(mod_name, "new_content"):
            new_content = cf.get(mod_name, "new_content")
        else:
            new_content = ""
        if cf.has_option(mod_name,"check_url"):
            check_url=cf.get(mod_name,"check_url")
        else:
            logger_root.info("没有设置监控url")
            check_url=""
        if cf.has_option(mod_name,"key_word"):
            key_word=cf.get(mod_name,"key_word")
        else:
            logger_root.info("没有设置监控关键字")
            key_word=""
        if cf.has_option(mod_name,"dbname"):
            dbname = cf.get(mod_name,"dbname")
        else:
            dbname = ""

        #上传文件名称前缀
        upload_file_prefix=upload_dir + "/" + mod_name
        #解压文件夹
        upload_unzip_dir=upload_dir + "/" + mod_name + "/"
        #同步文件夹名称
        #本地备份文件夹名称（本地和远程模块同步文件夹名称）
        local_backup_dir=local_backup_dir_prefix + mod_name + "/" + today + "/"
        local_backup_file_prefix=local_backup_dir_prefix + mod_name + "/" + today + "/" + mod_name + "/"
        if cf.has_option(mod_name,"docker_flag"):
            docker_flag=cf.get(mod_name,"docker_flag")
        else:
            docker_flag="0"
        if docker_flag == "1" or docker_flag == "2":
            if cf.has_option(mod_name,"docker_git"):
                docker_git = cf.get(mod_name,"docker_git")
            else:
                docker_git = "1"
            if action == "gray_update":
                logger_console.info("本次发版将构建war包!")
            if action == "update":
                if docker_git == "1":
                    logger_console.info("本次发版不构建war包,从灰度发到线上!")
                elif docker_git == "2":
                    logger_console.info("本次发版将构建war包!")
            if cf.has_option("docker", "ip"):
                docker_ip = cf.get("docker", "ip")
            else:
                logger_root.error("必须设置构建镜像的服务器的ip")
                logger_console.error("必须设置构建镜像的服务器的ip")
                sys.exit()
            if cf.has_option("docker", "port"):
                docker_port = int(cf.get("docker", "port"))
            else:
                docker_port = 22
            if cf.has_option("docker", "user"):
                docker_user = cf.get("docker", "user")
            else:
                logger_root.error("必须设置构建镜像的服务器的user")
                logger_console.error("必须设置构建镜像的服务器的user")
                sys.exit()
            if cf.has_option("docker", "password"):
                docker_pwd = cf.get("docker", "password")
            else:
                logger_root.error("必须设置构建镜像的服务器的password")
                logger_console.error("必须设置构建镜像的服务器的password")
                sys.exit()
            if cf.has_option("docker", "path"):
                docker_path = cf.get("docker", "path")
            else:
                docker_path = "/docker/tomcat"
            if cf.has_option("docker", "url"):
                docker_url = cf.get("docker", "url")
            else:
                docker_url = "http://docker.gaoxiaobang.com"
        #if docker_flag == "1":
            if cf.has_option(mod_name,"restart"):
                restart=cf.get(mod_name,"restart")
            else:
                restart="always"
            if cf.has_option(mod_name,"dns"):
                dns=cf.get(mod_name,"dns")
            else:
                dns="127.0.0.1"
            if cf.has_option(mod_name,"vol_list"):
                vol_list=cf.get(mod_name,"vol_list")
            else:
                vol_list=""
            if cf.has_option(mod_name,"port_list"):
                port_list=cf.get(mod_name,"port_list")
            else:
                port_list=""
            if cf.has_option(mod_name, "option"):
                option = cf.get(mod_name, "option")
            else:
                option = ""
            if port_list == "":
                ser_port = ""
            else:
                ser_port = port_list.split(":")[0]
        #if docker_flag == "2":
            if cf.has_option(mod_name,"replicas"):
                replicas=cf.get(mod_name,"replicas")
            else:
                replicas="1"
    except Exception as e:
        print e
        logger_root.error("mod_name error!")
        logger_console.error("mod_name error!")
        sys.exit()

    #在远程主机上执行命令的函数
    @log_fun
    def run_command(cmd,user=user,port=port,password=password,host=host,stdout="stdout",):
        logger_root.info('start exec command %s' % cmd)
        client=paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.load_system_host_keys()
        port=int(port)
        #logger_root.info('start connect %s,%s,%s,%s' % (host,port,user,password) )
        client.connect(hostname=host, port=port,username=user,password=password,timeout=10)
        stdin,stdout,stderr = client.exec_command(cmd)
        stdin.write("%s\n" % password)  #这两行是执行sudo命令要求输入密码时需要的
        stdin.flush()                         #执行普通命令的话不需要这两行
        logger_root.error(stderr.read())
        logger_console.error(stderr.read())
        if stdout == "stdout":
            logger_root.info(stdout.read())
        else:
            return stdout.read()
        client.close()

    #调用nginx类生成nginx加注释和解注释模块
    if cf.has_option("lb","ip"):
        ip_list = cf.get("lb","ip")
    else:
        logger_root.error("必须设置nginx服务器的ip!")
        logger_console.error("必须设置nginx服务器的ip!")
        sys.exit()
    if cf.has_option("lb","port"):
        lb_port = int(cf.get("lb", "port"))
    else:
        lb_port = 22
    if cf.has_option("lb","user"):
        lb_user = cf.get("lb", "user")
    else:
        logger_root.error("必须设置nginx服务器的用户!")
        logger_console.error("必须设置nginx服务器的用户!")
        sys.exit()
    if cf.has_option("lb","password"):
        lb_passwd = cf.get("lb","password")
    else:
        logger_root.error("必须设置nginx服务器的密码!")
        logger_console.error("必须设置nginx服务器的密码!")
        sys.exit()
    if cf.has_option("lb","path"):
        lb_path = cf.get("lb", "path")
    else:
        logger_root.error("必须设置nginx服务的目录!")
        logger_console.error("必须设置nginx服务的目录!")
        sys.exit()
    if docker_flag == "1" or docker_flag == "2":
        Add_Server = AddServer(mod_name, host_list, restart, dns, vol_list.split("|"), port_list.split("|"), host, option, port, user, password,ip_list.split("|"))
        image = docker(ip=docker_ip, port=docker_port, user=docker_user, password=docker_pwd, url=docker_url, path=docker_path, mod_name=mod_name)
        container_run=docker(ip=host, port=port, user=user, password=password, url=docker_url, path=docker_path,mod_name=mod_name, restart=restart, dns=dns, vol_list=vol_list, port_list=port_list,hostname=host,option=option)
        k8s_container=docker(ip=host, port=port, user=user, password=password, url=docker_url, path=remote_dst_file,mod_name=mod_name, replicas=replicas)
    nginx_mod = nginx(ip_list=ip_list.split("|"),port=lb_port,user=lb_user,password=lb_passwd,path=lb_path,ser_port=ser_port)
    check_mod = CheckStatus(host=host,port=ser_port,user=user,password=password,dbname=dbname,url=check_url,keyword=key_word)
    t=haixuan(
        mod_name=mod_name,host=host,port=port,upload_file_prefix=upload_file_prefix,
        local_backup_dir=local_backup_dir,user=user,password=password,is_compress=is_compress)
    try:
        eval("t.%s()" % action)
    except Exception as e:
        logger_root.error("执行报错 %s" % e)
        logger_console.error("执行报错 %s" % e)

def clean_cdn_cache(mod_name):
    import subprocess
        if mod_name == 'cms-web':
            itemid="123"
            #clean_cmd
        if mod_name == 'gxb-web':
            itemid="456"
            #clean_cmd
    p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    out = p.stdout.read()
    if eval(out)["msg"] == "success":
        if eval(out)["result"][itemid] == 0:
            logger_root.info("[%s]cdn缓存刷新成功!" % mod_name)
        else:
            err_dic = {1:"任务解释异常或入库异常",
                      2:"域名未在cdn系统注册",
                      3:"域名未开启分发或是域名获取失败",
                      4:"action不在指定范围",
                      5:"域名未开启解压或切片或转码",
                      6:"域名未开启目录刷新（默认不开启）",
                      7:"此任务正在进行中"}
            logger_root.error("[%s]cdn缓存刷新失败! 错误信息:%s" % (mod_name,err_dic[eval(out)["result"][itemid]]))
    else:
        logger_root.error("[%s]cdn缓存刷新失败! 错误信息:%s" % (mod_name,eval(out)["msg"]))
if action == 'update' and (mod_name == 'gxb-web' or mod_name == 'cms-web'):
    clean_cdn_cache(mod_name)
logger_console.info("本次操作完成: %s" % str(mod_list))
endtime=datetime.datetime.now()
logger_root.info("this program consumed %s seconds " % (endtime - starttime))
