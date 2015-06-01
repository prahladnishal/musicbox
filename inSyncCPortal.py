#!python2.6
#******************************************************************************
# Druva Confidential and Proprietary
#
#  Copyright (C) 2014, Druva Technologies Pte. Ltd.  ALL RIGHTS RESERVED.
#
#  Except as specifically permitted herein, no portion of the
#  information, including but not limited to object code and source
#  code, may be reproduced, modified, distributed, republished or
#  otherwise utilized in any form or by any means for any purpose
#  without the prior written permission of Druva Technologies Pte. Ltd.
#
#  Visit http://www.druva.com/ for more information.
#******************************************************************************


import os
import sys
import time
import logging
import socket
from inSyncLib import inSyncCherryPy
import cherrypy
import OpenSSL
import gettext
import threading
import urlparse
from OpenSSL import SSL

from optparse import OptionParser, SUPPRESS_HELP

from Lib import CloudConfig
from Lib import ClusterDB
from Lib import CloudConfigParser
from Lib import Globals
from Lib import MasterDB
from Lib import Params
from Lib import Utils
from Lib import dumpsig
import Providers

from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVNonCollection
from wsgidav.wsgidav_app import DEFAULT_CONFIG, WsgiDAVApp

from inSyncLib import inSyncLicense
from inSyncLib import inSyncCron
from inSyncLib import inSyncLog
from inSyncLib import inSyncUtil
from inSyncLib import inSyncParam
from inSyncLib import inSyncTrigger
from inSyncLib import inSyncAuthDB
from inSyncPanel import inSyncReportEngine
from inSyncLib import inSyncConfigParser
from inSyncLib import inSyncPerms
from inSyncLib import inSyncRPC
from inSyncLib import inSyncError
from inSyncLib import inSyncDhaga
from inSyncLib.inSyncError import SyncError
from inSyncLib.revision import REV
from inSyncLib import inSyncWebDav
from inSyncLib import inSyncWDDController
from inSyncLib.inSyncWDDController import inSyncWDDomainController
from inSyncShareLib import WebRestore
from inSyncLib import inSyncConnectionPool

def _(str):
    return str

def validate_admin_csrf():
    session_authenticated = cherrypy.session.get('username','')
    received_csrf_token = cherrypy.request.params.get('csrf_token','')
    secret_csrf_token = cherrypy.session.get('admin_csrf_token','')
    if session_authenticated and received_csrf_token != secret_csrf_token:
        msg = 'CSRF validation failed for ' + cherrypy.request.path_info + ' with args ' + str(cherrypy.request.params)
        SyncLog.info(msg)
        raise SyncError(inSyncError.ESTALECSRF)

def validate_user_csrf():
    session_authenticated = cherrypy.session.get('share_username','')
    received_csrf_token = cherrypy.request.params.get('csrf_token','')
    secret_csrf_token = cherrypy.session.get('user_csrf_token','')
    if session_authenticated and received_csrf_token != secret_csrf_token:
        msg = 'CSRF validation failed for ' + cherrypy.request.path_info + ' with args ' + str(cherrypy.request.params)
        SyncLog.info(msg)
        raise SyncError(inSyncError.ESTALECSRF)

cherrypy.tools.validate_admin_csrf = cherrypy.Tool('before_handler', validate_admin_csrf)
cherrypy.tools.validate_user_csrf = cherrypy.Tool('before_handler', validate_user_csrf)

def validate_querystring():
    if len(cherrypy.request.params) != 0:
        msg = 'XSS validation failed for ' + cherrypy.request.path_info + ' with args ' + str(cherrypy.request.params)
        SyncLog.error(msg)
        raise cherrypy.HTTPError(401)

cherrypy.tools.validate_querystring = cherrypy.Tool("before_handler", validate_querystring)

def validate_concurrentadminsession():
    username = cherrypy.session.get('username')
    if username:
        adminid = cherrypy.session['adminid']
        existing_session_id = AdminSessionMap.get(adminid)
        currend_session_id = cherrypy.session.id
        if existing_session_id and existing_session_id != currend_session_id:
            msg = 'Expiring old session with id ' + str(currend_session_id) + ' for adminid:' + str(adminid)
            SyncLog.info(msg)
            cherrypy.lib.sessions.expire()
            p = urlparse.urlparse(cherrypy.request.base)
            newurl = urlparse.urlunsplit(('https', p[1], '/', None, None))
            raise cherrypy.HTTPRedirect(newurl)

cherrypy.tools.validate_concurrentadminsession = cherrypy.Tool("before_handler", validate_concurrentadminsession)

def validate_concurrentusersession():
    username = cherrypy.session.get('share_username')
    if username:
        userid = cherrypy.session['userid']
        existing_session_id = UserSessionMap.get(userid)
        currend_session_id = cherrypy.session.id
        if existing_session_id and existing_session_id != currend_session_id:
            msg = 'Expiring old session with id ' + str(currend_session_id) + ' for userid:' + str(userid)
            SyncLog.info(msg)
            cherrypy.lib.sessions.expire()
            p = urlparse.urlparse(cherrypy.request.base)
            newurl = urlparse.urlunsplit(('https', p[1], '/home', None, None))
            raise cherrypy.HTTPRedirect(newurl)

cherrypy.tools.validate_concurrentusersession = cherrypy.Tool("before_handler", validate_concurrentusersession)

from Srv import SharePortal
import inSyncPanel
from inSyncPanel import inSyncWebAlert
from inSyncPanel import errorPage401
from inSyncPanel import RequestDurationTool

import inSyncSharePanel
from inSyncSharePanel.index import Root as SRoot
from inSyncSharePanel import errorPage401 as SerrorPage401
from inSyncSharePanel import inSyncCherrypyTunnel

if __name__ == '__main__':

    parser = OptionParser(usage=__doc__, version="Cloud Customer Portal 4.0.1")
    parser.add_option("-s", "--fromsource", action="count", dest="fromsource",
                      help=SUPPRESS_HELP)
    parser.add_option("-y", "--syslog", action="store_true", dest="syslog",
                      help=SUPPRESS_HELP)
    parser.add_option("-d", "--daemonize", action="count", dest="daemonize",
                      help="start the server as a daemon")
    parser.add_option("-l", "--local", action="store_true", dest="local",
                      help=SUPPRESS_HELP)
    parser.add_option("-e", "--debug", action="store_true", dest="debug", default=False,
                      help=SUPPRESS_HELP)
    parser.add_option("-n", "--connectDB", action="store_true", dest="connectDB",
                      help=SUPPRESS_HELP)
    parser.add_option("-m", "--set-mysqlconfig", action="store_true", dest="setmysqlconfig",
                      help=SUPPRESS_HELP)
    parser.add_option("-a", "--set-adminconfig", action="store_true", dest="setadminconfig",
                      help=SUPPRESS_HELP)
    parser.add_option("-p", "--check-apiservice", action="store_true", dest="checkapiserver",
                      help=SUPPRESS_HELP)
    parser.add_option("-w", "--check-cportalservice", action="store_true", dest="checkcportal",
                      help=SUPPRESS_HELP)

    if sys.platform == 'linux2':
        parser.add_option("-u", "--user", action="store", dest="user",
                          help="user to run the server process as",
                          type='string', default='')
        parser.add_option("-g", "--group", action="store", dest="group",
                          help="group to run the server process as",
                          type='string', default='')

    options, args = parser.parse_args()
    __builtins__.debug = options.debug
    if args:
        print >> sys.stderr, "Invalid syntax. Extra argument passed"
        print >> sys.stderr, __doc__
        sys.exit(1)

    if options.fromsource:
        Params.CPORTAL_WWW_DIR = os.path.join(os.getcwd(), '..', '..', 'www')
        Params.ORGPORTAL_WWW_DIR = os.path.join(os.getcwd(), '..', '..', 'www')
        Params.SHAREPORTAL_WWW_DIR = os.path.join(os.getcwd(), '..', '..', 'share')
    if options.daemonize:
        inSyncUtil.daemonize()

    inSyncParam.SERVER_SHARE_DIR = Params.SHAREPORTAL_WWW_DIR
    # init logging
    if options.syslog:
        SyncLog = inSyncLog.inSyncLog("CloudCustomerPortal", "syslog",
                                      "web",
                                      Params.MAX_DEBUG_LEVEL)
    else:
        SyncLog = inSyncLog.inSyncLog("CloudCustomerPortal", "server",
                                    Params.CPORTAL_LOGFILE,
                                    Params.MAX_DEBUG_LEVEL)

    SyncLog.insert_into_builtins()
    RestoreEstimateInfoObj = WebRestore.RestoreEstimateInfo()
    __builtins__.RestoreEstimateInfoObj = RestoreEstimateInfoObj
    Globals.log = SyncLog

    __builtins__.cloud_arch = inSyncUtil.check_cloud_edition()

    __builtins__._ = _

    
    if sys.platform == 'linux2' and not cloud_arch:
        if not options.user or not options.group:
            parser.error("Options -u and -g are mandatory") 
        
    #to set mysql credentials
    if options.setmysqlconfig:
        Globals.config = CloudConfigParser.MonitorConfig(Params.CLOUDSRV_CONFIG_FILE, ro=False)
        Globals.config.load()
        Globals.config['RDS_HOST'] = str(os.getenv("MYSQLHOST"))
        Globals.config['RDS_PORT'] = int(os.getenv("MYSQLPORT"))
        Globals.config['RDS_USER'] = str(os.getenv("MYSQLUSER"))
        Globals.config['RDS_PASSWD'] = str(os.getenv("MYSQLPASS"))
        Globals.config.save()
        sys.exit(0)

    Globals.config = CloudConfigParser.MonitorConfig()
    __builtins__.inSyncConfig = inSyncConfigParser.ServerConfig("")
    Utils.load_cloud_config()
    __builtins__.CloudConfig = Globals.config
    __builtins__.Globals     = Globals
    if inSyncUtil.check_cloud_edition():
        __builtins__.product_edition = inSyncParam.CLOUD_EDITION_NAME
    else:
        lic = inSyncLicense.License()
        lic.load()
        lic.insert_into_builtins()
        __builtins__.product_edition = inSyncUtil.getEdition()

    if options.setadminconfig:
        adminname = adminpass = None
        adminname = os.getenv("WEBADMIN")
        adminpass = os.getenv("WEBPASSWD")
        adminemail = os.getenv("WEBEMAIL")        
        try:
            MasterDB.InitDB()
            time.sleep(10)
            authAPI = inSyncAuthDB.AuthAPI()
            authAPI.createAdmin(adminname, adminpass,
                inSyncAuthDB.ADMIN_ROLE[inSyncAuthDB.SERVER_ADMIN], adminemail, force=True)
        except Exception as fault:
            print "Failed to create inSync Private Cloud Admin .%s" % str(fault)
            sys.exit(1)
        sys.exit(0)            

    if options.connectDB:
        try:
            inSyncUtil.connectDB(Globals.config['RDS_USER'], Globals.config['RDS_PASSWD'], 
                                    Globals.config['RDS_HOST'], Globals.config['RDS_PORT'])
            print "DB connection successfull."
            print "Use -f option to override the set config."
            sys.exit(0)
        except Exception as fault:
            print "Cannot connect to DB."
            print "Use -f option to recreate config with correct credentials."
            sys.exit(1)

    if options.checkapiserver:
        import xmlrpclib
        retry = 15
        cfgsrv = inSyncRPC.DispatcherClient(('127.0.0.1', inSyncParam.API_RPC_PORT), inSyncConfig.ADMINKEY, 'authenticate', mtserver=True)
        while True:
            try:
                # Verify that the server is indeed running.
                if not Globals.config['RDS_USER']:
                    print "Please configure the master server by running /usr/sbin/insync-master-config.sh as root."
                    sys.exit(1)
                cfgsrv.server.validate_version(inSyncParam.API_RPC_VERSION)
                sys.exit(0)
            except Exception as fault:
                # Retry in case of inSync Cloud if service is running
                if inSyncUtil.checkService(Params.CLOUD_SERVICE_NAME) and retry:
                    retry -= 1
                    time.sleep(5)
                    continue
                print "Could not connect to inSync Master service. Please start sevices."
                sys.exit(1)
            
    if options.checkcportal:
        #check if Admin UI is ready
        import urllib2
        retry = 15
        protocol = "https" #always https for msp and cloud
        url = '%s://127.0.0.1:%d' % (protocol, inSyncConfig.WEB_PANEL_PORT)
        while True:
            try:
                if not Globals.config['RDS_USER']:
                    sys.exit(1)
                response = urllib2.urlopen(url, timeout=5)
                sys.exit(0)
            except Exception as fault:
                if retry:
                    retry -= 1
                    time.sleep(5)
                    continue
                print "Could not connect to inSync Master Control Panel service. Please start sevices."
                sys.exit(1)

    try:
        inSyncDhaga.init_ioloopthr()
    except Exception, fault:
        SyncLog.traceback(fault)
        sys.exit(1)
    try:
        Globals.cfgsrvpool = inSyncConnectionPool.ConnectionPoolManager('apiserver', inSyncConfig.APISERVER_CPOOL_SIZE, inSyncConfig.ADMINKEY, 
                            'authenticate',  mtserver=True, async=True)
        if product_edition != inSyncParam.CLOUD_EDITION_NAME:
            Globals.clustersrvpool = inSyncConnectionPool.ConnectionPoolManager('master_apiserver', 1, inSyncConfig.ADMINKEY, 
                            'authenticate', mtserver=True, async=True)
    except Exception, fault:
        SyncLog.traceback(fault)
        raise

    if cloud_arch:
        from Lib import Debug
        ndbg_srv = Debug.DebugService("CPortal", Params.NDBG_LOCAL_URL)
        ndbg_srv.start()

    if not options.local:
        Providers.Init()
        for provider in Globals.providers.values():
            provider.connect()
    else:
        #Change the port so that multiple process can run in localmode
        Params.CFG_SERVER_PORT = 6062

    MasterDB.InitDB()
    if cloud_arch:
        dumpsig.install_dumper_thread("CPortal")
    
    if options.local:
        cloudapi = ClusterDB.LocalhostCloudAPI()
    else:
        cloudapi = ClusterDB.CloudAPI()
    __builtins__.CloudAPI = cloudapi

    cron_thread = inSyncCron.Cron(inSyncCron.WEB_CRON, name = "Web Panel Cron")
    __builtins__.WebPanelCron = cron_thread
    cron_thread.start()

    report_engine =  inSyncReportEngine.WebPanelReportEngine()
    __builtins__.WebPanelReportEngine = report_engine
    #WebPanelReportEngine.reload()

    alert_engine = inSyncWebAlert.AlertEngine()
    __builtins__.WebPanelAlertEngine = alert_engine
    alert_engine.start()

    try:
        if not cloud_arch:
            inSyncPerms.ResetPermissions(Params.CPORTAL_LOGFILE, False)
    except:
        pass

    #initialise the global loader in the inSyncPanel
    inSyncPanel.init_loader(Params.CPORTAL_WWW_DIR, options.debug)
    SharePortal.init_panel('/home')
    # create an instance of the app
    from inSyncPanel.index import BaseRoot, Root, OrgRoot
    baseroot = BaseRoot()
    root = Root(vroot=inSyncParam.ADMINCONSOLE_VROOT)
    print "Root",root
    share_root = SRoot(vroot="/home", session_key="share_username")
    print "Share root", share_root
    if product_edition == inSyncParam.CLOUD_EDITION_NAME:
        wrsaml = baseroot.wrsaml
        share_root.wrsaml = wrsaml
        # Set share_root as target for saml consume....
        wrsaml.parent = share_root
    else:
        orgportal_root = OrgRoot(vroot=inSyncParam.ORGPORTAL_VROOT, session_key="orgportal_username")
        print "Orgportal root", orgportal_root


    if not os.path.exists(inSyncParam.SERVER_SSLKEY_FILE):
        SyncLog.info('Exiting: Could not find ssl key file')
        os._exit(1)

    sslkeyf = inSyncParam.SERVER_SSLKEY_FILE
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_options(SSL.OP_CIPHER_SERVER_PREFERENCE|SSL.OP_NO_SSLv2|SSL.OP_ALL)
    ctx.use_privatekey_file(sslkeyf)
    ctx.load_verify_locations(sslkeyf)
    ctx.use_certificate_file(sslkeyf)
    ctx.set_cipher_list('ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:HIGH:!RC4:!MD5:!aNULL:!EDH')
    cherrypy.tools.request_duration = RequestDurationTool()

    # Custom authorization framework

    def custom_authorize():
        #Checking only for guests which have resetpwd true 
        cmenu = cherrypy.session.get('cmenu', False)
        
        if cherrypy.session.get('user') and not cmenu:
            resetpass = cherrypy.session['user']['resetpasswd']
            useAD = cherrypy.session['user']['useADPassword']
            useSaml = cherrypy.session['user']['useSaml']
            if resetpass and (not useAD) and (not useSaml):
                SyncLog.error('Reset the password for the user=%s', cherrypy.session['user']['id'])
                raise cherrypy.HTTPRedirect('/home/dologout')

    if cloud_arch:
        cportal_listen_port = inSyncConfig.CLOUD_CPORTAL_PORT
    else:
        cportal_listen_port = inSyncConfig.WEB_PANEL_PORT

    cherrypy.tools.custom_authorize = cherrypy.Tool("before_handler", custom_authorize)

    base_config = {
        '/' : {
            'tools.sessions.on'      : True,
            'tools.sessions.locking' : 'explicit',
            }
        }

    config = {
        'global' : {
            'server.socket_host' : '0.0.0.0',
            'server.socket_port' : cportal_listen_port,
            'server.thread_pool' : 64,
            'server.socket_queue_size' : 128,
            'server.max_request_body_size' : 310 * 1024 * 1024,
            'engine.autoreload_on' : False,
            'log.error_file' : '',
            'log.access_file' : '',
            'log.screen' : False,
            'checker.on' : False,
            'server.ssl_context' : ctx,
            'server.ssl_module' : 'pyopenssl',
            'tools.sessions.httponly'   : True, 
            'tools.sessions.locking' : 'explicit',
            'tools.sessions.secure'     : True,
            'tools.request_duration.on' : True,
            'error_page.default'       : os.path.join(Params.CPORTAL_WWW_DIR, 'html/error_default.html'),
            'error_page.405'       : os.path.join(Params.CPORTAL_WWW_DIR, 'html/error_405.html'),
            },
        '/' : {
            'tools.log_headers.on' : False,
            'tools.staticdir.root'   : Params.CPORTAL_WWW_DIR,
            'tools.staticfile.root'  : Params.CPORTAL_WWW_DIR,
            'tools.gzip.on'          : True,
            'tools.gzip.mime_types': ['text/*','application/javascript','application/x-javascript'],
            'tools.caching.on'       : False,
            'tools.sessions.timeout' : 30,
            'tools.sessions.on'      : True,
            'tools.session_auth.on'  : True,
            'tools.session_auth.login_screen' : root.login_page,
            'tools.session_auth.do_login' : root.dologin,
            'tools.sessions.locking' : 'explicit',
            'response.headers.server' : 'WebServer',
            
            # 'tools.on_login'       : WebPanelUser.on_login,
            # 'tools.on_logout'      : WebPanelUser.on_logout,
            #'tools.session_auth.debug' : True,
            'request.error_response' : root.handle_error,
            'response.headers.X-Frame-Options' : 'SAMEORIGIN',
            'tools.validate_concurrentadminsession.on' : True
            },
        '/styles': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : 'styles'
            },
        '/' + REV + '/css': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : 'css'
            },
        '/' + REV + '/css': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : 'css'
            },
        '/css': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : 'css'
            },
        '/images': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'images')
            },
        '/img': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : 'img',
            'tools.validate_querystring.on' : True
            },
        '/' + REV + '/js': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'js')
            },
        '/js': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : 'js'
            },
        '/' + REV + '/insyncjs': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : 'insyncjs'
            },
        '/doc': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : '../../insync/doc'
            },
        '/wrsaml' : {
            'tools.sessions.on'      : True,
            'tools.session_auth.on'  : False
            },
        '/webrestore': {
            'tools.session_auth.on'  : False
            },
        '/resetaccount': {
            'tools.session_auth.on'  : False
            },
        '/sendpush': {
            'tools.session_auth.on'  : False
            },
        '/upgnotifications': {
            'tools.session_auth.on'  : False
            },
        }

    share_config = {
        '/' : {
            'tools.log_headers.on' : False,
            'tools.staticdir.root'   : Params.SHAREPORTAL_WWW_DIR,
            'tools.staticfile.root'  : Params.SHAREPORTAL_WWW_DIR,
            'tools.gzip.on'          : True,
            'tools.gzip.mime_types': ['text/*','application/javascript','application/x-javascript'],
            'tools.caching.on'       : False,
            'tools.sessions.timeout' : 30,
            'tools.sessions.on'      : True,
            'tools.session_auth.on'  : True,
            'tools.session_auth.debug'  : True,
            'tools.session_auth.session_key'  : 'share_username',
            'tools.session_auth.login_screen' : share_root.login_page,
            #'tools.session_auth.do_login' : share_root.dologin,
            'tools.sessions.locking' : 'explicit',
            'tools.session_auth.debug' : True,
            #'tools.on_login'       : WebPanelUser.on_login,
            #'tools.on_logout'      : WebPanelUser.on_logout,
            'request.error_response' : share_root.handle_error,
            'tools.sessions.httponly'   : True, 
            'tools.sessions.secure'     : True,
            'response.headers.server' : 'WebServer',
            'error_page.401'       : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'templates/error_401.html'),
            'error_page.403'       : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'templates/error_403.html'),
            'error_page.404'       : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'templates/error_404.html'),
            'error_page.500'       : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'templates/error_500.html'),
            'tools.validate_concurrentusersession.on': True
            },
        '/share' : {
            'tools.custom_authorize.on' : True,
        },
        '/webrestore' : {
            'tools.custom_authorize.on' : True,
        },
        '/dologin': {
            'tools.session_auth.on' : False,
            },
        '/tray' : {
            'tools.session.on'        : False,
            'tools.session_auth.on'  : False,
            },
        '/link' : {
            'tools.session.on'        : False,
            'tools.session_auth.on'  : False,
            },
        '/cmenu/do' : {
            'tools.session.on'        : False,
            'tools.session_auth.on'  : False,
            },
        '/' + REV + '/styles': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'styles')
            },
        '/images': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'images')
            },
        '/' + REV + '/js': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'js')
            },
        '/locale': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'locale')
            },
        '/errorpagestyles': { 
            'tools.session_auth.on'  : False, 
            'tools.staticdir.on'  : True, 
            'tools.staticdir.dir' : 'styles' 
            }, 
        '/doc': {
            'tools.session_auth.on'  : False,
            'tools.staticdir.on'  : True,
            'tools.staticdir.dir' : '../doc'
            }
        }

    if product_edition <> inSyncParam.CLOUD_EDITION_NAME:
        orgportal_config = {
            '/' : {
                'tools.log_headers.on' : False,
                'tools.staticdir.root'   : Params.ORGPORTAL_WWW_DIR,
                'tools.staticfile.root'  : Params.ORGPORTAL_WWW_DIR,
                'tools.gzip.on'          : True,
                'tools.gzip.mime_types': ['text/*','application/javascript','application/x-javascript'],
                'tools.caching.on'       : False,
                'tools.sessions.timeout' : 30,
                'tools.sessions.on'      : True,
                'tools.session_auth.on'  : True,
                'tools.session_auth.debug'  : True,
                'tools.session_auth.session_key'  : 'orgportal_username',
                'tools.session_auth.login_screen' : orgportal_root.login_page,
                #'tools.session_auth.do_login' : share_root.dologin,
                'tools.sessions.locking' : 'explicit',
                'tools.session_auth.debug' : True,
                #'tools.on_login'       : WebPanelUser.on_login,
                #'tools.on_logout'      : WebPanelUser.on_logout,
                'request.error_response' : orgportal_root.handle_error,
                'tools.sessions.httponly'   : True, 
                'tools.sessions.secure'     : True,
                'response.headers.server' : 'WebServer'
                },
            '/dologin': {
                'tools.session_auth.on' : False,
                },
            '/tray' : {
                'tools.session.on'        : False,
                'tools.session_auth.on'  : False,
                },
            '/link' : {
                'tools.session.on'        : False,
                'tools.session_auth.on'  : False,
                },
            '/cmenu/do' : {
                'tools.session.on'        : False,
                'tools.session_auth.on'  : False,
                },
            '/' + REV + '/css': {
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : 'css'
                },
            '/' + REV + '/styles': {
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'styles')
                },
            '/images': {
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'images')
                },
            '/img': {
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : 'img',
                'tools.validate_querystring.on' : True
                },
            '/' + REV + '/insyncjs': {
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : 'insyncjs'
                },
            '/locale': {
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : os.path.join(Params.SHAREPORTAL_WWW_DIR, 'locale')
                },
            '/errorpagestyles': { 
                'tools.session_auth.on'  : False, 
                'tools.staticdir.on'  : True, 
                'tools.staticdir.dir' : 'styles' 
                }, 
            '/doc': {
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : '../doc'
                }
            }
    # bake and serve
    if not cloud_arch:
        if not options.fromsource:
            doc ={
                'tools.session_auth.on'  : False,
                'tools.staticdir.on'  : True,
                'tools.staticdir.dir' : '../doc'
                }
            config['/doc'] = doc
    
    cherrypy.config.update(config['global'])
    cherrypy.config.update({'error_page.401': errorPage401})
    # Enable analytics for production only.
    cherrypy.config['clickAnalytics'] = Globals.config['CLOUD_NAME'] in ('cloud',)
    baseapp = cherrypy.tree.mount(baseroot, '/', config=base_config)
    app = cherrypy.tree.mount(root, inSyncParam.ADMINCONSOLE_VROOT, config=config)
    shareapp = cherrypy.tree.mount(share_root, "/home", config=share_config)

    __builtins__.AdminConsoleRoot = root

    #Not running webdav app for cloud
    if product_edition <> inSyncParam.CLOUD_EDITION_NAME:
        srv = inSyncWebDav.init('inSyncCPortal')
        wprovider = inSyncWebDav.WebDavProvider()
        wconfig = DEFAULT_CONFIG.copy()
        wconfig.update({'provider_mapping': {'/': wprovider}, 'user_mapping': {}, 'verbose': 0, 'enable_loggers': [],
                        'propsmanager': True, 'locksmanager': False, 'domaincontroller': inSyncWDDomainController(timeout=120,srv=srv), 
                        'defaultdigest':False, 'acceptdigest':False, 'acceptbasic':True})
        wapp = WsgiDAVApp(wconfig)
        cherrypy.tree.graft(wapp, '/webdav')

        cherrypy.log.access_log.propagate = 0 
        cherrypy.log.error_log.propagate = 0

    if product_edition <> inSyncParam.CLOUD_EDITION_NAME:
        orgportalapp = cherrypy.tree.mount(orgportal_root, inSyncParam.ORGPORTAL_VROOT, config=orgportal_config)
    
    log = app.log
    log.error_file = ''
    log.access_file = ''

    for h in SyncLog.logger.handlers:
        app.log.error_log.addHandler(h)
        shareapp.log.error_log.addHandler(h)
        if product_edition <> inSyncParam.CLOUD_EDITION_NAME:
            orgportalapp.log.error_log.addHandler(h)
        #cherrypy.log.error_log.addHandler(h)
        #cherrypy.log.access_log.addHandler(h)
    cherrypy.log.error_log.setLevel(logging.DEBUG)
    
    __builtins__.inSyncUgettext = {}
    locales = ['en', 'fr', 'de']
    for locale in locales:
        path = "translations/%s/LC_MESSAGES/inSyncSharePanelMessages.mo" % locale
        filename = os.path.join(Params.SHAREPORTAL_WWW_DIR, path)
        try:
            trans = gettext.GNUTranslations(open( filename, "rb" ) )
        except IOError:
            trans = gettext.NullTranslations()
        __builtins__.inSyncUgettext[locale] = trans.ugettext
    
    th = threading.Thread(target=inSyncCherrypyTunnel.start, args=('127.0.0.1', Params.CFG_SERVER_PORT))
    th.start()
    if product_edition <> inSyncParam.CLOUD_EDITION_NAME:
        lic_stats = threading.Thread(target=inSyncCron.update_license_stats)
        lic_stats.start()

    __builtins__.AdminSessionMap = {}
    __builtins__.UserSessionMap = {}

    try:
        if not cloud_arch:
            SyncLog.info("Starting the inSync Web Panel at port %s",
                    inSyncConfig.WEB_PANEL_PORT)
        else:
            SyncLog.info("Starting the inSync Web Panel at port %s",
                    inSyncConfig.CLOUD_CPORTAL_PORT)
        cherrypy.engine.start()
        cherrypy.engine.block()
    except socket.error, fault:
        print "Unable to start inSync Web Panel: ", fault
    except Exception, fault:
        SyncLog.error("Unable to start inSync Web Panel: %s", str(fault))


