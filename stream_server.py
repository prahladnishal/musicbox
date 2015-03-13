from stat import S_ISREG, ST_CTIME, ST_MODE
import os, sys, time, glob
import json
import cherrypy
import os
import time
import sqlobject
import genshi
from genshi.template import TemplateLoader
from genshi.template import Context
import test_downloader

cwd = os.getcwd()
loader = TemplateLoader(cwd, auto_reload=True, max_cache_size=200)

def render(context_dict, base='base.html'):
    ctx = Context(**context_dict)
    # Load the main template (which will then include all other templates
    # provided in context_dict['page_list']) ...
    tmpl = loader.load(base)
    # Cook and serve ...
    stream = tmpl.generate(ctx)
    cherrypy.request.headers['Accept-Charset'] = 'utf-8;q=0.7,*;q=0.7'
    return stream.render('html', encoding='utf-8')



class URL(sqlobject.SQLObject):
    url = sqlobject.UnicodeCol()
    done = sqlobject.BoolCol()

    def asdict(self):
        return {'id': self.id, 'url': self.url, 'done': self.done}

class DBManager():
    def add_url(self, url):
        url = URL(url=url, done=False)
        return url.asdict()


class HelloWorld(object):
    @cherrypy.expose
    def index(self):
        return render({})

    @cherrypy.expose
    def play(self, **kwargs):
        videoid = kwargs['id']
        name = kwargs['title']
        test_downloader.download(videoid, name)

    @cherrypy.expose
    def list_files(self, *args, **kwargs):
        dirpath = cwd
        entries = ((os.path.join(dirpath, fn), fn) for fn in os.listdir(dirpath))
        entries = ((os.stat(path), path, fname) for path, fname in entries)

        # leave only regular files, insert creation date
        entries = [(stat[ST_CTIME], path, fname)
            for stat, path, fname in entries if S_ISREG(stat[ST_MODE])]
        entries.sort()
        entries.reverse()
        entries = [(time.ctime(x[0]), x[1], x[2]) for x in entries if self.check_extn(x[1])]
        return json.dumps(entries)

    def check_extn(self, fname):
        for extn in [".py", ".js", ".html"]:
            if fname.find(extn) > -1:
                return False
        return True
    
config = {
    'global' : {
        'server.socket_host' : '0.0.0.0',
        'server.socket_port' : 8080
    },
    '/' : {
        'tools.staticdir.root'   : cwd,
        'tools.staticfile.root'  : cwd,
    },
    '/js' : {
        'tools.staticdir.on' : True,
        'tools.staticdir.dir' : 'js'
    },
    '/video' : {
        'tools.staticdir.on' : True,
        'tools.staticdir.dir' : cwd
    }
}
cherrypy.quickstart(HelloWorld(), '/', config)
