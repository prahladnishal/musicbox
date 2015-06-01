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

if len(sys.argv) <> 2:
    print 'Usage: python stream_server.py <songs_directory>'

songs_cwd = sys.argv[1]
webcwd = os.getcwd() 
print 'Hosting directory', songs_cwd, webcwd
os.chdir(songs_cwd)
loader = TemplateLoader(webcwd, auto_reload=True, max_cache_size=200)

def render(context_dict, base='base.html'):
    ctx = Context(**context_dict)
    # Load the main template (which will then include all other templates
    # provided in context_dict['page_list']) ...
    tmpl = loader.load(base)
    # Cook and serve ...
    stream = tmpl.generate(ctx)
    cherrypy.request.headers['Accept-Charset'] = 'utf-8;q=0.7,*;q=0.7'
    return stream.render('html', encoding='utf-8')

def ConnectDB():
    conn = sqlobject.connectionForURI('sqlite:file.db')
    conn.debug = True
    sqlobject.sqlhub.processConnection = conn
    FileData.createTable(ifNotExists = True)

class FileData(sqlobject.SQLObject):
    name = sqlobject.UnicodeCol()
    nplayed = sqlobject.IntCol(default=0)
    last_played = sqlobject.IntCol(default=0)
    rating = sqlobject.IntCol(default=0)

    def as_dict(self):
        return {'name' : self.name, 'nplayed' : self.nplayed, 'last_played' : self.last_played, 'rating' : self.rating}

class DBManager():
    def get_files(self):
        res = list(FileData.select())
        #print res
        results = []
        for r in res:
            results.append(r.as_dict())
        return results

    def update_play(self, fname):
        if FileData.selectBy(name=fname).count() > 0:
            row = FileData.selectBy(name=fname).getOne()
            row.nplayed = row.nplayed + 1
            row.last_played = int(time.time())
        else:
            FileData(name=fname, nplayed=1, last_played=int(time.time()))

    def delete(self, fname):
        rc = list(FileData.selectBy(name=fname))
        if rc:
            rc[0].destroySelf()

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
        dirpath = songs_cwd
        entries = ((os.path.join(dirpath, fn), fn) for fn in os.listdir(dirpath))
        entries = ((os.stat(path), path, fname) for path, fname in entries)

        # leave only regular files, insert creation date
        entries = [(stat[ST_CTIME], path, fname)
            for stat, path, fname in entries if S_ISREG(stat[ST_MODE])]
        entries.sort()
        entries.reverse()
        entries = [(time.ctime(x[0]), x[1], x[2]) for x in entries if self.check_extn(x[1])]
        return json.dumps(entries)

    @cherrypy.expose
    def list_played(self, *args, **kwargs):
        key = kwargs['key']
        res = DB.get_files()
        res.sort(key=lambda x: x[key], reverse=True)
        return json.dumps(res)

    @cherrypy.expose
    def update_play(self, **kwargs):
        fname = kwargs['fname']
        DB.update_play(fname)


    def check_extn(self, fname):
        for extn in [".py", ".js", ".html", "db", "-del"]:
            if fname.find(extn) > -1:
                return False
        return True

    @cherrypy.expose
    def download(self):
        return render({}, base='download-base.html')

    @cherrypy.expose
    def delete_file(self, *args, **kwargs):
        fname = kwargs['fname']
        name = fname
        fname = os.path.join(songs_cwd, fname)
        print 'delete-file', fname
        try:
            os.rename(fname, fname+'-del')
        except Exception, fault:
            print str(fault)
        DB.delete(name) 



ConnectDB()
DB = DBManager()
config = {
    'global' : {
        'server.socket_host' : '0.0.0.0',
        'server.socket_port' : 8080
    },
    '/' : {
        'tools.staticdir.root'   : webcwd,
        'tools.staticfile.root'  : webcwd,
    },
    '/js' : {
        'tools.staticdir.on' : True,
        'tools.staticdir.dir' : 'js'
    },
    '/video' : {
        'tools.staticdir.on' : True,
        'tools.staticdir.dir' : songs_cwd
    }
}
cherrypy.quickstart(HelloWorld(), '/', config)