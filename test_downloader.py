from subprocess import Popen, PIPE, STDOUT
import threading, sys


#global p
#item = sys.argv[1]
#items = [item]
def kill_current():
	while True:
		c = raw_input('Enter to kill')
		if c == 'e':
			break
		cmd = "ps -ef | grep 'youtube-dl' | awk '{print $2}'| xargs kill "
		p = Popen(cmd, stdout = PIPE, 
	        stderr = STDOUT, shell = True)
		p.wait()


def download(videoid, name):
	cmd = 'youtube-dl ' + 'www.youtube.com/watch?v=' + videoid + ' -f 18/5'
	print 'Downloading', cmd, name 
	p = Popen(cmd, stdout = PIPE, 
    stderr = STDOUT, shell = True)
	print cmd, p
	while True:
		line = p.stdout.readline()
		if not line: break
		print line
	p.wait()


"""
th = threading.Thread(target=kill_current)
th.start()
for item in items:
	print 'processing', item

	cmd = 'youtube-dl ' + 'www.youtube.com/watch?v=' + item 
	global p
	p = Popen(cmd, stdout = PIPE, 
        stderr = STDOUT, shell = True)
	print cmd, p
	while True:
		line = p.stdout.readline()
		if not line: break
		print line
		if line.find('Destination:') > -1:
			fname = line.split(':', 1)[1].strip()
			cmd = 'vlc "' + fname + '.part"'
			print cmd
			vlcp = Popen(cmd, stdout = PIPE, 
			stderr = STDOUT, shell = True)
			vlcp.wait()



th.join()
"""