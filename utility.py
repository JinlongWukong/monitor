import os
import logging
import re

log = logging.getLogger(__name__)

def export_config(config):
	file=os.path.join(os.getcwd(),'monitor_tool_config')
	log.info("Export configuration into file : %s" % file)
	try:
		fo = open(file,"w")
		fo.truncate()
		for i in config:
			fo.write(i)
			fo.write("\n")
		fo.close
		log.info("Export configuration successfully")
		return True
	except Exception, e:
		log.error ("%s" % str(e))

def load_config():
	file=os.path.join(os.getcwd(),'monitor_tool_config')
	log.info("Load configuration from file %s" % file)
	try:
		fo = open(file,"r")
		config = fo.readlines()
		fo.close
		log.info("Load configuration successfully")
		return config
	except Exception, e:
		log.error ("%s" % str(e))

def time2sec(sTime):

	if len(sTime.split(':')) == 2:
		sTime = '00:' + sTime
	p = "^(0[0-9]|1[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$"
	cp = re.compile(p)
	try:
		mTime = cp.match(sTime)
	except TypeError:
		return "[InModuleError]:time2itv(sTime) invalid argument type"

	if mTime:
		t = map(int,mTime.group(1,2,3))
		return 3600*t[0]+60*t[1]+t[2]
	else:
		return "[InModuleError]:time2itv(sTime) invalid argument value"

def parseTime(stdout):

	if len(stdout.rsplit()) == 2:
		x = stdout.rsplit()
		pid_start_time = x[0]
		y = x[1]
		if len(y.split('-')) == 2:
			z = y.split('-')
			pid_run_time_str = "%s days %s " % (z[0], z[1])
			sec = time2sec(z[1])
			pid_run_time_sec = 3600 * 24 * int(z[0]) + int(sec)
		elif len(y.split('-')) == 1:
			z = y.split('-')
			pid_run_time_str = "%s" % (z[0])
			pid_run_time_sec = time2sec(z[0])
		else:
			return None
		return (pid_start_time, pid_run_time_str, pid_run_time_sec)
	else:
		return None

flag = 1
def getmovie(string):
	global flag
	if flag:
		string = string + '...'
		flag = 0
	else:
		flag = 1

	return string



