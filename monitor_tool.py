#!/usr/bin/python
"""
	This module is used to monitor remote script 

"""
import os
import logging
import datetime
import commands
import time
import paramiko
import sys
import threading
import smtplib
from smtplib import SMTP_SSL
from email.header import Header
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import utility

log = logging.getLogger(__name__)


class monitor:

	def __init__(self, ip, user, passwd, cmd, logPath, from_host, from_user, from_password, to_user, frequency, report):
		self.hostip = ip
		self.username = user
		self.password = passwd
		self.command = cmd
		self.log_path = logPath
		self.mailInfo = {
			"from":from_user,
			"to":to_user,
			"hostname":from_host,
			"username":from_user,
			"password":from_password,
			"mailsubject":"monitor tool notification",
			"mailtext":"script finished",
			"mailencoding":"utf-8"
		}
		self.fre = float(frequency)
		self.reportime_fre = float(report)
		self.start = False
		self.cmd = 'ps -ef | grep %s | grep -v grep | grep -v "sh -c"' % self.command
		#self.log_cmd = "tail -15 %s" % self.log_path
		#self.log_cmd = "echo script log last update at :`ls -l %s | awk '{print $8}'` ; tail -50 %s" % (self.log_path,self.log_path)
		self.log_cmd = "echo For your reference :`ls -l %s | awk '{print $8}'` ; tail -30 %s" % (self.log_path,self.log_path)
		log.debug ('mail information: %s ' % self.mailInfo)
		log.debug ('monitor command: %s ' % self.cmd)
		log.debug ('get command log: %s ' % self.log_cmd)

	def send_mail(self, message):

		if len(message) != 0:
			self.mailInfo["mailtext"] = message
		msg = MIMEMultipart()
		msg["Subject"] = Header(self.mailInfo["mailsubject"],self.mailInfo["mailencoding"])
		msg["from"] = self.mailInfo["from"]
		msg["to"] = self.mailInfo["to"]

		text = MIMEText(self.mailInfo["mailtext"],"plain",self.mailInfo["mailencoding"])
		msg.attach(text)

		part = MIMEBase('application', "octet-stream")
		part.set_payload(open("C:\\Work\\Fun\\monitor\\version_8_20161218\\foo.xlsx", "rb").read())
		encoders.encode_base64(part)
		part.add_header('Content-Disposition', 'attachment; filename="WorkBook3.xlsx"')
		msg.attach(part)

		log.info ("print msg with attachment: %s" % msg.as_string)
		from_email = self.mailInfo["from"]
		to_mail = self.mailInfo["to"].split(';')

		smtp = SMTP_SSL(self.mailInfo["hostname"])
		smtp.set_debuglevel(1)
		smtp.ehlo(self.mailInfo["hostname"])
		smtp.login(self.mailInfo["username"], self.mailInfo["password"])
		smtp.sendmail(from_email, to_mail, msg.as_string())
		smtp.quit()

	def report_progress(self, ssh, start_time, run_time):

		log.info("Time up, ready send script progress log")
		try:
			stdin, stdout, stderr = ssh.exec_command(self.log_cmd)
			standard_err = stderr.readlines()
			if len(standard_err) != 0:
				log.error("get script log error:")
				for err in standard_err:
					log.error ("%s" % err)
			message = ''.join(stdout.readlines())
			if len(message) == 0:
				message = "log empty"
			message = "Report script progress: script started at %s, already running %s\n" % (start_time, run_time) + message
			log.debug ("get script log: %s" % message)
			self.send_mail(message)
			log.info("%s : send sript progress log mail successfully, \nmonitor continue..." % threading.current_thread().name)
			return True
		except Exception, e:
			log.error ("%s : Throw exception: %s" % (threading.current_thread().name, str(e)))
			log.error ("send script progress log failed")
			return False

	def run(self):

		log.info ("%s : Try to ping %s" % (threading.current_thread().name, self.hostip))
		res = os.system('ping %s' % self.hostip)
		if res != 0:
			errMsg = "Error : %s is not pingnable" % self.hostip
			log.error("%s" % errMsg)
			return errMsg

		abort = False
		retry = 0
		while True:
			try:
				start_clock = time.clock()
				log.debug("%s :Ready to setup ssh connect to %s" % (threading.current_thread().name, self.hostip))
				paramiko.util.log_to_file('paramiko.log')  
				ssh = paramiko.SSHClient()
				ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				ssh.connect(self.hostip, 22, self.username, self.password, timeout=5)
				log.debug("Setup ssh connect successfully")
				log.debug("ready to execute ssh cmd %s" % self.cmd)
				stdin, stdout, stderr = ssh.exec_command(self.cmd)
				stdin.write("Y")
				standard_out = stdout.readlines()
				standard_err = stderr.readlines()
				log.info ("%s :err len: %d" % (threading.current_thread().name, len(standard_err)))
				log.info ("%s :std len: %d" % (threading.current_thread().name, len(standard_out)))

				if self.start == False:
					if len(standard_out) != 1:
						errMsg = "Error: Given command %s seems not suitable, no pid or more then one pid was found" % self.command
						ssh.close()
						time.sleep(2)
						log.error("%s" % errMsg)
						return errMsg
					else:
						pid = standard_out[0].strip().split()[1]
						log.info ("fetch pid: %s" % pid)
						if not pid.isdigit():
							ssh.close()
							time.sleep(2)
							errMsg = "fetch pid is not digit,command run error"
							log.error("%s" % errMsg)
							return errMsg
						self.cmd = "ps -o stime,etime -p %s | grep -v TIME" % pid
						stdin, stdout, stderr = ssh.exec_command(self.cmd)
						standard_out = stdout.readlines()
						standard_err = stderr.readlines()
						(pid_start_time, pid_run_time_str, pid_run_time_sec) = utility.parseTime(standard_out[0])
						self.reportime = pid_run_time_sec
						log.info ("script started at %s , already running %s" % (pid_start_time, pid_run_time_str))
						self.start = True
				else:
					if (len(standard_out) == 0) or (abort == True):
						log.info("%s finished on remote host server" % self.command)
						log.info("ready get script log")
						stdin, stdout, stderr = ssh.exec_command(self.log_cmd)
						standard_err = stderr.readlines()
						if len(standard_err) != 0:
							log.error("get script log error:")
							for err in standard_err:
								log.error ("%s" % err)
						message = ''.join(stdout.readlines())
						log.debug ("get script log: %s" % message)
						try:
							self.send_mail(message)
						except Exception, e:
							log.error ("%s : Throw exception: %s" % (threading.current_thread().name, str(e)))
							ssh.close()
							time.sleep(2)
							retry = retry + 1
							if retry >= 3:
								log.error ("send mail retry 3 times failed, monitor quit")
								return str(e)
							else:
								log.error ("send mail failed, will retry %s time" % retry)
								time.sleep(5)
								continue
						log.info("%s : send mail successfully" % threading.current_thread().name)
						ssh.close()
						time.sleep(2)
						return True
					elif len(standard_err) != 0:
						log.error("run %s error" % self.cmd)
						for err in standard_err:
							log.error ("%s" % err)
					else:
						log.info ("%s :script %s still running..." % (threading.current_thread().name, self.command))
						for out in standard_out:
							log.debug ("%s" % out)
						(pid_start_time, pid_run_time_str, pid_run_time_sec) = utility.parseTime(standard_out[0])
						log.info ("%s :script started at %s , already running %s" % (threading.current_thread().name, pid_start_time, pid_run_time_str))
						if pid_run_time_sec <= 60 * self.fre:
							log.info ("script %s already finished, found a new script started with same pid, abort monitor tool" % self.command)
							abort = True
							continue
						if self.reportime_fre != 0:
							countDown = pid_run_time_sec - self.reportime
							log.debug ("pid already run time(sec):%s, last time send mail time:%s, countdown: %s" % (pid_run_time_sec,self.reportime,countDown))
							if countDown >= self.reportime_fre:
								if self.report_progress(ssh,pid_start_time,pid_run_time_str) or retry >= 3:
									self.reportime = pid_run_time_sec
									retry = 0
								else:
									retry = retry + 1
									log.error ("send mail failed, will retry %s time" % retry)
									time.sleep(5)
									continue
				ssh.close()
			except Exception, e:
				log.error ("%s : Throw exception: %s" % (threading.current_thread().name, str(e)))
				ssh.close()
				return str(e)

			stop_clock = time.clock()
			sleep_time = (60 * self.fre) - int(stop_clock - start_clock)
			if sleep_time < 0:
				sleep_time = 0
			time.sleep(sleep_time)

def verify_email(hostname,username,password):
	try:
		smtp = SMTP_SSL(hostname)
		smtp.set_debuglevel(1)
		smtp.ehlo(hostname)
		smtp.login(username,password)
		smtp.quit()
		return True
	except Exception, e:
		log.error ("Throw exception: %s" % str(e))
		return False

if __name__ == '__main__':

	FORMAT = '%(asctime)-15s %(message)s'
	logging.basicConfig(filename=os.path.join(os.getcwd(),'monitor_tool.log'),
						filemode='w',
						level=logging.DEBUG,
						format=FORMAT)
	console = logging.StreamHandler()
	console.setLevel(logging.INFO)
	log.addHandler(console)

	hostname = raw_input("Please input smtp server: ")
	username = raw_input("Please input smtp user: ")
	password = raw_input("Please input smtp passwd: ")
	log.info ("Start to verify smtp email...")
	if not verify_email(hostname, username, password):
		log.error ("\nsmtp email verify failed. exit...")
		quit = raw_input("\nPlease enter to exit..")
		sys.exit(1)
	log.info ("\nsmtp server is okay. continue to input monitor server information: ")
	time.sleep(1)
	# smtp server verify passed, input monitor server information
	ip = raw_input("Please input host ip: ")
	user = raw_input("Please input login user name: ")
	passwd = raw_input("Please input login user password: ")
	cmd = raw_input("Please input monitor command: ")
	logPath = raw_input("Please input full path of the command log: ")
	frequency = raw_input("Please input the monitor frequency(minutes): ")

	#monitor server infor input passed, input mail to address
	mail_to = raw_input("Please input the email address which you want send to: ")
	log.info ("Now ready to start monitor ...")
	time.sleep(1)

	m = monitor(ip, user, passwd, cmd, logPath, hostname, username, password, mail_to, frequency, 0)
	result = m.run()
	if result == True:
		log.info ("monitor finish successfully.")
		sys.exit(0)
	else:
		raw_input("\nPlease enter to exit..")
		sys.exit(1)
