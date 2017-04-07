from Tkinter import *
from ScrolledText import ScrolledText
import tkMessageBox
import logging
import os
import time
import threading
from multiprocessing import Process
from Queue import Queue
import utility
from monitor_tool import monitor
from monitor_tool import verify_email

log = logging.getLogger(__name__)
FORMAT = '%(asctime)-15s %(message)s'

logging.basicConfig(filename=os.path.join(os.getcwd(),'monitor_tool.log'),
					filemode='w',
					level=logging.DEBUG,
					format=FORMAT)

def email_verify(event):
	hostname = e1.get()
	username = e2.get()
	password = e3.get()
	if len(hostname) == 0:
		tkMessageBox.showinfo('Message', 'please input smtp server')
	elif len(username) == 0:
		tkMessageBox.showinfo('Message', 'please input QQ email user')
	elif len(password) == 0:
		tkMessageBox.showinfo('Message', 'please input QQ email passwd')
	elif verify_email(hostname,username,password):
		tkMessageBox.showinfo('Message', 'email is okay')
	else:
		tkMessageBox.showerror('Message', 'Error: smtp email is not working.\n\
1. check the user/passwd is right\n\
2. check your QQ email setting, make sure POP3/SMTP is supported\n\
3. turn off your symantec firewall, then try again')

def start_monitor():

	from_smtp = e1.get()
	from_user = e2.get()
	from_passwd = e3.get()
	to_user = e4.get()
	ip = e6.get()
	user = e7.get()
	passwd = e8.get()
	command = e9.get()
	log_path = e10.get()
	frequency = float(e11.get())
	if frequency > 15 or frequency < 0: 
		log.error ('Error: The frequency should be between 0 and 15')
		e11.delete(0, END)
		e11.insert(0, '5')
		return
	if c1State.get():
		report = report_time_table[w1State.get()]
		log.info ("Report progress enabled, schedule: every %s sec" % report)
	else:
		report = 0

	m = monitor(ip,user,passwd,command,log_path,from_smtp,from_user,from_passwd,to_user,frequency,report)
	log.info ('%s started' % threading.current_thread().name)
	result = m.run()
	input = [command, result]
	queue.put(input)

def queue_consumer():
	master.after(2000,queue_consumer)
	if not queue.empty(): 
		output = queue.get()
		if output[1] == True:
			tkMessageBox.showinfo('Message', '%s already finish, check the email for result' % output[0])
		else:
			tkMessageBox.showerror('Message', '%s monitor failed: %s' % (output[0], output[1]))

	num = threading.activeCount() - 1 #explude main thread
	for item in threading.enumerate():
		if str(item).find('paramiko') >= 0:
			num = num - 1
	if num:
		string = utility.getmovie("running")
		numThread.set("Total %d monitor job is %s" % (num,string))
	else:
		numThread.set("No monitor job is running ")

def start_process(event):
	log.debug ("current thread total numbers: %d" % threading.activeCount())
	response = tkMessageBox.askokcancel('Message', 'Will start monitor script %s, please click OK to continue, or cancel' % e9.get())
	if response == False:
		return
	th = threading.Thread(target=start_monitor, name="Monitor-%s" % (e9.get()))
	th.setDaemon(True)
	th.start()

def export():
	config = []
	config.append(e1.get())
	config.append(e2.get())
	config.append(e3.get())
	config.append(e4.get())
	config.append(e6.get())
	config.append(e7.get())
	config.append(e8.get())
	config.append(e9.get())
	config.append(e10.get())
	config.append(e11.get())
	if utility.export_config(config) == True:
		tkMessageBox.showinfo('Message', 'export finish')

def load():

	config = utility.load_config()
	if config == None:
		tkMessageBox.showerror('Message', 'Configuration file not existed, please input manually')
	else:
		e1.delete(0, END)
		e1.insert(0, config[0].strip())
		e2.delete(0, END)
		e2.insert(0, config[1].strip())
		e3.delete(0, END)
		e3.insert(0, config[2].strip())
		e4.delete(0, END)
		e4.insert(0, config[3].strip())
		e6.delete(0, END)
		e6.insert(0, config[4].strip())
		e7.delete(0, END)
		e7.insert(0, config[5].strip())
		e8.delete(0, END)
		e8.insert(0, config[6].strip())
		e9.delete(0, END)
		e9.insert(0, config[7].strip())
		e10.delete(0, END)
		e10.insert(0, config[8].strip())
		e11.delete(0, END)
		e11.insert(0, config[9].strip())
		tkMessageBox.showinfo('Message', 'import finish')

def readme():
	popup()

class redirect(object):

	def __init__(self, text):
		self.output = text

	def write(self, string):
		self.output.insert(END, string)
		self.output.see("end")

class popup(Toplevel):

	def __init__(self):
		Toplevel.__init__(self)
		self.geometry('500x400')
		Label(self, text = 'Read Me').pack()
		text= ScrolledText(self, bg="lightgray")
		text['font'] = ('console','10')
		text.insert(END,"			welcome to monitor tool\n\n \
Here is some notes which will help you use monitor tool\n\n\
1. About SMTP setting, please input your smtp user/passwd information, till now only QQ email smtp is varified\
for other smtp emails can not garantee. also you should open POP3/SMTP setting, the passwd is grant access passwd\
you can click verity email button to check the input smtp server is okay or not\n\n\
2. About server information, please input the target server ip/user/passwd and command keyword which will be used\
to search its pid, ps -ef | grep <command keyword>. also input the command log path, which will be used to fetch command\
result,  the frequency(mins), default value is 5 mins, means monitor will ssh to server every 5 mins to fetch pid status\n\n\
3. About the email to address, you can add more then one email address into this enty, like ***@qq.com;***@ericsson.com\n\n\
4. About Enable report progress, if want to know the script progress every certain period(30 mins, 1 hour...), you can select this checkbutton\
   the monitor will fetch script log and send out by email")
		text.see("end")
		text.pack()
		text.config(state=DISABLED)

def callCheckbutton():
	if c1State.get():
		w1.config(state=NORMAL)
		log.info ("Select %s" % c1['text'])
		log.info ("Monitor will send script log(tail -10) by email every 30 minutes")
	else:
		w1.config(state=DISABLED)
		log.info ("Unselect %s" % c1['text'])

master = Tk()
master.title('Script Monitor Tool')

#------ Label Entry defination---------#

# Email from information
Label(master, text="Email From:").grid(row=0, column=0, sticky="w")

Label(master, text="Smtp server:").grid(row=1, column=1, sticky="w")
e1 = Entry(master)
e1.insert(0, 'smtp.qq.com')
e1.grid(row=1, column=2,sticky="ew")

Label(master, text="User:").grid(row=2, column=1, sticky="w")
e2 = Entry(master)
e2.grid(row=2, column=2,sticky="ew")

Label(master, text="Passwd:").grid(row=3, column=1, sticky="w")
e3 = Entry(master)
e3['show'] = '*'
e3.grid(row=3, column=2,sticky="ew")


# Email to information
Label(master, text="Email To:").grid(row=5, column=0, sticky="w")
e4 = Entry(master)
e4.grid(row=5, column=2, sticky="ew")
#e5 = Entry(master)
#e5.grid(row=6, column=2)
Label(master, text="Example: ***@qq.com;***@ericsson.com").grid(row=6, column=1, columnspan=2, sticky="w")

numThread = StringVar()
Label(master, textvariable=numThread,fg="red").grid(row=7, column=0, columnspan=3, sticky="w")


# Monitor Server information
Label(master, text="Server Information:").grid(row=0, column=3, sticky="w")

Label(master, text="IP address:").grid(row=1, column=4, sticky="w")
e6 = Entry(master)
e6.grid(row=1, column=5,sticky="ew")

Label(master, text="User:").grid(row=2, column=4, sticky="w")
e7 = Entry(master)
e7.grid(row=2, column=5,sticky="ew")

Label(master, text="Passwd:").grid(row=3, column=4, sticky="w")
e8 = Entry(master)
e8['show'] = '*'
e8.grid(row=3, column=5,sticky="ew")

Label(master, text="Command:").grid(row=4, column=4, sticky="w")
e9 = Entry(master)
e9.grid(row=4, column=5,sticky="ew")

Label(master, text="Log path:").grid(row=5, column=4, sticky="w")
e10 = Entry(master)
e10.grid(row=5, column=5,sticky="ew")

Label(master, text="Frequency\n(minutes):").grid(row=6, column=4, rowspan=1, sticky="w")
e11 = Entry(master)
e11.insert(0, '5')
e11.grid(row=6, column=5, sticky="w")
e11['width'] = 3

#------- Buttion defination ----------#
# Verity email address
b1 = Button(master,text="Verify email")
b1.grid(row=4, column=1)
b1.bind("<ButtonRelease>",email_verify)

# Start button
b2 = Button(master, text="Start monitor")
b2['background'] = 'green'
b2['width'] = '15'
b2.grid(row=7, column=6)
b2.bind("<ButtonRelease>",start_process)

#------- Checkbutton defination ----------#
c1State = IntVar()
c1 = Checkbutton(master, variable=c1State, text = "Enable report progress", command=callCheckbutton)
c1.grid(row=1, column=6)

report_time_table = {
"2 hours" : 120 * 60,
"1.5 hours" : 90 * 60,
"1 hour" : 60 * 60,
"30 mins" : 30 * 60
}

w1State = StringVar()
w1State.set("30 mins") # default value
w1 = apply(OptionMenu, (master, w1State) + tuple(report_time_table.keys()))
w1.grid(row=2, column=6)
w1.config(state=DISABLED)

#--------Text scrollar defination--------------#
s1= ScrolledText(master)
s1['font'] = ('console','10')
s1.grid(row=8,columnspan=8,sticky="ew")
redir = redirect(s1)
sys.stdout = redir
sys.stderr = redir
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)
#log.addHandler(console)
#------- Menu defination -------------#

# parent menu
menubar = Menu()
# child menu 
fmenu = Menu()
fmenu.add_command(label = 'Export config', command = export)
fmenu.add_command(label = 'Import config', command = load)
fmenu.add_command(label = 'Exit', command = master.quit)

hmenu = Menu()
hmenu.add_command(label = 'Reame', command = readme)

# add menu tree
menubar.add_cascade(label = 'File', menu = fmenu)
menubar.add_cascade(label = 'Help', menu = hmenu)

# add menu to wget
master['menu'] = menubar

queue = Queue()
master.after(2000,queue_consumer)

master.columnconfigure(2, weight=1)
master.columnconfigure(5, weight=1) 

master.mainloop()
