# Verlihub Blacklist 1.0
# Written by RoLex, 2010-2014
# Special thanks to Frog
# Changelog:
# 0.0 - Not available
# 1.0 - Added configuration find_maxres to limit number of results on find action
# 1.0 - Added country codes of addresses in waiting feed list

import vh, re, urllib2, gzip, StringIO, time, os, socket, struct

bl_conf = {
	"file_except": ["blacklist_except.txt", "str", 1, 255],
	"nick_feed": ["", "str", 0, 255],
	"class_feed": [5, "int", 0, 11],
	"class_conf": [10, "int", 3, 11],
	"time_feed": [60, "int", 0, 1440],
	"notify_update": [1, "int", 0, 1],
	"find_maxres": [1000, "int", 1, 100000]
}

bl_stats = {
	"connect": 0l,
	"block": 0l,
	"except": 0l,
	"tick": time.time (),
	"version": 1.0
}

bl_update = [
	# ["http://list.iblocklist.com/?list=ijfqtofzixtwayqovmxn&fileformat=p2p&archiveformat=gz", "gzip-p2p", "Primary threat", 0, 0],
	# ["http://list.iblocklist.com/?list=bt_proxy&fileformat=p2p&archiveformat=gz", "gzip-p2p", "Proxy", 0, 0],
	# ["http://torstatus.blutmagie.de/ip_list_exit.php/tor_ip_list_exit.csv", "single", "Tor exit", 60, 0],
	# ["http://torstatus.blutmagie.de/ip_list_all.php/tor_ip_list_all.csv", "single", "Tor server", 60, 0]
]

bl_list = [[] for i in xrange (256)]
bl_except = []
bl_feed = []

def bl_startup ():
	global bl_conf, bl_update, bl_stats

	vh.SQL (
		"create table if not exists `py_bl_conf` ("\
			"`name` varchar(255) collate utf8_general_ci not null primary key,"\
			"`value` varchar(255) collate utf8_general_ci not null"\
		") engine = myisam default character set utf8 collate utf8_general_ci"
	)

	vh.SQL (
		"create table if not exists `py_bl_list` ("\
			"`list` varchar(255) collate utf8_general_ci not null primary key,"\
			"`type` varchar(25) collate utf8_general_ci not null,"\
			"`title` varchar(255) collate utf8_general_ci not null,"\
			"`update` smallint(4) collate utf8_general_ci not null default 0"\
		") engine = myisam default character set utf8 collate utf8_general_ci"
	)

	for name, value in bl_conf.iteritems ():
		vh.SQL ("insert ignore into `py_bl_conf` (`name`, `value`) values ('%s', '%s')" % (bl_repsql (name), bl_repsql (str (value [0]))))

	sql, rows = vh.SQL ("select * from `py_bl_conf`", 100)

	if sql and rows:
		for conf in rows:
			bl_setconf (conf [0], conf [1], False)

	sql, rows = vh.SQL ("select * from `py_bl_list`", 100)

	if sql and rows:
		for list in rows:
			bl_update.append ([list [0], list [1], list [2], int (list [3]), 0])

	out = "Blacklist %s startup:\r\n\r\n" % bl_stats ["version"]

	for id, item in enumerate (bl_update):
		out += " [*] %s: %s\r\n" % (item [2], bl_import (item [0], item [1], item [2], 0))

		if item [3]:
			bl_update [id][4] = time.time ()

	out += " [*] %s: %s\r\n" % ("Exception", bl_import (bl_conf ["file_except"][0], "p2p", "Exception", 0, True))
	bl_notify (out)

def bl_import (list, type, title, update, exlist = False): # gzip-p2p, gzip-range, gzip-single, p2p, range, single
	global bl_list, bl_except
	file = None

	if "://" in list:
		try:
			file = urllib2.urlopen (list, None, 5)
		except urllib2.HTTPError:
			return "Failed due HTTP error"
		except urllib2.URLError:
			return "Failed due URL error"
		except:
			return "Failed due unknown error"
	else:
		try:
			file = open (list, "r")
		except:
			pass

	if file:
		find = None

		if "p2p" in type:
			find = "(.*)\:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
		elif "range" in type:
			find = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
		elif "single" in type:
			find = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

		if find:
			try:
				find = re.compile (r"^" + find + "$")
			except:
				file.close ()
				return "Failed to compile pattern"

			if "gzip" in type:
				data = StringIO.StringIO (file.read ())
				file.close ()

				try:
					file = gzip.GzipFile (fileobj = data)
					file.read (1)
				except:
					return "File is not compressed with GZIP"

			mylist = []

			for line in file:
				part = find.findall (line)

				if part:
					mytitle = None
					myloaddr = None
					myhiaddr = None

					if "p2p" in type:
						mytitle = part [0][0] or title
						myloaddr = part [0][1]
						myhiaddr = part [0][2]
					elif "range" in type:
						mytitle = title
						myloaddr = part [0][0]
						myhiaddr = part [0][1]
					elif "single" in type:
						mytitle = title
						myloaddr = part [0]
						myhiaddr = part [0]

					if mytitle and myloaddr and myhiaddr and bl_validaddr (myloaddr) and bl_validaddr (myhiaddr):
						mylist.append ([bl_addrtoint (myloaddr), bl_addrtoint (myhiaddr), mytitle])

			file.close ()

			if exlist:
				for item in mylist:
					bl_except.append (item)
			else:
				for item in mylist:
					for i in xrange (item [0] >> 24, (item [1] >> 24) + 1):
						if not update or (update and not item in bl_list [i]):
							bl_list [i].append (item)

			return "%s items loaded" % len (mylist)
		else:
			file.close ()
			return "Unknown list type"
	else:
		return "Failed to open file"

def bl_exceptsave ():
	global bl_conf, bl_except
	file = None

	try:
		file = open (bl_conf ["file_except"][0], "w+")
	except:
		pass

	if file:
		for item in bl_except:
			file.write ("%s:%s-%s\n" % (item [2], bl_addrtostr (item [0]), bl_addrtostr (item [1])))

		file.close ()
		return "%s items saved" % len (bl_except)
	else:
		return "Failed to open file"

def bl_getconf (name):
	global bl_conf

	if name in bl_conf:
		return bl_conf [name][0]
	else:
		return None

def bl_setconf (name, value, update = True):
	global bl_conf

	if name in bl_conf:
		old = bl_conf [name][0]

		if bl_conf [name][1] == "int":
			try:
				new = int (value)

				if new < bl_conf [name][2]:
					return "Value too low"
				elif new > bl_conf [name][3]:
					return "Value too high"
				else:
					bl_conf [name][0] = new
			except:
				return "Value is not a number"
		else:
			if len (value) < bl_conf [name][2]:
				return "Value too short"
			elif len (value) > bl_conf [name][3]:
				return "Value too long"
			else:
				bl_conf [name][0] = value

		if update:
			vh.SQL ("update `py_bl_conf` set `value` = '%s' where `name` = '%s'" % (bl_repsql (str (value)), bl_repsql (name)))

			if name == "file_except":
				try:
					os.rename (old, bl_conf [name][0])
				except:
					pass

		return "%s -> %s" % (old, bl_conf [name][0])
	else:
		return "Item not found"

def bl_addrtoint (addr):
	return struct.unpack ("!L", socket.inet_aton (addr)) [0]

def bl_addrtostr (addr):
	return socket.inet_ntoa (struct.pack ('!L', addr))

def bl_validaddr (addr):
	for part in addr.split ("."):
		if int (part) < 0 or int (part) > 255:
			return 0

	return 1

def bl_repsql (data):
	return data.replace (chr (92), chr (92) + chr (92)).replace (chr (34), chr (92) + chr (34)).replace (chr (39), chr (92) + chr (39))

def bl_repnmdc (data, out = False):
	if out:
		return data.replace ("&#124;", "|").replace ("&#36;", "$")
	else:
		return data.replace ("|", "&#124;").replace ("$", "&#36;")

def bl_reply (user, data):
	vh.SendDataToUser ("<%s> %s|" % (vh.GetConfig ("config", "hub_security"), bl_repnmdc (data)), user)

def bl_notify (data):
	global bl_conf
	bot = vh.GetConfig ("config", "opchat_name")

	if len (bl_conf ["nick_feed"][0]) > 0:
		vh.SendDataToUser ("$To: %s From: %s $<%s> %s|" % (bl_conf ["nick_feed"][0], bot, bot, bl_repnmdc (data)), bl_conf ["nick_feed"][0])
	else:
		vh.SendPMToAll (bl_repnmdc (data), bot, bl_conf ["class_feed"][0], 10)

def OnNewConn (addr):
	global bl_conf, bl_stats, bl_list, bl_except, bl_feed
	bl_stats ["connect"] += 1
	intaddr = bl_addrtoint (addr)

	for item in bl_list [intaddr >> 24]:
		if intaddr >= item [0] and intaddr <= item [1]:
			code = vh.GetIPCC (addr)

			for eitem in bl_except:
				if intaddr >= eitem [0] and intaddr <= eitem [1]:
					bl_notify ("Blacklisted connection exception from %s.%s: %s | %s" % (addr, code, item [2], eitem [2]))
					bl_stats ["except"] += 1
					return 1

			for id, feed in enumerate (bl_feed):
				if feed [0] == addr:
					if time.time () - feed [1] >= bl_conf ["time_feed"][0] * 60:
						bl_notify ("Blocking blacklisted connection from %s.%s: %s" % (addr, code, item [2]))
						bl_feed [id][1] = time.time ()

					bl_stats ["block"] += 1
					return 0

			bl_notify ("Blocking blacklisted connection from %s.%s: %s" % (addr, code, item [2]))
			bl_feed.append ([addr, time.time ()])
			bl_stats ["block"] += 1
			return 0

	return 1

def OnOperatorCommand (user, data):
	global bl_conf, bl_stats, bl_list, bl_except, bl_update, bl_feed

	if data [1:3] == "bl":
		if vh.GetUserClass (user) < bl_conf ["class_conf"][0]:
			bl_reply (user, "You don't have access to this command.")
			return 0

		if data [4:9] == "stats":
			count = 0

			for i in range (len (bl_list)):
				for item in bl_list [i]:
					count += 1

			out = "Blacklist statistics:\r\n"
			out += "\r\n [*] Version: %s" % bl_stats ["version"]
			out += "\r\n [*] Loaded lists: %s" % len (bl_update)
			out += "\r\n [*] Blacklisted items: %s" % count
			out += "\r\n [*] Excepted items: %s" % len (bl_except)
			out += "\r\n [*] Blocked connections: %s" % bl_stats ["block"]
			out += "\r\n [*] Excepted connections: %s" % bl_stats ["except"]
			out += "\r\n [*] Total connections: %s\r\n" % bl_stats ["connect"]
			bl_reply (user, out)
			return 0

		if data [4:8] == "find":
			if not data [9:]:
				bl_reply (user, "Missing command parameters: find <item>")
				return 0

			pars = re.findall (r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", data [9:])
			out = ""

			if pars and pars [0] and bl_validaddr (data [9:]):
				intaddr = bl_addrtoint (data [9:])
				rmax = 0

				for item in bl_list [intaddr >> 24]:
					if intaddr >= item [0] and intaddr <= item [1]:
						out += " %s - %s : %s\r\n" % (bl_addrtostr (item [0]), bl_addrtostr (item [1]), item [2])
						rmax = rmax + 1

						if rmax >= bl_conf ["find_maxres"][0]:
							break

				if out:
					bl_reply (user, "Results for IP: %s\r\n\r\n%s" % (data [9:], out))
				else:
					bl_reply (user, "No results for IP: %s" % data [9:])
			else:
				lowdata = data [9:].lower ()
				rmax = 0

				for i in range (len (bl_list)):
					for item in bl_list [i]:
						if lowdata in item [2].lower ():
							out += " %s - %s : %s\r\n" % (bl_addrtostr (item [0]), bl_addrtostr (item [1]), item [2])
							rmax = rmax + 1

							if rmax >= bl_conf ["find_maxres"][0]:
								break

					if rmax >= bl_conf ["find_maxres"][0]:
						break

				if out:
					bl_reply (user, "Results for title: %s\r\n\r\n%s" % (data [9:], out))
				else:
					bl_reply (user, "No results for title: %s" % data [9:])

			return 0

		if data [4:11] == "listall":
			if not bl_update:
				out = "Blacklist list is empty."
			else:
				out = "Blacklist list:\r\n"

				for id, item in enumerate (bl_update):
					out += "\r\n [*] ID: %s" % id
					out += "\r\n [*] List: %s" % item [0]
					out += "\r\n [*] Type: %s" % item [1]
					out += "\r\n [*] Title: %s" % item [2]
					out += "\r\n [*] Update: %s\r\n" % ("On load" if not item [3] else "%s minute | %s" % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [4] + (item [3] * 60)))) if item [3] == 1 else "%s minutes | %s" % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [4] + (item [3] * 60)))))

			bl_reply (user, out)
			return 0

		if data [4:11] == "listadd":
			pars = re.findall (r"^(\S+)[ ]+(\S+)[ ]+\"(.+)\"[ ]*(\d+)?$", data [12:])

			if not pars or not pars [0][0] or not pars [0][1] or not pars [0][2]:
				bl_reply (user, "Missing command parameters: listadd <list> <type> <\"title\"> [update]")
				return 0

			types = [
				"gzip-p2p",
				"gzip-range",
				"gzip-single",
				"p2p",
				"range",
				"single"
			]

			if not pars [0][1] in types:
				bl_reply (user, "Type must be one of: %s" % ", ".join (types))
				return 0

			try:
				update = int (pars [0][3])
			except:
				update = 0

			if update < 0 or update > 10080:
				bl_reply (user, "Update must be in range: %s - %s" % (0, 10080))
				return 0

			for id, item in enumerate (bl_update):
				if item [0].lower () == pars [0][0].lower ():
					out = "Item already in list:\r\n"
					out += "\r\n [*] ID: %s" % id
					out += "\r\n [*] List: %s" % item [0]
					out += "\r\n [*] Type: %s" % item [1]
					out += "\r\n [*] Title: %s" % item [2]
					out += "\r\n [*] Update: %s\r\n" % ("On load" if not item [3] else "%s minute | %s" % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [4] + (item [3] * 60)))) if item [3] == 1 else "%s minutes | %s" % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [4] + (item [3] * 60)))))
					bl_reply (user, out)
					return 0

			bl_update.append ([pars [0][0], pars [0][1], pars [0][2], update, time.time () if update else 0])
			vh.SQL ("insert into `py_bl_list` (`list`, `type`, `title`, `update`) values ('%s', '%s', '%s', '%s')" % (bl_repsql (pars [0][0]), bl_repsql (pars [0][1]), bl_repsql (pars [0][2]), bl_repsql (str (update))))
			out = "Item added to list:\r\n"
			out += "\r\n [*] ID: %s" % (len (bl_update) - 1)
			out += "\r\n [*] List: %s" % pars [0][0]
			out += "\r\n [*] Type: %s" % pars [0][1]
			out += "\r\n [*] Title: %s" % pars [0][2]
			out += "\r\n [*] Update: %s" % ("On load" if not update else "%s minute | %s" % (update, time.strftime ("%d/%m %H:%M", time.gmtime (time.time () + (update * 60)))) if update == 1 else "%s minutes | %s" % (update, time.strftime ("%d/%m %H:%M", time.gmtime (time.time () + (update * 60)))))
			out += "\r\n [*] Status: %s\r\n" % bl_import (pars [0][0], pars [0][1], pars [0][2], 0)
			bl_reply (user, out)
			return 0

		if data [4:11] == "listdel":
			try:
				id = int (data [12:])
			except:
				bl_reply (user, "Missing command parameters: listdel <id>")
				return 0

			if id >= 0 and bl_update and len (bl_update) - 1 >= id:
				item = bl_update.pop (id)
				vh.SQL ("delete from `py_bl_list` where `list` = '%s'" % bl_repsql (item [0]))
				del bl_list [:]
				bl_list = [[] for i in xrange (256)]

				for newid, newitem in enumerate (bl_update):
					bl_import (newitem [0], newitem [1], newitem [2], 0)

					if newitem [3]:
						bl_update [newid][4] = time.time ()

				out = "Item deleted from list:\r\n"
				out += "\r\n [*] ID: %s" % id
				out += "\r\n [*] List: %s" % item [0]
				out += "\r\n [*] Type: %s" % item [1]
				out += "\r\n [*] Title: %s" % item [2]
				out += "\r\n [*] Update: %s\r\n" % ("On load" if not item [3] else "%s minute | %s" % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [4] + (item [3] * 60)))) if item [3] == 1 else "%s minutes | %s" % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [4] + (item [3] * 60)))))
				bl_reply (user, out)
			else:
				bl_reply (user, "List out of item with ID: %s" % id)

			return 0

		if data [4:9] == "exall":
			if not bl_except:
				out = "Exception list is empty."
			else:
				out = "Exception list:\r\n"

				for id, item in enumerate (bl_except):
					out += "\r\n [*] ID: %s" % id
					out += "\r\n [*] Title: %s" % item [2]
					out += "\r\n [*] Lower IP: %s" % bl_addrtostr (item [0])
					out += "\r\n [*] Higher IP: %s\r\n" % bl_addrtostr (item [1])

			bl_reply (user, out)
			return 0

		if data [4:9] == "exadd":
			pars = re.findall (r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\- ]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?[ ]*(.*)$", data [10:])

			if not pars or not pars [0][0]:
				bl_reply (user, "Missing command parameters: exadd <addr>-[range] [title]")
				return 0

			if not bl_validaddr (pars [0][0]):
				bl_reply (user, "Lower IP not valid: %s" % pars [0][0])
				return 0

			if not bl_validaddr (pars [0][1] or pars [0][0]):
				bl_reply (user, "Higher IP not valid: %s" % pars [0][1] or pars [0][0])
				return 0

			for id, item in enumerate (bl_except):
				if item [0] == bl_addrtoint (pars [0][0]) and item [1] == bl_addrtoint (pars [0][1] or pars [0][0]):
					out = "Item already in list:\r\n"
					out += "\r\n [*] ID: %s" % id
					out += "\r\n [*] Title: %s" % item [2]
					out += "\r\n [*] Lower IP: %s" % pars [0][0]
					out += "\r\n [*] Higher IP: %s\r\n" % (pars [0][1] or pars [0][0])
					bl_reply (user, out)
					return 0

			bl_except.append ([bl_addrtoint (pars [0][0]), bl_addrtoint (pars [0][1] or pars [0][0]), pars [0][2] or "Exception"])
			out = "Item added to list:\r\n"
			out += "\r\n [*] ID: %s" % (len (bl_except) - 1)
			out += "\r\n [*] Title: %s" % (pars [0][2] or "Exception")
			out += "\r\n [*] Lower IP: %s" % pars [0][0]
			out += "\r\n [*] Higher IP: %s\r\n" % (pars [0][1] or pars [0][0])
			bl_reply (user, out)
			bl_exceptsave ()
			return 0

		if data [4:9] == "exdel":
			try:
				id = int (data [10:])
			except:
				bl_reply (user, "Missing command parameters: exdel <id>")
				return 0

			if id >= 0 and bl_except and len (bl_except) - 1 >= id:
				item = bl_except.pop (id)
				out = "Item deleted from list:\r\n"
				out += "\r\n [*] ID: %s" % id
				out += "\r\n [*] Title: %s" % item [2]
				out += "\r\n [*] Lower IP: %s" % bl_addrtostr (item [0])
				out += "\r\n [*] Higher IP: %s\r\n" % bl_addrtostr (item [1])
				bl_reply (user, out)
				bl_exceptsave ()
			else:
				bl_reply (user, "List out of item with ID: %s" % id)

			return 0

		if data [4:8] == "conf":
			out = "Configuration list:\r\n"

			for name, item in sorted (bl_conf.iteritems ()):
				out += "\r\n [*] Name: %s" % name
				out += "\r\n [*] Type: %s" % item [1]
				out += "\r\n [*] Range: %s - %s" % (item [2], item [3])
				out += "\r\n [*] Value: %s\r\n" % item [0]

			bl_reply (user, out)
			return 0

		if data [4:7] == "set":
			pars = re.findall (r"^(\S+)[ ]*(.*)$", data [8:])

			if pars and pars [0][0]:
				out = "Item configuration:\r\n"
				out += "\r\n [*] Name: %s" % pars [0][0]
				out += "\r\n [*] Type: %s" % (bl_conf [pars [0][0]][1] if pars [0][0] in bl_conf else "None")
				out += "\r\n [*] Range: %s - %s" % (bl_conf [pars [0][0]][2] if pars [0][0] in bl_conf else 0, bl_conf [pars [0][0]][3] if pars [0][0] in bl_conf else 0)
				out += "\r\n [*] Old value: %s" % (bl_getconf (pars [0][0]) or "None")
				out += "\r\n [*] New value: %s" % pars [0][1]
				out += "\r\n [*] Status: %s\r\n" % bl_setconf (pars [0][0], pars [0][1])
			else:
				out = "Missing command parameters: set <item> [value]"

			bl_reply (user, out)
			return 0

		if data [4:8] == "feed":
			if not bl_feed:
				out = "Waiting feed list is empty."
			else:
				out = "Waiting feed list:\r\n"

				for item in bl_feed:
					code = vh.GetIPCC (item [0])
					out += "\r\n [*] IP: %s.%s" % (item [0], code)
					out += "\r\n [*] Expires: %s\r\n" % time.strftime ("%d/%m %H:%M", time.gmtime (item [1] + (bl_conf ["time_feed"][0] * 60)))

			bl_reply (user, out)
			return 0

		out = "Blacklist usage:\r\n\r\n"
		# space
		out += " !bl stats\t\t\t\t\t- Script statistics\r\n"
		out += " !bl find <item>\t\t\t\t- Search in all lists\r\n\r\n"
		# space
		out += " !bl listall\t\t\t\t\t- Show loaded lists\r\n"
		out += " !bl listadd <list> <type> <\"title\"> [update]\t- Load new list\r\n"
		out += " !bl listdel <id>\t\t\t\t- Delete loaded list\r\n\r\n"
		# space
		out += " !bl exall\t\t\t\t\t- Show exception list\r\n"
		out += " !bl exadd <addr>-[range] [title]\t\t- New exception item\r\n"
		out += " !bl exdel <id>\t\t\t\t- Delete an exception\r\n\r\n"
		# space
		out += " !bl conf\t\t\t\t\t- Show current configuration\r\n"
		out += " !bl set <item> [value]\t\t\t- Set configuration item\r\n\r\n"
		# space
		out += " !bl feed\t\t\t\t\t- Show waiting feed list\r\n"
		bl_reply (user, out)
		return 0

	return 1

def OnTimer ():
	global bl_stats, bl_update, bl_feed, bl_conf

	if time.time () - bl_stats ["tick"] >= 60:
		bl_stats ["tick"] = time.time ()

		for id, item in enumerate (bl_feed):
			if time.time () - item [1] >= bl_conf ["time_feed"][0] * 60:
				bl_feed.pop (id)

		for id, item in enumerate (bl_update):
			if item [3] and time.time () - item [4] >= item [3] * 60:
				bl_update [id][4] = time.time ()
				out = bl_import (item [0], item [1], item [2], item [3])

				if bl_conf ["notify_update"][0]:
					bl_notify ("%s: %s" % (item [2], out))

bl_startup ()
