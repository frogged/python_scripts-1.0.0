# Verlihub Blacklist 1.1.4
# Written by RoLex, 2010-2015
# Special thanks to Frog

# Changelog:

# 0.0.1 - Initial release
# 1.0.0 - Added configuration find_maxres to limit number of results on find action
# 1.0.0 - Added country codes of addresses in waiting feed list
# 1.1.0 - Added configuration time_down to specify timeout of download progress in seconds
# 1.1.1 - Added listoff command to disable or enable lists
# 1.1.2 - Added another read failure check
# 1.1.3 - Fixed display of item configuration old value when changing from zero
# 1.1.3 - Fixed default exception file creation in wrong directory
# 1.1.3 - Added translation ability with list command lang and update command trans
# 1.1.4 - Added compression file format "zip"
# 1.1.4 - Added data file format "emule"

import vh, re, urllib2, gzip, zipfile, StringIO, time, os, socket, struct

bl_lang = {
	0: "Blacklist %s startup",
	1: "Exception",
	2: "Failed with HTTP error",
	3: "Failed with URL error",
	4: "Failed with unknown error",
	5: "Failed to compile pattern",
	6: "File is not compressed with GZIP",
	7: "Failed to read data",
	8: "%s items loaded",
	9: "Unknown list type",
	10: "Failed to open file",
	11: "%s items saved",
	12: "Value too low",
	13: "Value too high",
	14: "Value is not a number",
	15: "Value too short",
	16: "Value too long",
	17: "Item not found",
	18: "Blacklisted connection exception from %s.%s: %s",
	19: "Blocking blacklisted connection from %s.%s: %s",
	20: "You don't have access to this command.",
	21: "Blacklist statistics",
	22: "Version: %s",
	23: "Loaded lists: %s of %s",
	24: "Blacklisted items: %s",
	25: "Excepted items: %s",
	26: "Blocked connections: %s",
	27: "Excepted connections: %s",
	28: "Total connections: %s",
	29: "Missing command parameters: %s",
	30: "Results for IP: %s",
	31: "No results for IP: %s",
	32: "Results for title: %s",
	33: "No results for title: %s",
	34: "Blacklist list is empty.",
	35: "Blacklist list",
	36: "ID: %s",
	37: "List: %s",
	38: "Type: %s",
	39: "Title: %s",
	40: "Update: %s",
	41: "On load",
	42: "%s minute",
	43: "%s minutes",
	44: "Disabled: %s",
	45: "No",
	46: "Yes",
	47: "Type must be one of: %s",
	48: "Update must be in range: %s - %s",
	49: "Item already in list",
	50: "Item added to list",
	51: "Status: %s",
	52: "Item deleted from list",
	53: "List out of item with ID: %s",
	54: "Item now disabled",
	55: "Item now enabled",
	56: "Exception list is empty.",
	57: "Exception list",
	58: "Lower IP: %s",
	59: "Higher IP: %s",
	60: "Lower IP not valid: %s",
	61: "Higher IP not valid: %s",
	62: "Configuration list",
	63: "Name: %s",
	64: "Range: %s - %s",
	65: "Value: %s",
	66: "Item configuration",
	67: "Old value: %s",
	68: "New value: %s",
	69: "Waiting feed list is empty.",
	70: "Waiting feed list",
	71: "IP: %s.%s",
	72: "Expires: %s",
	73: "Blacklist usage",
	74: "Script statistics",
	75: "Search in loaded lists",
	76: "Show all lists",
	77: "Load new list",
	78: "Disable or enable list",
	79: "Delete existing list",
	80: "Show exception list",
	81: "New exception item",
	82: "Delete an exception",
	83: "Show current configuration",
	84: "Set configuration item",
	85: "Show waiting feed list",
	86: "value",
	87: "item",
	88: "id",
	89: "addr",
	90: "range",
	91: "title",
	92: "list",
	93: "type",
	94: "update",
	95: "None",
	96: "Set translation string",
	97: "Show current translation",
	98: "Translation list",
	99: "Updated translation with ID: %s",
	100: "Parameter count mismatch in translation with ID: %s",
	101: "File is not compressed with ZIP"
}

bl_conf = {
	"file_except": [vh.basedir + "/blacklist_except.txt", "str", 1, 255],
	"nick_feed": ["", "str", 0, 255],
	"class_feed": [5, "int", 0, 11],
	"class_conf": [10, "int", 3, 11],
	"time_feed": [60, "int", 0, 1440],
	"time_down": [5, "int", 1, 300],
	"notify_update": [1, "int", 0, 1],
	"find_maxres": [1000, "int", 1, 100000]
}

bl_stats = {
	"connect": 0l,
	"block": 0l,
	"except": 0l,
	"tick": time.time (),
	"version": "1.1.4" # update on release
}

bl_update = [
	# ["http://list.iblocklist.com/?list=ijfqtofzixtwayqovmxn&fileformat=p2p&archiveformat=gz", "gzip-p2p", "Primary threat", 0, 0, 0],
	# ["http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz", "gzip-p2p", "Proxy", 0, 0, 0],
	# ["http://ledo.feardc.net/mirror/torexit.list", "single", "Tor exit", 60, 0, 0],
	# ["http://ledo.feardc.net/mirror/torserver.list", "single", "Tor server", 60, 0, 0]
]

bl_list = [[] for i in xrange (256)]
bl_except = []
bl_feed = []

def bl_startup ():
	global bl_conf, bl_update, bl_stats

	vh.SQL (
		"create table if not exists `py_bl_lang` ("\
			"`id` bigint(20) unsigned not null primary key,"\
			"`value` text collate utf8_unicode_ci not null"\
		") engine = myisam default character set utf8 collate utf8_unicode_ci"
	)

	vh.SQL (
		"create table if not exists `py_bl_conf` ("\
			"`name` varchar(255) collate utf8_unicode_ci not null primary key,"\
			"`value` varchar(255) collate utf8_unicode_ci not null"\
		") engine = myisam default character set utf8 collate utf8_unicode_ci"
	)

	vh.SQL (
		"create table if not exists `py_bl_list` ("\
			"`list` varchar(255) collate utf8_unicode_ci not null primary key,"\
			"`type` varchar(25) collate utf8_unicode_ci not null,"\
			"`title` varchar(255) collate utf8_unicode_ci not null,"\
			"`update` smallint(4) unsigned not null default 0,"\
			"`off` tinyint(1) unsigned not null default 0"\
		") engine = myisam default character set utf8 collate utf8_unicode_ci"
	)

	vh.SQL ("alter ignore table `py_bl_list` add column `off` tinyint(1) unsigned not null default 0 after `update`")

	for id, lang in bl_lang.iteritems ():
		vh.SQL ("insert ignore into `py_bl_lang` (`id`, `value`) values (%s, '%s')" % (str (id), bl_repsql (lang)))

	sql, rows = vh.SQL ("select * from `py_bl_lang`", 300)

	if sql and rows:
		for lang in rows:
			if int (lang [0]) >= 0 and len (bl_lang) - 1 >= int (lang [0]) and lang [1].count ("%s") == bl_lang [int (lang [0])].count ("%s"):
				bl_lang [int (lang [0])] = lang [1]

	for name, value in bl_conf.iteritems ():
		vh.SQL ("insert ignore into `py_bl_conf` (`name`, `value`) values ('%s', '%s')" % (bl_repsql (name), bl_repsql (str (value [0]))))

	sql, rows = vh.SQL ("select * from `py_bl_conf`", 100)

	if sql and rows:
		for conf in rows:
			bl_setconf (conf [0], conf [1], False)

	sql, rows = vh.SQL ("select * from `py_bl_list`", 100)

	if sql and rows:
		for list in rows:
			bl_update.append ([list [0], list [1], list [2], int (list [3]), int (list [4]), 0])

	out = (bl_lang [0] + ":\r\n\r\n") % bl_stats ["version"]

	for id, item in enumerate (bl_update):
		if not item [4]:
			out += " [*] %s: %s\r\n" % (item [2], bl_import (item [0], item [1], item [2], 0))

			if item [3]:
				bl_update [id][5] = time.time ()

	out += " [*] %s: %s\r\n" % (bl_lang [1], bl_import (bl_conf ["file_except"][0], "p2p", bl_lang [1], 0, True))
	bl_notify (out)

def bl_import (list, type, title, update, exlist = False): # gzip-p2p, gzip-emule, gzip-range, gzip-single, zip-p2p, zip-emule, zip-range, zip-single, p2p, emule, range, single
	global bl_list, bl_except
	file = None

	if "://" in list:
		try:
			file = urllib2.urlopen (list, None, bl_conf ["time_down"][0])
		except urllib2.HTTPError:
			return bl_lang [2]
		except urllib2.URLError:
			return bl_lang [3]
		except:
			return bl_lang [4]
	else:
		try:
			file = open (list, "r")
		except:
			pass

	if file:
		find = None

		if "p2p" in type:
			find = "(.*)\:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\-(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
		elif "emule" in type:
			find = "(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}) \- (\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}) \, \d{1,3} \, (.*)"
		elif "range" in type:
			find = "(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\-(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
		elif "single" in type:
			find = "(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"

		if find:
			try:
				find = re.compile (r"^" + find + "$")
			except:
				file.close ()
				return bl_lang [5]

			if "gzip" in type or "zip" in type:
				data = None

				try:
					data = StringIO.StringIO (file.read ())
				except:
					pass

				file.close ()

				if data:
					if "gzip" in type: # gzip
						try:
							file = gzip.GzipFile (fileobj = data)
							file.read (1)
						except:
							return bl_lang [6]
					elif "zip" in type: # zip
						try:
							arch = zipfile.ZipFile (file = data)
							file = arch.open (arch.namelist () [0])
							arch.close ()
							file.read (1)
						except:
							return bl_lang [101]
				else:
					return bl_lang [7]

			mylist = []

			for line in file:
				part = find.findall (line.replace ("\r", "").replace ("\n", ""))

				if part:
					mytitle = None
					myloaddr = None
					myhiaddr = None

					if "p2p" in type:
						mytitle = part [0][0] or title
						myloaddr = str (int (part [0][1])) + "." + str (int (part [0][2])) + "." + str (int (part [0][3])) + "." + str (int (part [0][4]))
						myhiaddr = str (int (part [0][5])) + "." + str (int (part [0][6])) + "." + str (int (part [0][7])) + "." + str (int (part [0][8]))
					elif "emule" in type:
						mytitle = part [0][8] or title
						myloaddr = str (int (part [0][0])) + "." + str (int (part [0][1])) + "." + str (int (part [0][2])) + "." + str (int (part [0][3]))
						myhiaddr = str (int (part [0][4])) + "." + str (int (part [0][5])) + "." + str (int (part [0][6])) + "." + str (int (part [0][7]))
					elif "range" in type:
						mytitle = title
						myloaddr = str (int (part [0][0])) + "." + str (int (part [0][1])) + "." + str (int (part [0][2])) + "." + str (int (part [0][3]))
						myhiaddr = str (int (part [0][4])) + "." + str (int (part [0][5])) + "." + str (int (part [0][6])) + "." + str (int (part [0][7]))
					elif "single" in type:
						mytitle = title
						myloaddr = str (int (part [0][0])) + "." + str (int (part [0][1])) + "." + str (int (part [0][2])) + "." + str (int (part [0][3]))
						myhiaddr = myloaddr

					if mytitle and myloaddr and myhiaddr and bl_validaddr (myloaddr) and bl_validaddr (myhiaddr):
						mylist.append ([bl_addrtoint (myloaddr), bl_addrtoint (myhiaddr), mytitle.replace ("\\'", "'").replace ("\\\"", "\"").replace ("\\&", "&").replace ("\\\\", "\\")])

			file.close ()

			if exlist:
				for item in mylist:
					bl_except.append (item)
			else:
				for item in mylist:
					for i in xrange (item [0] >> 24, (item [1] >> 24) + 1):
						if not update or not item in bl_list [i]:
							bl_list [i].append (item)

			return bl_lang [8] % len (mylist)
		else:
			file.close ()
			return bl_lang [9]
	else:
		return bl_lang [10]

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
		return bl_lang [11] % len (bl_except)
	else:
		return bl_lang [10]

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
					return bl_lang [12]
				elif new > bl_conf [name][3]:
					return bl_lang [13]
				else:
					bl_conf [name][0] = new
			except:
				return bl_lang [14]
		else:
			if len (value) < bl_conf [name][2]:
				return bl_lang [15]
			elif len (value) > bl_conf [name][3]:
				return bl_lang [16]
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
		return bl_lang [17]

def bl_addrtoint (addr):
	res = 0

	try:
		res = struct.unpack ("!L", socket.inet_aton (addr)) [0]
	except:
		pass

	return res

def bl_addrtostr (addr):
	res = "0.0.0.0"

	try:
		res = socket.inet_ntoa (struct.pack ("!L", addr))
	except:
		pass

	return res

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
					bl_notify ((bl_lang [18] + " | %s") % (addr, code, item [2], eitem [2]))
					bl_stats ["except"] += 1
					return 1

			for id, feed in enumerate (bl_feed):
				if feed [0] == addr:
					if time.time () - feed [1] >= bl_conf ["time_feed"][0] * 60:
						bl_notify (bl_lang [19] % (addr, code, item [2]))
						bl_feed [id][1] = time.time ()

					bl_stats ["block"] += 1
					return 0

			bl_notify (bl_lang [19] % (addr, code, item [2]))
			bl_feed.append ([addr, time.time ()])
			bl_stats ["block"] += 1
			return 0

	return 1

def OnOperatorCommand (user, data):
	global bl_conf, bl_stats, bl_list, bl_except, bl_update, bl_feed

	if data [1:3] == "bl":
		if vh.GetUserClass (user) < bl_conf ["class_conf"][0]:
			bl_reply (user, bl_lang [20])
			return 0

		if data [4:9] == "stats":
			count = 0
			lists = 0

			for i in range (len (bl_list)):
				for item in bl_list [i]:
					count += 1

			for item in bl_update:
				if not item [4]:
					lists += 1

			out = bl_lang [21] + ":\r\n"
			out += ("\r\n [*] " + bl_lang [22]) % bl_stats ["version"]
			out += ("\r\n [*] " + bl_lang [23]) % (lists, len (bl_update))
			out += ("\r\n [*] " + bl_lang [24]) % count
			out += ("\r\n [*] " + bl_lang [25]) % len (bl_except)
			out += ("\r\n [*] " + bl_lang [26]) % bl_stats ["block"]
			out += ("\r\n [*] " + bl_lang [27]) % bl_stats ["except"]
			out += ("\r\n [*] " + bl_lang [28] + "\r\n") % bl_stats ["connect"]
			bl_reply (user, out)
			return 0

		if data [4:8] == "find":
			if not data [9:]:
				bl_reply (user, bl_lang [29] % ("find <" + bl_lang [87] + ">"))
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
					bl_reply (user, (bl_lang [30] + "\r\n\r\n%s") % (data [9:], out))
				else:
					bl_reply (user, bl_lang [31] % data [9:])
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
					bl_reply (user, (bl_lang [32] + "\r\n\r\n%s") % (data [9:], out))
				else:
					bl_reply (user, bl_lang [33] % data [9:])

			return 0

		if data [4:11] == "listall":
			if not bl_update:
				out = bl_lang [34]
			else:
				out = bl_lang [35] + ":\r\n"

				for id, item in enumerate (bl_update):
					out += ("\r\n [*] " + bl_lang [36]) % id
					out += ("\r\n [*] " + bl_lang [37]) % item [0]
					out += ("\r\n [*] " + bl_lang [38]) % item [1]
					out += ("\r\n [*] " + bl_lang [39]) % item [2]

					if not item [4]:
						out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not item [3] else (bl_lang [42] + " | %s") % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [5] + (item [3] * 60)))) if item [3] == 1 else (bl_lang [43] + " | %s") % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [5] + (item [3] * 60)))))
					else:
						out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not item [3] else bl_lang [42] % item [3] if item [3] == 1 else bl_lang [43] % item [3])

					out += ("\r\n [*] " + bl_lang [44] + "\r\n") % (bl_lang [45] if not item [4] else bl_lang [46])

			bl_reply (user, out)
			return 0

		if data [4:11] == "listadd":
			pars = re.findall (r"^(\S+)[ ]+(\S+)[ ]+\"(.+)\"[ ]*(\d+)?$", data [12:])

			if not pars or not pars [0][0] or not pars [0][1] or not pars [0][2]:
				bl_reply (user, bl_lang [29] % ("listadd <" + bl_lang [92] + "> <" + bl_lang [93] + "> <\"" + bl_lang [91] + "\"> [" + bl_lang [94] + "]"))
				return 0

			types = [
				"gzip-p2p",
				"gzip-emule",
				"gzip-range",
				"gzip-single",
				"zip-p2p",
				"zip-emule",
				"zip-range",
				"zip-single",
				"p2p",
				"emule",
				"range",
				"single"
			]

			if not pars [0][1] in types:
				bl_reply (user, bl_lang [47] % ", ".join (types))
				return 0

			try:
				update = int (pars [0][3])
			except:
				update = 0

			if update < 0 or update > 10080:
				bl_reply (user, bl_lang [48] % (0, 10080))
				return 0

			for id, item in enumerate (bl_update):
				if item [0].lower () == pars [0][0].lower ():
					out = bl_lang [49] + ":\r\n"
					out += ("\r\n [*] " + bl_lang [36]) % id
					out += ("\r\n [*] " + bl_lang [37]) % item [0]
					out += ("\r\n [*] " + bl_lang [38]) % item [1]
					out += ("\r\n [*] " + bl_lang [39]) % item [2]

					if not item [4]:
						out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not item [3] else (bl_lang [42] + " | %s") % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [5] + (item [3] * 60)))) if item [3] == 1 else (bl_lang [43] + " | %s") % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (item [5] + (item [3] * 60)))))
					else:
						out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not item [3] else bl_lang [42] % item [3] if item [3] == 1 else bl_lang [43] % item [3])

					out += ("\r\n [*] " + bl_lang [44] + "\r\n") % (bl_lang [45] if not item [4] else bl_lang [46])
					bl_reply (user, out)
					return 0

			bl_update.append ([pars [0][0], pars [0][1], pars [0][2], update, 0, time.time () if update else 0])
			vh.SQL ("insert into `py_bl_list` (`list`, `type`, `title`, `update`) values ('%s', '%s', '%s', '%s')" % (bl_repsql (pars [0][0]), bl_repsql (pars [0][1]), bl_repsql (pars [0][2]), bl_repsql (str (update))))
			out = bl_lang [50] + ":\r\n"
			out += ("\r\n [*] " + bl_lang [36]) % (len (bl_update) - 1)
			out += ("\r\n [*] " + bl_lang [37]) % pars [0][0]
			out += ("\r\n [*] " + bl_lang [38]) % pars [0][1]
			out += ("\r\n [*] " + bl_lang [39]) % pars [0][2]
			out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not update else (bl_lang [42] + " | %s") % (update, time.strftime ("%d/%m %H:%M", time.gmtime (time.time () + (update * 60)))) if update == 1 else (bl_lang [43] + " | %s") % (update, time.strftime ("%d/%m %H:%M", time.gmtime (time.time () + (update * 60)))))
			out += ("\r\n [*] " + bl_lang [44]) % bl_lang [45]
			out += ("\r\n [*] " + bl_lang [51] + "\r\n") % bl_import (pars [0][0], pars [0][1], pars [0][2], 0)
			bl_reply (user, out)
			return 0

		if data [4:11] == "listdel":
			try:
				id = int (data [12:])
			except:
				bl_reply (user, bl_lang [29] % ("listdel <" + bl_lang [88] + ">"))
				return 0

			if id >= 0 and bl_update and len (bl_update) - 1 >= id:
				item = bl_update.pop (id)
				vh.SQL ("delete from `py_bl_list` where `list` = '%s'" % bl_repsql (item [0]))

				if not item [4]:
					del bl_list [:]
					bl_list = [[] for i in xrange (256)]

					for newid, newitem in enumerate (bl_update):
						if not newitem [4]:
							bl_import (newitem [0], newitem [1], newitem [2], 0)

							if newitem [3]:
								bl_update [newid][5] = time.time ()

				out = bl_lang [52] + ":\r\n"
				out += ("\r\n [*] " + bl_lang [36]) % id
				out += ("\r\n [*] " + bl_lang [37]) % item [0]
				out += ("\r\n [*] " + bl_lang [38]) % item [1]
				out += ("\r\n [*] " + bl_lang [39]) % item [2]
				out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not item [3] else bl_lang [42] % item [3] if item [3] == 1 else bl_lang [43] % item [3])
				out += ("\r\n [*] " + bl_lang [44] + "\r\n") % (bl_lang [45] if not item [4] else bl_lang [46])
				bl_reply (user, out)
			else:
				bl_reply (user, bl_lang [53] % id)

			return 0

		if data [4:11] == "listoff":
			try:
				id = int (data [12:])
			except:
				bl_reply (user, bl_lang [29] % ("listoff <" + bl_lang [88] + ">"))
				return 0

			if id >= 0 and bl_update and len (bl_update) - 1 >= id:
				item = bl_update [id]

				if not item [4]:
					bl_update [id][4] = 1
					bl_update [id][5] = 0
					vh.SQL ("update `py_bl_list` set `off` = 1 where `list` = '%s'" % bl_repsql (item [0]))
					del bl_list [:]
					bl_list = [[] for i in xrange (256)]

					for newid, newitem in enumerate (bl_update):
						if not newitem [4]:
							bl_import (newitem [0], newitem [1], newitem [2], 0)

							if newitem [3]:
								bl_update [newid][5] = time.time ()

					out = bl_lang [54] + ":\r\n"
					out += ("\r\n [*] " + bl_lang [36]) % id
					out += ("\r\n [*] " + bl_lang [37]) % item [0]
					out += ("\r\n [*] " + bl_lang [38]) % item [1]
					out += ("\r\n [*] " + bl_lang [39]) % item [2]
					out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not item [3] else bl_lang [42] % item [3] if item [3] == 1 else bl_lang [43] % item [3])
					out += ("\r\n [*] " + bl_lang [44] + "\r\n") % bl_lang [46]
					bl_reply (user, out)
				else:
					bl_update [id][4] = 0
					vh.SQL ("update `py_bl_list` set `off` = 0 where `list` = '%s'" % bl_repsql (item [0]))

					if item [3]:
						bl_update [id][5] = time.time ()

					out = bl_lang [55] + ":\r\n"
					out += ("\r\n [*] " + bl_lang [36]) % id
					out += ("\r\n [*] " + bl_lang [37]) % item [0]
					out += ("\r\n [*] " + bl_lang [38]) % item [1]
					out += ("\r\n [*] " + bl_lang [39]) % item [2]
					out += ("\r\n [*] " + bl_lang [40]) % (bl_lang [41] if not item [3] else (bl_lang [42] + " | %s") % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (time.time () + (item [3] * 60)))) if item [3] == 1 else (bl_lang [43] + " | %s") % (item [3], time.strftime ("%d/%m %H:%M", time.gmtime (time.time () + (item [3] * 60)))))
					out += ("\r\n [*] " + bl_lang [44]) % bl_lang [45]
					out += ("\r\n [*] " + bl_lang [51] + "\r\n") % bl_import (item [0], item [1], item [2], 0)
					bl_reply (user, out)
			else:
				bl_reply (user, bl_lang [53] % id)

			return 0

		if data [4:9] == "exall":
			if not bl_except:
				out = bl_lang [56]
			else:
				out = bl_lang [57] + ":\r\n"

				for id, item in enumerate (bl_except):
					out += ("\r\n [*] " + bl_lang [36]) % id
					out += ("\r\n [*] " + bl_lang [39]) % item [2]
					out += ("\r\n [*] " + bl_lang [58]) % bl_addrtostr (item [0])
					out += ("\r\n [*] " + bl_lang [59] + "\r\n") % bl_addrtostr (item [1])

			bl_reply (user, out)
			return 0

		if data [4:9] == "exadd":
			pars = re.findall (r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\- ]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?[ ]*(.*)$", data [10:])

			if not pars or not pars [0][0]:
				bl_reply (user, bl_lang [29] % ("exadd <" + bl_lang [89] + ">-[" + bl_lang [90] + "] [" + bl_lang [91] + "]"))
				return 0

			if not bl_validaddr (pars [0][0]):
				bl_reply (user, bl_lang [60] % pars [0][0])
				return 0

			if not bl_validaddr (pars [0][1] or pars [0][0]):
				bl_reply (user, bl_lang [61] % (pars [0][1] or pars [0][0]))
				return 0

			for id, item in enumerate (bl_except):
				if item [0] == bl_addrtoint (pars [0][0]) and item [1] == bl_addrtoint (pars [0][1] or pars [0][0]):
					out = bl_lang [49] + ":\r\n"
					out += ("\r\n [*] " + bl_lang [36]) % id
					out += ("\r\n [*] " + bl_lang [39]) % item [2]
					out += ("\r\n [*] " + bl_lang [58]) % pars [0][0]
					out += ("\r\n [*] " + bl_lang [59] + "\r\n") % (pars [0][1] or pars [0][0])
					bl_reply (user, out)
					return 0

			bl_except.append ([bl_addrtoint (pars [0][0]), bl_addrtoint (pars [0][1] or pars [0][0]), pars [0][2] or bl_lang [1]])
			out = bl_lang [50] + ":\r\n"
			out += ("\r\n [*] " + bl_lang [36]) % (len (bl_except) - 1)
			out += ("\r\n [*] " + bl_lang [39]) % (pars [0][2] or bl_lang [1])
			out += ("\r\n [*] " + bl_lang [58]) % pars [0][0]
			out += ("\r\n [*] " + bl_lang [59] + "\r\n") % (pars [0][1] or pars [0][0])
			bl_reply (user, out)
			bl_exceptsave ()
			return 0

		if data [4:9] == "exdel":
			try:
				id = int (data [10:])
			except:
				bl_reply (user, bl_lang [29] % ("exdel <" + bl_lang [88] + ">"))
				return 0

			if id >= 0 and bl_except and len (bl_except) - 1 >= id:
				item = bl_except.pop (id)
				out = bl_lang [52] + ":\r\n"
				out += ("\r\n [*] " + bl_lang [36]) % id
				out += ("\r\n [*] " + bl_lang [39]) % item [2]
				out += ("\r\n [*] " + bl_lang [58]) % bl_addrtostr (item [0])
				out += ("\r\n [*] " + bl_lang [59] + "\r\n") % bl_addrtostr (item [1])
				bl_reply (user, out)
				bl_exceptsave ()
			else:
				bl_reply (user, bl_lang [53] % id)

			return 0

		if data [4:8] == "conf":
			out = bl_lang [62] + ":\r\n"

			for name, item in sorted (bl_conf.iteritems ()):
				out += ("\r\n [*] " + bl_lang [63]) % name
				out += ("\r\n [*] " + bl_lang [38]) % item [1]
				out += ("\r\n [*] " + bl_lang [64]) % (item [2], item [3])
				out += ("\r\n [*] " + bl_lang [65] + "\r\n") % item [0]

			bl_reply (user, out)
			return 0

		if data [4:7] == "set":
			pars = re.findall (r"^(\S+)[ ]*(.*)$", data [8:])

			if pars and pars [0][0]:
				out = bl_lang [66] + ":\r\n"
				out += ("\r\n [*] " + bl_lang [63]) % pars [0][0]
				out += ("\r\n [*] " + bl_lang [38]) % (bl_conf [pars [0][0]][1] if pars [0][0] in bl_conf else bl_lang [95])
				out += ("\r\n [*] " + bl_lang [64]) % (bl_conf [pars [0][0]][2] if pars [0][0] in bl_conf else 0, bl_conf [pars [0][0]][3] if pars [0][0] in bl_conf else 0)
				out += ("\r\n [*] " + bl_lang [67]) % (bl_lang [95] if bl_getconf (pars [0][0]) == None else bl_getconf (pars [0][0]))
				out += ("\r\n [*] " + bl_lang [68]) % pars [0][1]
				out += ("\r\n [*] " + bl_lang [51] + "\r\n") % bl_setconf (pars [0][0], pars [0][1])
			else:
				out = bl_lang [29] % ("set <" + bl_lang [87] + "> [" + bl_lang [86] + "]")

			bl_reply (user, out)
			return 0

		if data [4:8] == "lang":
			out = bl_lang [98] + ":\r\n\r\n"

			for id, lang in sorted (bl_lang.iteritems ()):
				out += (" %s = %s\r\n") % (id, lang)

			bl_reply (user, out)
			return 0

		if data [4:9] == "trans":
			pars = re.findall (r"^(\S+)[ ]*(.*)$", data [10:])

			if not pars or not pars [0][0] or not pars [0][1]:
				bl_reply (user, bl_lang [29] % ("trans <" + bl_lang [88] + "> <" + bl_lang [86] + ">"))
				return 0

			try:
				id = int (pars [0][0])
			except:
				bl_reply (user, bl_lang [29] % ("trans <" + bl_lang [88] + "> <" + bl_lang [86] + ">"))
				return 0

			if id >= 0 and len (bl_lang) - 1 >= id:
				if pars [0][1].count ("%s") == bl_lang [id].count ("%s"):
					vh.SQL ("update `py_bl_lang` set `value` = '%s' where `id` = %s" % (bl_repsql (pars [0][1]), str (id)))
					old = bl_lang [id]
					bl_lang [id] = pars [0][1]
					out = (bl_lang [99] + "\r\n") % id
					out += ("\r\n [*] " + bl_lang [67]) % old
					out += ("\r\n [*] " + bl_lang [68] + "\r\n") % pars [0][1]
					bl_reply (user, out)
				else:
					out = (bl_lang [100] + "\r\n") % id
					out += ("\r\n [*] " + bl_lang [67]) % bl_lang [id]
					out += ("\r\n [*] " + bl_lang [68] + "\r\n") % pars [0][1]
					bl_reply (user, out)
			else:
				bl_reply (user, bl_lang [53] % id)

			return 0

		if data [4:8] == "feed":
			if not bl_feed:
				out = bl_lang [69]
			else:
				out = bl_lang [70] + ":\r\n"

				for item in bl_feed:
					code = vh.GetIPCC (item [0])
					out += ("\r\n [*] " + bl_lang [71]) % (item [0], code)
					out += ("\r\n [*] " + bl_lang [72] + "\r\n") % time.strftime ("%d/%m %H:%M", time.gmtime (item [1] + (bl_conf ["time_feed"][0] * 60)))

			bl_reply (user, out)
			return 0

		out = bl_lang [73] + ":\r\n\r\n"
		out += " !bl stats\t\t\t\t\t- " + bl_lang [74] + "\r\n"
		out += " !bl find <" + bl_lang [87] + ">\t\t\t\t- " + bl_lang [75] + "\r\n\r\n"
		out += " !bl listall\t\t\t\t\t- " + bl_lang [76] + "\r\n"
		out += " !bl listadd <" + bl_lang [92] + "> <" + bl_lang [93] + "> <\"" + bl_lang [91] + "\"> [" + bl_lang [94] + "]\t- " + bl_lang [77] + "\r\n"
		out += " !bl listoff <" + bl_lang [88] + ">\t\t\t\t- " + bl_lang [78] + "\r\n"
		out += " !bl listdel <" + bl_lang [88] + ">\t\t\t\t- " + bl_lang [79] + "\r\n\r\n"
		out += " !bl exall\t\t\t\t\t- " + bl_lang [80] + "\r\n"
		out += " !bl exadd <" + bl_lang [89] + ">-[" + bl_lang [90] + "] [" + bl_lang [91] + "]\t\t- " + bl_lang [81] + "\r\n"
		out += " !bl exdel <" + bl_lang [88] + ">\t\t\t\t- " + bl_lang [82] + "\r\n\r\n"
		out += " !bl conf\t\t\t\t\t- " + bl_lang [83] + "\r\n"
		out += " !bl set <" + bl_lang [87] + "> [" + bl_lang [86] + "]\t\t\t- " + bl_lang [84] + "\r\n\r\n"
		out += " !bl lang\t\t\t\t\t- " + bl_lang [97] + "\r\n"
		out += " !bl trans <" + bl_lang [88] + "> <" + bl_lang [86] + ">\t\t\t- " + bl_lang [96] + "\r\n\r\n"
		out += " !bl feed\t\t\t\t\t- " + bl_lang [85] + "\r\n"
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
			if not item [4] and item [3] and time.time () - item [5] >= item [3] * 60:
				bl_update [id][5] = time.time ()
				out = bl_import (item [0], item [1], item [2], 1)

				if bl_conf ["notify_update"][0]:
					bl_notify ("%s: %s" % (item [2], out))

bl_startup ()
