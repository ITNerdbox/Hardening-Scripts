#!/usr/bin/python

try:
	import argparse, os, stat, textwrap
	
	from ConfigParser import SafeConfigParser
	from termcolor import colored
	
except:
	print "[!] Not all required modules could be loaded...."
	exit(0)

parser = argparse.ArgumentParser(description="PHP Configuration Analyzer by Jeroen Diel <jeroen@nerdbox.it>")
parser.add_argument("-f", "--file", help="Path to the php.ini file that needs to be analyzed")
args = parser.parse_args()


## Variables
exec_functions = ["exec", "passthru", "system", "shell_exec"]
version = "0.1"


## Function(s)
def printwrap(pwidth, message):
	prefix = "     "
	wrapper = textwrap.TextWrapper(initial_indent=prefix, width=pwidth, subsequent_indent=" " * len(prefix))
	
	print wrapper.fill(message)


## Start of code
try:
	if os.path.isfile(args.file):
		fname = args.file

		parser = SafeConfigParser()
		parser.read(fname)
		
		print(chr(27) + "[2J")
		print colored("-", "white") * 100
		print colored(" PHP Configuration Analyzer v%s by Jeroen Diel <jeroen@nerdbox.it>" % version, "green")
		print colored("-", "white") * 100
		print ""

		## Generic
		print colored(" [+] PHP Generic Settings \n", "green")

		try:
			if "On" in parser.get("PHP", "display_errors"):
				print colored("     Error Messages\n", "yellow")
				printwrap(100, "It appears that error messages are exposed. If this web server is a production machine, it is recommended to disable the option 'display_errors' in the PHP configuration.")
				print "\n"
			else:
				pass
		except:
				print colored("     Error Messages\n", "yellow")
				printwrap(100, "It appears that error messages are not configured. If this web server is a production machine, it is recommended to disable the option 'display_errors' in the PHP configuration.")
				print "\n"

		try:
			if "On" in parser.get("PHP", "expose_php"):
				print colored("     Information Disclosure\n", "blue")
				printwrap(100, "The PHP version is exposed in all of the HTTP response header called 'X-Powered-By'. Attackers could use this information to specifically search for vulnerabilities within this version of PHP.")
				print "\n"
			else:
				pass
		except:
				print colored("     Information Disclosure\n", "blue")
				printwrap(100, "It appears that error messages are not configured. If this web server is a production machine, it is recommended to disable the option 'display_errors' in the PHP configuration.")
				print "\n"

		cnt = 0
		for exec_function in exec_functions:
			try:
				if exec_function not in parser.get("PHP", "disable_functions").split(","):
					cnt += 1
			except:
				print colored("     Disabled Functions\n", "red")
				printwrap(100, "It appears that the disable_functions option is not configured in the PHP configuration. This means that functions such as 'exec', 'passthru', 'shell_exec' and 'system' are enabled. Unless you execute operating system commands from your application, these functions should be disabled.")
				
		
		if cnt > 0:
			print colored("     Disabled Functions\n", "red")
			printwrap(100, "It appears that the disable_function option is not configured in the PHP configuration, however, functions such as 'exec', 'shell_exec', 'passthru' and 'system' are not disabled.")
			print ""
			printwrap(100, "These functions allow operating system commands to be executed through PHP. Unless your application specifically uses these functions, they should be added to the disable_functions option.") 
			print "\n"
		
		try:
			if not parser.get("PHP", "open_basedir"):
				print colored("     Open Basedir\n", "yellow")
				printwrap(100, "This option prevents functions such as 'fopen()' and 'include' to access files on the filesystem outside the configured path set in open_basedir.")
				print ""
				printwrap(100, "The open_basedir was found enabled in the PHP configuration file. However, it does not have a path configured which means that functions such as 'fopen()' and 'include' can read any file on the filesystem.")
				print "\n"
		except:
			print colored("     Open Basedir\n", "yellow")
			printwrap(100, "The open_basedir option was either commented out or not set in the PHP configuration file. This option prevents functions such as 'fopen()' and 'include' to access files on the filesystem outside the configured path set in open_basedir.")
			print ""
			printwrap(100, "Additionally, if MySQL/MariaDB is configured to use mysqlnd drivers, 'LOAD DATA INFILE' will be affected by open_basedir.")
			print "\n"

		try:
			if "On" in parser.get("PHP", "allow_url_fopen"):
				print colored("     Remote File Reading\n", "yellow")
				printwrap(100, "The 'allow_url_fopen' option has been enabled and can be used to retrieve data from remote servers or websites. However, if the application that uses this functionality is configured incorrectly, this may cause security issues.")
				print ""
				printwrap(100, "If your application does not require to read remote files, it is recommended to set 'allow_url_fopen' to Off.") 
				print "\n"
		except:
			print colored("     Remote File Reading\n", "yellow")
			printwrap(100, "The 'allow_url_fopen' option was either commented out or not set in the PHP configuration file. This option allows reading file from remote servers or websites. If the application does not require this feature, it is recommended to turn it off.")
			print "\n"


		try:
			if "On" in parser.get("PHP", "allow_url_include"):
				print colored("     Remote File Inclusion\n", "red")
				printwrap(100, "The 'allow_url_include' option has been enabled and can be used to include PHP code remotely. Applications that use this method of loading PHP files should be avoided at all costs.")
				print ""
				printwrap(100, "No matter what, the 'allow_url_include' should always be set to Off.") 
				print "\n"
		except:
			print colored("     Remote File Inclusion\n", "red")
			printwrap(100, "The 'allow_url_include' option was either commented out or not set in the PHP configuration file. This option should always be forced to be disabled.")
			print "\n"


		## Performance
		try:
			memory_limit = int(parser.get("PHP", "memory_limit")[:-1])
			post_size = int(parser.get("PHP", "post_max_size")[:-1])
			max_upload = int(parser.get("PHP", "upload_max_filesize")[:-1])
			
			if post_size > memory_limit:
				print colored(" [+] PHP Performance Settings \n", "green")
				print colored("     Memory Configuration\n", "yellow")
				printwrap(100, "Currently, PHP is configured with a memory limit of %sM. However, the maximum post (%sM) size is larger than the memory limit and might cause performance issues." % (memory_limit, post_size))

			if max_upload > post_size and parser.get("PHP", "file_uploads") == "On":
				print ""
				printwrap(100, "The maximum upload size (%sM) is larger than the maximum post size (%sM). This may cause issues when uploading large files." % (max_upload, post_size))  
			print "\n"
		except:
			pass


		## Session Management
		print colored(" [+] PHP Session Management \n", "green")

		try:
			if "1" in parser.get("Session", "session.cookie_lifetime"):
				print colored("     Session Lifetime does not expire when the browser terminates", "yellow")
				printwrap(100, "When a user is authenticated in an application and closes the browser, the sesion is kept a live because the session identifier is stored in permanent storage.")
				print ""
				printwrap(100, "Configure PHP to not store the sesion identifier to be stored in permanent storage by settings 'session.cookie_lifetime=0'")
				print ""
		except:
			pass

		try:
			if parser.get("Session", "session.save_path"):
				path = parser.get("Session", "session.save_path").split("\"")[1]
				
				if int(oct(os.stat(path).st_mode & 0777)[-1:]) >= 4:
					print colored("     Session are stored in a non secure path\n", "red")
					printwrap(100, "The session are stored in a path (%s) where permissions are not properly set. Anyone with SSH access to this system has access to the path where the session identifiers are stored." % path)
					print ""
					printwrap(100, "Change the permissions on the folder %s to 750." % path)
					print "\n\n"	
		except:
				print colored("     Sessions are stored in a non secure path\n", "red")
				printwrap(100, "The option session.save_path was either commented out or not set in the PHP configuration file. If not set, the default path is /tmp which is readable to anyone on the system.")
				print ""
				printwrap(100, "This can be set by either uncommenting or setting the session.save_path to a path that is not world readable.")
				print "\n"		

		try:
			if parser.get("Session", "session.use_strict_mode") == "0":
				print colored("     Strict Session Mode is Disabled\n", "yellow")
				printwrap(100, "If strict session mode is enabled, it does not accept uninitialized session identifiers. If an uninitialized session identifier is transmitted by the browser, the session identifier will be regenerated. By enabling this option, PHP will prevent session fixation attacks.")
				print ""
				printwrap(100, "This can be enabled by setting session.use_strict_mode to 1 in the php.ini file.")
				print "\n"
				
			elif parser.get("Session", "session.use_strict_mode") == "1":
				pass
		except:
			print colored("     Strict Session Mode is Disabled\n", "yellow")
			printwrap(100, "Currently strict session mode is commented out in the PHP configuration file. It is highly recommended to enable it and properly configure it.")
			print "\n"

		try:
			if not "0" in parser.get("Session", "session.use_trans_sid"):
				print colored("     Session Identifier is Transmitted in the URL\n", "yellow")
				printwrap(100, "The 'session.use_trans_sid' has not been disabled. This means that the session identifier is transmitted in the URL.")
				print ""
				printwrap(100, "If users of the application have an active session and copy / paste the URL in chat applications or email, the session can be hijacked.")
				print ""
				printwrap(100, "It is recommended to set 'session.use_trans_sid' to 0 in the PHP configuration.")
				print "\n"
		except:
			pass
			
		## session.hash_function
		print colored("     Session Identifier Hashing Algorithm\n", "blue")
		try:
			hash_function = parser.get("Session", "session.hash_function")
			if int(hash_function) == 0:
				printwrap(100, "The used hashing algorithm for generating the session identifier is MD5 and has known cryptographic weaknesses.")
			if int(hash_function) == 1:
				printwrap(100, "The used hashing algorithm for generating the session identifier is SHA-1 and has known cryptographic weaknesses.")
			print ""
			printwrap(100, "Although session identifiers are not considered to last long, in high traffic websites or applications, this could become be a concern.") 
			
			print "\n"
		except:
			printwrap(100, "No hash function defined in the PHP config, the default is MD5 which has known cryptographic weaknesses.")
			print ""
			printwrap(100, "Although session identifiers are not considered to last long, in high traffic websites or applications, this could become be a concern.")
			print "\n"

		try:
			if not "1" in parser.get("Session", "session.cookie_secure"):
				print colored("     Session Cookie Secure Attribute\n", "yellow")
				printwrap(100, "The 'Secure' attribute on the session cookie is not set. This attribute makes sure that session cookie data is transmitted soley over HTTPS.")
				print ""
				printwrap(100, "If the application is using HTTPS, it is recommended to enable the secure attribute on the cookie by setting 'session.cookie_secure = 1'")
				print "\n"
		except:
			print colored("     Session Cookie Secure Attribute\n", "yellow")
			printwrap(100, "The 'Secure' attribute on the session cookie is not configured in the PHP configuration. This attribute makes sure that session cookie data is transmitted soley over HTTPS.")
			print ""
			printwrap(100, "As this option is either commented out or not found in the current PHP configuration, the secure attribute is not set (which is the default setting).")
			print ""
			printwrap(100, "If the application is using HTTPS, it is recommended to enable the 'secure' attribute on the cookie by settings 'session.cookie_secure = 1'")
			print "\n"

		try:
			if not "1" in parser.get("Session", "session.cookie_httponly"):
				print colored("     Session Cookie HTTPOnly Attribute\n", "yellow")
				printwrap(100, "The 'HTTPOnly' attribute on the session cookie is not set. This attribute makes sure that session cookie data can not be accessed by javascript. In case of Cross-Site Scripting attacks, the session can not be hijacked.")
				print ""
				printwrap(100, "If the application does not use javascript to access the session cookie, it is recommended to enable the HTTPOnly attribute on the cookie by setting 'session.cookie_httponly = 1'")
				print "\n"
		except:
			print colored("     Session Cookie HTTPOnly Attribute\n", "yellow")
			printwrap(100, "The 'HTTPOnly' attribute on the session cookie is not configured in the PHP configuration. This attribute makes sure that session cookie data can not be accessed by javascript. In case of Cross-Site Scripting attacks, the session can not be hijacked.")
			print ""
			printwrap(100, "As this option is either commented out or not found in the current PHP configuration, the HTTPOnly attribute is not set.")
			print ""
			printwrap(100, "If the application does not use javascript to access the session cookie, it is recommended to enable the HTTPOnly attribute on the cookie by setting 'session.cookie_httponly = 1'")
			print "\n"

	else:
		print "[!] Error: File does not exist!"
except:
	print "[!] Error: No argument supplied?"
