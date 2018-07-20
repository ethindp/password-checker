# Password checker - checks the strength of passwords
# Ethin Probst
# copyright (c) 2018 Ethin Probst
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA,
# or visit <https://www.gnu.org/licenses/gpl-2.0.en.html>
import sys
import globalPluginHandler
import wx
import gui
import ui
import threading
import os
import logHandler
import addonHandler
addonHandler.initTranslation()
import math
import string
import struct
import decimal
sys.path.append(os.path.dirname(__file__))
import zxcvbn
import zxcvbn.matching

def GetTime(seconds):
	try:
		ctx=decimal.localcontext()
		ctx.prec=32000
		minutes, seconds = ctx.new_context.divmod(seconds, 60)
		hours, minutes = ctx.new_context.divmod(minutes, 60)
		days, hours = ctx.new_context.divmod(hours, 24)
		weeks, days = ctx.new_context.divmod(days, 7)
		months, weeks = ctx.new_context.divmod(weeks, 4)
		years, months = ctx.new_context.divmod(months, 12)
		decades, years=ctx.new_context.divmod(years, 10)
		centuries, decades = ctx.new_context.divmod(decades, 10)
		millennia, centuries=ctx.new_context.divmod(centuries, 10)
		# translators: various time strings for time calculations
		periods = [('millennia' if millennia > 1 or millennia < 1 else 'millennium', millennia), ('centuries' if centuries > 1 or centuries < 1 else 'century', centuries), ('decades' if decades > 1 or decades < 1 else 'decade', decades), ('years' if years > 1 or years < 1 else 'year', years), ('months' if months > 1 or months < 1 else 'month', months), ('weeks' if weeks > 1 or weeks < 1 else 'week', weeks), ('days' if days > 1 or days < 1 else 'day', days), ('hours' if hours > 1 or hours < 1 else 'hour', hours), ('minutes' if minutes > 1 or minutes < 1 else 'minute', minutes), ('seconds' if seconds > 1 or seconds < 1 else 'second', seconds)]
		time_string = ', '.join('{} {}'.format(value, name) for name, value in periods if value)
		return time_string
	except Exception:
		return "Innumerable"

class GlobalPlugin(globalPluginHandler.GlobalPlugin):
	ScriptCategory=_("Password checker")
	passwords=[]
	inDialog=False
	password=""
	def __init__(self, *args, **kwargs):
		super(GlobalPlugin, self).__init__(*args, **kwargs)
		self.create_menu()

	def create_menu(self):
		self.menu=wx.Menu()
		# translators: option to load (or reload) the password list.
		self.load_password_list=self.menu.Append(wx.ID_ANY, _("&Load password list..."), _("Load the password list."))
		# translators: option to extend the password list
		self.extend_password_list=self.menu.Append(wx.ID_ANY, _("&Extend loaded password list..."), _("Extend the currently loaded password list with another set of passwords from a text file."))
		self.extend_password_list.Enable(False)
		# translators: option to unload the password list
		self.unload_password_list=self.menu.Append(wx.ID_ANY, _("&Unload password list..."), _("Unload the currently loaded password list."))
		self.unload_password_list.Enable(False)
		gui.mainFrame.sysTrayIcon.Bind(wx.EVT_MENU, self.on_load_password_list, self.load_password_list)
		gui.mainFrame.sysTrayIcon.Bind(wx.EVT_MENU, self.on_extend_password_list, self.extend_password_list)
		gui.mainFrame.sysTrayIcon.Bind(wx.EVT_MENU, self.on_unload_password_list, self.unload_password_list)
		# translators: sub-menu for this add-on in tools menu.
		self.password_checker_item=gui.mainFrame.sysTrayIcon.toolsMenu.AppendSubMenu(self.menu, _("&Password checker"), _("Check strength of passwords."))

	def terminate(self):
		del passwords
		self.menu.RemoveItem(self.load_password_list)
		self.load_password_list.Destroy()
		self.load_password_list=None
		self.menu.RemoveItem(self.extend_password_list)
		self.extend_password_list.Destroy()
		self.extend_password_list=None
		self.menu.RemoveItem(self.unload_password_list)
		self.unload_password_list.Destroy()
		self.unload_password_list=None
		gui.mainFrame.sysTrayIcon.toolsMenu.RemoveItem(self.password_checker_item)
		self.password_checker_item.Destroy()
		self.password_checker_item=None
		try:
			self.menu.Destroy()
		except wx.PyDeadObjectError:
			pass

	def on_load_password_list(self, evt):
		evt.Skip()
		self.load_password_list.Enable(False)
		self.extend_password_list.Enable(False)
		self.unload_password_list.Enable(False)
		if len(self.passwords)<1:
			# translators: strings to indicate the password list is being loaded.
			self.prog=gui.IndeterminateProgressDialog(gui.mainFrame, _("Loading password list"), _("Please wait while the password list is loaded."))
			gui.ExecAndPump(self._load)
			self.prog.done()
			del self.prog
			# translators: text displayed by NVDA when the password list is loaded.
			gui.messageBox(_("Password list loaded."), _("Finished"))
		else:
			# translators: strings to indicate the password list is being reloaded.
			self.prog=gui.IndeterminateProgressDialog(gui.mainFrame, _("Reloading password list"), _("Please wait while the password list is reloaded."))
			gui.ExecAndPump(self._reload)
			self.prog.done()
			del self.prog
			# translators: text displayed by NVDA when the password list is reloaded.
			gui.messageBox(_("Password list reloaded."), _("Finished"))
		self.load_password_list.Enable(True)
		self.extend_password_list.Enable(True)
		self.unload_password_list.Enable(True)

	def _load(self):
		try:
			for root, dirs, files in os.walk(os.path.dirname(__file__)+"\\SecLists\\Passwords"):
				for file in files:
					if file.endswith(".txt"):
						with open(os.path.join(root, file), "r") as f:
							for line in f.read():
								self.passwords.append(line)
							f.close()
		except Exception as ex:
			logHandler.log.warning("{}; skipping load.".format(ex if not ex is None else "Unknown error"))
			pass
		zxcvbn.matching.add_frequency_lists({
			'extra_passwords': self.passwords
		})

	def _reload(self):
		self.passwords=[]
		try:
			for root, dirs, files in os.walk(os.path.dirname(__file__)+"\\SecLists\\Passwords"):
				for file in files:
					if file.endswith(".txt"):
						with open(os.path.join(root, file), "r") as f:
							for line in f.read():
								self.passwords.append(line)
							f.close()
		except Exception as ex:
			logHandler.log.warning("{}; skipping load.".format(ex if not ex is None else "Unknown error"))
			pass
		zxcvbn.matching.add_frequency_lists({
			'extra_passwords': self.passwords
		})

	def _load_list(file):
		try:
			with open(file, "r") as f:
				for line in f.read():
					self.passwords.append(line)
				f.close()
		except Exception as ex:
			logHandler.log.exception(ex+"; skipping load.")
			pass
		zxcvbn.matching.add_frequency_lists({
			"extra lists": self.passwords
		})

	def on_extend_password_list(self, evt):
		evt.Skip()
		if self.inDialog:
			# translators: text to indicate that another dialog is already open.
			gui.messageBox(_("Another dialog is already open; close it first!"), _("Cannot continue"))
			return
		self.load_password_list.Enable(False)
		self.extend_password_list.Enable(False)
		self.unload_password_list.Enable(False)
		# translators: the open file dialog for extending the password list.
		openfile=wx.FileDialog(parent=gui.mainFrame, message=_("Select a password list to append to the list of currently loaded passwords (currently {} passwords)".format(len(self.passwords))), defaultDir=_(""), defaultFile=_(""), wildcard=_("Password list files (*.txt)|.txt"), style=wx.FD_OPEN|wx.FD_FILE_MUST_EXIST|wx.FD_MULTIPLE)
		self.inDialog=True
		if openfile.ShowModal()==wx.ID_OK:
			self.inDialog=False
			# translators: strings to indicate the password list is being loaded.
			self.prog=gui.IndeterminateProgressDialog(gui.mainFrame, _("Loading password list"), _("Please wait while the password list is loaded."))
			gui.ExecAndPump(self._load_list, openfile.GetPath())
			self.prog.done()
			del self.prog
			# translators: text announced by NVDA when the password list is loaded.
			gui.messageBox(_("Password list loaded!"), _("Finished"))
		else:
			logHandler.log.error("Could not open password extender dialog")
		self.load_password_list.Enable(True)
		self.extend_password_list.Enable(True)
		self.unload_password_list.Enable(True)

	def on_unload_password_list(self, evt):
		evt.Skip()
		self.passwords=[]
		gui.messageBox(_("Password list unloaded."), _("Done"))
		self.extend_password_list.Enable(False)
		self.unload_password_list.Enable(False)

	def script_check_password_strength(self, gesture):
		if len(self.passwords)==0:
			# translators: message spoken when no password list is loaded.
			ui.message(_("You must loada password list."))
			return
		if self.inDialog:
			# translators: text to indicate that another dialog is already open.
			gui.messageBox(_("Another dialog is already open; close it first!"), _("Cannot continue"))
			return
		t=threading.Thread(target=self.get_pass)
		t.daemon=True
		t.start()

	def get_pass(self):
		# translators: edit box displayed when a password is neded.
		dlg = wx.TextEntryDialog(gui.mainFrame, _("Enter the password you'd like to check"), _("Enter password"))
		self.inDialog=True
		dlg.ShowModal()
		dlg.SetFocus()
		password=dlg.GetValue()
		dlg.Destroy()
		del dlg
		self.inDialog=False
		# translators: text announced by NVDA while checking your password.
		ui.message(_("One moment, checking your entered password."))
		self.password=password
		del password
		t=threading.Thread(target=self.get_strength)
		t.daemon=True
		t.start()

	def get_strength(self):
		if len(self.password)<1:
			# translators: message displayed when no input was found.
			gui.messageBox(_("You must enter a password."), _("Error"))
			return
		if self.password in self.passwords:
			# translators: message displayed when password is found in password list.
			gui.messageBox(_("Your password was found in the loaded password list! If you use this password for anything, you are strongly advised to change it immediately!"), _("Alert!"))
			return
		passdata=zxcvbn.zxcvbn(self.password)
		# translators: various score messages for password grading. Score 0 is there for sanity cases.
		scoremsg=""
		if passdata["score"]==0:
			scoremsg=_("Your password is so week that it would be pretty much instantaneous to crack.")
		elif passdata["score"]==1:
			scoremsg=_("Your password earned a score of 1 (very weak/too guessable). It would take roughly less than 10^3 guesses to determine it.")
		elif passdata["score"]==2:
			scoremsg=_("Your password earned a score of 2 (very guessable). This means that, while it has protection against throttled online attacks, it would still take roughly less than 10^6 guesses to determine it.")
		elif passdata["score"]==3:
			scoremsg=_("Your password earned a score of 3 (somewhat guessable). This means that, while it has protection against unthrottled online attacks, it would still only require roughly less than 10^8 guesses to determine it.")
		elif passdata["score"]==4:
			scoremsg=_("Your password earned a score of 4 (very unguessable). This is the highest score you can get. This means your password has moderate protection from offline slow-hash scenarios, and would require roughly greator than 10^10 guesses to determine it.")
		# translators: feedback messages (in zxcvbn, not in this add-on). Translation may not be possible.
		feedback=[]
		if len(passdata["feedback"]["warning"])==0 and len(passdata["feedback"]["suggestions"])==0:
			# translators: the message given when no feedback was available.
			feedback=_("No feedback given.")
		else:
			feedback=list()
			if len(passdata["feedback"]["warning"])==0:
				feedback.append("Warnings: none")
			else:
				feedback.append("Warnings: {}".format(passdata["feedback"]["warning"]))
			if len(passdata["feedback"]["suggestions"])==0:
				feedback.append("Suggestions: none")
			else:
				msg="Suggestions: "
				for suggestion in passdata["feedback"]["suggestions"]:
					msg+="<br>{}".format(suggestion)
				feedback.append(msg)
		# translators: The browseable HTML document containing the password strength information.
		ui.browseableMessage(_("""<h1>Password strength report</h1>
<p>Password calculation time: {}</p>
<h2>Score</h2>
<p>{}</p>
<h2>Termonology used in this report</h2>
<p>If you already know this termonology, skip this section.</p>
<dl>
<dt>Throttling</dt>
<dd>A process responsible for regulating the rate at which application processing is conducted, either statically or dynamically. For example, in high throughput processing scenarios, as may be common in online transactional processing (OLTP) architectures, a throttling controller may be embedded in the application hosting platform to balance the application's outbound publishing rates with its inbound consumption rates, optimize available system resources for the processing profile, and prevent eventually unsustainable consumption. In something like an enterprise application integration (EAI) architecture, a throttling process may be built into the application logic to prevent an expectedly slow end-system from becoming overloaded as a result of overly aggressive publishing from the middleware tier.</dd>
</dl>
<h2>Scenarios</h2>
<ul>
<li>Online attack on a service that ratelimits password auth attempts (100/hr): {}</li>
<li>Online attack on a service that doesn't ratelimit, or where an attacker has outsmarted ratelimiting: {}</li>
<li>Offline attack, assuming multiple attackers, proper user-unique salting, and a slow hash function w/ moderate work factor, such as bcrypt, scrypt, PBKDF2: {}</li>
<li>offline attack with user-unique salting but a fast hash function like SHA-1, SHA-256 or MD5, with a wide range of reasonable numbers anywhere from one billion - one trillion guesses per second, depending on number of cores and machines, and ballparking at 10B/sec: {}</li>
</ul>
<h2>Feedback</h2>
<p>{}</p>""".format(passdata["calc_time"], scoremsg, GetTime(passdata["crack_times_seconds"]["online_throttling_100_per_hour"]), GetTime(passdata["crack_times_seconds"]["online_no_throttling_10_per_second"]), GetTime(passdata["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"]), GetTime(passdata["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"]), "<br>".join(feedback) if type(feedback)==list else feedback)), "Password strength report", True)
		self.password=""
		return

	def script_generate_password(self, gesture):
		if self.inDialog:
			# translators: text to indicate that another dialog is already open.
			gui.messageBox(_("Another dialog is already open; close it first!"), _("Cannot continue"))
			return
		t=threading.Thread(target=self.gen_passwd)
		t.daemon=True
		t.start()

	def gen_passwd(self):
		length=None
		try:
			# translators: dialog display text for password generation.
			dlg = wx.TextEntryDialog(gui.mainFrame, _("Enter the length of the password you'd like to generate:"), _("Enter length"))
			self.inDialog=True
			dlg.ShowModal()
			dlg.SetFocus()
			length=int(dlg.GetValue())
			dlg.Destroy()
			del dlg
			self.inDialog=False
		except Exception as ex:
			logHandler.log.warning("{}; bailing out.".format(ex if ex is not None else "Unknown error"))
			# translators: message displayed to user when a non-integral number is found.
			gui.messageBox(_("Please enter an integer."), _("Error"))
		symbols = string.printable.strip()
		# translators: generated password. Do not translate.
		ui.browseableMessage(_(''.join([symbols[x * len(symbols) / 256] for x in struct.unpack('%dB' % (length,), os.urandom(length))])), _("Generated Password"), False)
		return
	__gestures={
		"kb:control+shift+NVDA+z": "check_password_strength",
		"kb:control+shift+NVDA+g": "generate_password"
	}
