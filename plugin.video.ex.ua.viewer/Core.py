'''
    Ex.Ua.Viewer plugin for XBMC
    Copyright (C) 2011 Vadim Skorba
	vadim.skorba@gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
	
	
'''

import Localization
import sys
import os
import xbmc
import xbmcaddon
import xbmcgui
import xbmcplugin
import urllib
import urllib2
import cookielib
import re
import tempfile
from htmlentitydefs import name2codepoint

class Core:
	__plugin__ = sys.modules[ "__main__"].__plugin__
	__settings__ = sys.modules[ "__main__" ].__settings__
	URL = "http://www.ex.ua"
	USERAGENT = "Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.0"
	ROWCOUNT = (15, 30, 50, 100)[int(__settings__.getSetting("rowcount"))]
	LANGUAGE = ('ru', 'uk', 'en')[int(__settings__.getSetting("language"))]
	ROOT = sys.modules[ "__main__"].__root__
	localization = ()
	htmlCodes = (
		('&', '&amp;'),
		('<', '&lt;'),
		('>', '&gt;'),
		('"', '&quot;'),
		("'", '&#39;'),
	)
	stripPairs = (
		('<p>', '\n'),
		('<li>', '\n'),
		('<br>', '\n'),
		('<.+?>', ' '),
		('</.+?>', ' '),
		('&nbsp;', ' '),
	)

	def __init__(self, localization):
		self.localization = localization

	def localize(self, text):
		try:
			return self.localization[self.LANGUAGE][text]
		except:
			return text

	def sectionMenu(self):
		sections = self.fetchData("%s/%s/video" % (self.URL, self.LANGUAGE))
		for (link, sectionName, count) in re.compile("<a href='(/view/.+?)'><b>(.+?)</b></a><p><a href='/view/.+?' class=info>.+?: (\d+)</a>").findall(sections):
			self.drawItem(sectionName + ' (' + count + ')', 'openSection', self.URL + link)
		self.drawItem(self.localize('< Search User Page >'), 'searchUser', image=self.ROOT + '/icons/search_user.png')
		if self.__settings__.getSetting("auth"):
			self.drawItem(self.localize('< User Bookmarks >'), 'openSearch', self.URL + '/buffer', self.ROOT + '/icons/bookmarks.png')
			self.drawItem(self.localize('< User Logout >'), 'logoutUser', image=self.ROOT + '/icons/logout.png')
		else:
			self.drawItem(self.localize('< User Login >'), 'loginUser', image=self.ROOT + '/icons/login.png')
		self.lockView(50)
		xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)

	def openSection(self, params = {}):
		get = params.get
		url = urllib.unquote_plus(get("url"))
		self.drawItem(self.localize('< Search >'), 'openSearch', re.search("/view/(\d+)", url).group(1), self.ROOT + '/icons/search.png')
		if 'True' == get("contentReady"):
			videos = self.__settings__.getSetting("lastContent")
			if 0 == len(re.compile(">(.+?)?<a href='([\w\d\?=&/_,]+)'><b>(.+?)</b>.+?</small><p>(.*?)&nbsp;").findall(videos)):
				videos = self.fetchData(url)
		else:
			videos = self.fetchData(url)
		for (image, link, title, comments) in re.compile(">(.+?)?<a href='(/view[\w\d\?=&/_,]+)'><b>(.+?)</b>.+?</small><p>(.*?)&nbsp;").findall(videos):
			image = re.compile("<img src='(.+?)\?\d+'.+?></a><p>").search(image)
			if image:
				image = image.group(1)
			else:
				image = ''
			if comments:
				comments = " [%s]" % re.sub('.+?>(.+?)</a>', '\g<1>', comments)
			contextMenu = [
				(
					self.localize('Search Like That'),
					'XBMC.Container.Update(%s)' % ('%s?action=%s&url=%s&like=%s' % (sys.argv[0], 'openSearch', re.search("/view/(\d+)", url).group(1), urllib.quote_plus(self.unescape(title))))
				)
			]
			self.drawItem(self.unescape(title + comments), 'openPage', self.URL + link, image + '?200', contextMenu=contextMenu)
		self.drawPaging(videos, 'openSection')
		self.lockView(51)
		xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)

	def openSearch(self, params = {}):
		get = params.get
		if re.match('\d+', get("url")):
			try:
				keyboard = xbmc.Keyboard(urllib.unquote_plus(get("like")), self.localize("Edit Line For Searching:"))
			except:
				keyboard = xbmc.Keyboard('', self.localize("Input Search Phrase:"))
			keyboard.doModal()
			query = keyboard.getText()
			if keyboard.isConfirmed() and query:
				url = '%s/search?original_id=%s&s=%s' % (self.URL, get("url"), urllib.quote_plus(query))
			else:
				return
		else:
			url = urllib.unquote_plus(get("url"))
		videos = self.fetchData(url)
		for (image, link, title, comments) in re.compile(">(.+?)?<a href='(/view[\w\d\?=&/_,]+)'><b>(.+?)</b>(.+?)</td>", re.DOTALL).findall(videos):
			image = re.compile("<img src='(.+?)\?\d+'.+?></a>").search(image)
			if image:
				image = image.group(1)
			else:
				image = ''
			comments = re.search("<a href='/view_comments.+?>(.+?)</a>", comments)
			if comments:
				title = "%s [%s]" % (title, comments.group(1))
			self.drawItem(self.unescape(title), 'openPage', self.URL + link, image + '?200')
		self.drawPaging(videos, 'openSearch')
		self.lockView(51)
		xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)

	def searchUser(self, params = {}):
		keyboard = xbmc.Keyboard("", self.localize("Input Search Username:"))
		keyboard.doModal()
		query = keyboard.getText()
		if not query:
			return
		elif keyboard.isConfirmed():
			params["url"] = self.URL + '/user/' + query
			self.openSearch(params)

	def createPlaylist(self, playlist, content, flv = True):
		xbmc.executebuiltin("Action(Stop)")
		resultPlaylist = xbmc.PlayList(xbmc.PLAYLIST_VIDEO)
		resultPlaylist.clear()
		image = re.compile("<img src='(.+?\.jpg)\?800'.+?>").search(content).group(1) + '?200'
		for episode in playlist:
			episodeName = re.compile("<a href='(/get/" + episode + ")' .*?>(.*?)</a>").search(content)
			if episodeName:
				listitem = xbmcgui.ListItem(self.unescape(self.stripHtml(episodeName.group(2))), iconImage=image, thumbnailImage=image)
				if flv:
					episodeName = re.compile("\"url\": \"http://www.ex.ua(/show/%s/[abcdef0-9]+.flv)\"" % episode).search(content)
				resultPlaylist.add(self.URL + episodeName.group(1), listitem)
		if 1 == resultPlaylist.size():
			player = xbmc.Player(xbmc.PLAYER_CORE_AUTO)
			player.play(resultPlaylist)
		else:
			xbmc.executebuiltin("Action(Playlist)")

	def playM3U(self):
		content = self.__settings__.getSetting("lastContent")
		if content:
			m3uPlaylistUrl = re.compile(".*<a href='(.*?).m3u' rel='nofollow'><b>.*</b></a>").search(content)
			if m3uPlaylistUrl:
				m3uPlaylist = re.compile(".*/get/(\d+).*").findall(self.fetchData(self.URL + m3uPlaylistUrl.group(1) + '.m3u'))
				if m3uPlaylist:
					self.createPlaylist(m3uPlaylist, content, False)

	def playFLV(self):
		content = self.__settings__.getSetting("lastContent")
		if content:
			flvPlaylist = re.compile("\"url\": \"http://www.ex.ua/show/(\d+)/[abcdef0-9]+.flv\"").findall(content)
			if flvPlaylist:
				self.createPlaylist(flvPlaylist, content)

	def showDetails(self, params = {}):
		xbmc.executebuiltin("Action(Info)")
		if self.__settings__.getSetting("skin_optimization"):
			xbmc.executebuiltin("ActivateWindow(1113)")
			xbmc.executebuiltin("Action(Right)")

	def openPage(self, params = {}):
		get = params.get
		content = self.fetchData(urllib.unquote_plus(get("url")))
		self.__settings__.setSetting("lastContent", content)
		filelist = re.compile("<a href='/filelist/(\d+).urls' rel='nofollow'>").search(content)
		details = re.compile(">(.+?)?<h1>(.+?)</h1>(.+?)</td>", re.DOTALL).search(content)
		if details and filelist:
			if re.compile("\"url\": \"http://www.ex.ua/show/\d+/[abcdef0-9]+.flv\"").search(content):
				self.drawItem(self.localize('FLV Playlist'), 'playFLV', '', self.ROOT + '/icons/flash.png', False)
			if re.compile(".*<a href='.*?.m3u' rel='nofollow'><b>.*</b></a>").search(content):
				self.drawItem(self.localize('M3U Playlist'), 'playM3U', '', self.ROOT + '/icons/video.png', False)
			image = re.compile("<img src='(http.+?\?800)'").search(details.group(1))
			if image:
				image = image.group(1)
			else:
				image = ''
			title = details.group(2)
			description = "-----------------------------------------------------------------------------------------\n"
			description += self.localize('\n[B]:::Description:::[/B]\n')
			description += details.group(3).replace('смотреть онлайн', '')
			comments = re.compile("<a href='(/view_comments/\d+).+?(\d+)</a>").search(content)
			if comments:
				description += self.localize('[B]:::Comments:::[/B]\n\n')
				commentsContent = self.fetchData(self.URL + comments.group(1))
				for (commentTitle, comment) in re.compile("<a href='/view_comments/\d+'><b>(.+?)</b>.+?<p>(.+?)<p>", re.DOTALL).findall(commentsContent):
					description += "[B]%s[/B]%s" % (commentTitle, comment)
				listitem = xbmcgui.ListItem(self.localize('Description &\nComments') + ' [%s]' % comments.group(2), iconImage=self.ROOT + '/icons/description.png')
			else:
				listitem = xbmcgui.ListItem(self.localize('Description &\nComments') + ' [0]', iconImage=self.ROOT + '/icons/description.png')
			description += "-----------------------------------------------------------------------------------------\n\n\n\n\n\n\n"
			listitem.setInfo(type = 'Video', infoLabels = {
				"Title": 		self.unescape(self.stripHtml(title)),
				"Plot": 		self.unescape(self.stripHtml(description)) } )
			url = '%s?action=%s' % (sys.argv[0], 'showDetails')
			xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]), url=url, listitem=listitem, isFolder=True)
			if self.__settings__.getSetting("auth"):
				self.drawItem(self.localize('Leave\nComment'), 'leaveComment', filelist.group(1), self.ROOT + '/icons/comment.png', False)
			self.lockView(53)
			xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)
		else:
			url = '%s?action=%s&url=%s&contentReady=True' % (sys.argv[0], 'openSection', get("url"))
			xbmc.executebuiltin("Container.Update(%s)" % url)

	def drawPaging(self, videos, action):
		next = re.compile("<td><a href='([\w\d\?=&/_]+)'><img src='/t2/arr_r.gif'").search(videos)
		pages = re.compile("<font color=#808080><b>(\d+\.\.\d+)</b>").search(videos)
		if next:
			self.drawItem('[%s] ' % pages.group(1) + self.localize('Next >>'), action, self.URL + next.group(1), self.ROOT + '/icons/next.png')

	def drawItem(self, title, action, link = '', image=None, isFolder = True, contextMenu=None):
		listitem = xbmcgui.ListItem(title, iconImage=image, thumbnailImage=image)
		url = '%s?action=%s&url=%s' % (sys.argv[0], action, urllib.quote_plus(link))
		if contextMenu:
			listitem.addContextMenuItems(contextMenu)
		if isFolder:
			listitem.setProperty("Folder", "true")
		else:
			listitem.setInfo(type = 'Video', infoLabels = {"Title":title})
		xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]), url=url, listitem=listitem, isFolder=isFolder)

	
	def leaveComment(self, params = {}):
		get = params.get
		if re.match('\d+', get("url")) and self.__settings__.getSetting("auth"):
			content = self.fetchData(self.URL + '/edit?original_id=' + get("url") + '&link_id=2')
			commentId = re.compile("<form name=edit method=post action='/edit/(\d+)'>").search(content).group(1)
			
			if re.match('\d+', commentId):
				keyboardTitle = xbmc.Keyboard(self.localize("Sent from XBMC"), self.localize("Enter Message Title:"))
				keyboardTitle.doModal()
				title = keyboardTitle.getText()

				keyboardText = xbmc.Keyboard("", self.localize("Enter Message Text:"))
				keyboardText.doModal()
				text = keyboardText.getText()
				if not text:
					return

				request = urllib2.Request(self.URL + '/r_edit/' + commentId, urllib.urlencode({'avatar_id' : 0, 'post' : text, 'public' : -1, 'title' : title}))
				request.add_header('Cookie', self.__settings__.getSetting("auth"))
				try:
					connection = urllib2.urlopen(request)
					result = connection.read()
					connection.close()
					if '1' == result:
						xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Commenting'), self.localize('Message sent successfully')))
						xbmc.executebuiltin("Container.Refresh()")
					else:
						xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Commenting'), self.localize('Message not sent')))
				except urllib2.HTTPError, e:
					print self.__plugin__ + " fetchData(" + url + ") exception: " + str(e)
					return
		else:
			return

	def loginUser(self):
		if self.__settings__.getSetting("auth"):
			xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Auth'), self.localize('Already logged in')))
			return

		xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=False)
		keyboardUser = xbmc.Keyboard("", self.localize("Input Username:"))
		keyboardUser.doModal()
		username = keyboardUser.getText()
		if not username:
			return

		keyboardPass = xbmc.Keyboard("", self.localize("Input Password:"))
		keyboardPass.setHiddenInput(True)
		keyboardPass.doModal()
		password = keyboardPass.getText()
		keyboardPass.setHiddenInput(False)
		if not password:
			return

		content = self.fetchData(self.URL + '/login')
		captcha = re.compile("<img src='/captcha\?captcha_id=(\d+)'").search(content)
		if captcha:
			urllib.URLopener().retrieve(self.URL + '/captcha?captcha_id=' + captcha.group(1), tempfile.gettempdir() + '/captcha.png')
			window = xbmcgui.Window(xbmcgui.getCurrentWindowId())
			image = xbmcgui.ControlImage(460, 20, 360, 160, tempfile.gettempdir() + '/captcha.png')
			window.addControl(image)
			keyboardCaptcha = xbmc.Keyboard("", self.localize("Input symbols from CAPTCHA image:"))
			keyboardCaptcha.doModal()
			captchaText = keyboardCaptcha.getText()
			captchaId = captcha.group(1)
			window.removeControl(image)
			if not captchaText:
				return
		else:
			captchaText = captchaId = ''

		try:
			cookieJar = cookielib.CookieJar()
			opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookieJar))
			data = urllib.urlencode({
				'login': username, 'password': password, 'flag_permanent': 1,
				'captcha_value': captchaText, 'captcha_id': captchaId
			})
			value = opener.open(self.URL + "/login", data).read()
			if re.compile("<a href='/logout'>Выход</a>").search(value):
				xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Auth'), self.localize('Login successfull')))
				for cookie in cookieJar:
					if cookie.name == 'ukey':
						self.__settings__.setSetting("auth", 'ukey=' + cookie.value)
			else:
				xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Auth'), self.localize('Login failed')))
				self.loginUser()
		except urllib2.HTTPError, e:
			print self.__plugin__ + " loginUser() exception: " + str(e)
		xbmc.executebuiltin("Container.Refresh()")

	def logoutUser(self):
		if not self.__settings__.getSetting("auth"):
			xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Auth'), self.localize('User not logged in')))
			return

		self.__settings__.setSetting("auth", '')
		xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Auth'), self.localize('User successfully logged out')))
		xbmc.executebuiltin("Container.Refresh()")

	def executeAction(self, params = {}):
		get = params.get
		if (get("action") == "openSection"):
			self.openSection(params)
		elif (get("action") == "openPage"):
			self.openPage(params)
		elif (get("action") == "openSearch"):
			self.openSearch(params)
		elif (get("action") == "searchUser"):
			self.searchUser(params)
		elif (get("action") == "playM3U"):
			self.playM3U()
		elif (get("action") == "playFLV"):
			self.playFLV()
		elif (get("action") == "showDetails"):
			self.showDetails(params)
		elif (get("action") == "loginUser"):
			self.loginUser()
		elif (get("action") == "logoutUser"):
			self.logoutUser()
		elif (get("action") == "leaveComment"):
			self.leaveComment(params)
		else:
			self.sectionMenu()

	def fetchData(self, url):
		request = urllib2.Request(url)
		request.add_header('User-Agent', self.USERAGENT)
		if self.__settings__.getSetting("auth"):
			authString = '; ' + self.__settings__.getSetting("auth")
		else:
			authString = ''
		request.add_header('Cookie', 'uper=' + str(self.ROWCOUNT) + authString)
		try:
			connection = urllib2.urlopen(request)
			result = connection.read()
			connection.close()
			return (result)
		except urllib2.HTTPError, e:
			print self.__plugin__ + " fetchData(" + url + ") exception: " + str(e)
			return

	def lockView(self, viewId):
		if self.__settings__.getSetting("lock_view"):
			xbmc.executebuiltin("Container.SetViewMode(%s)" % str(viewId))

	def getParameters(self, parameterString):
		commands = {}
		splitCommands = parameterString[parameterString.find('?')+1:].split('&')
		for command in splitCommands: 
			if (len(command) > 0):
				splitCommand = command.split('=')
				name = splitCommand[0]
				value = splitCommand[1]
				commands[name] = value
		return commands

	def unescape(self, string):
		for (symbol, code) in self.htmlCodes:
			string = re.sub(code, symbol, string)
		return string

	def stripHtml(self, string):
		for (html, replacement) in self.stripPairs:
			string = re.sub(html, replacement, string)
		return string
