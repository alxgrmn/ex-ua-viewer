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
import xbmc
import xbmcaddon
import xbmcgui
import xbmcplugin
import urllib
import urllib2
import cookielib
import re
import os
import tempfile
from BeautifulSoup import BeautifulSoup

class Core:
	__plugin__ = sys.modules[ "__main__"].__plugin__
	__settings__ = sys.modules[ "__main__" ].__settings__
	URL = 'http://www.ex.ua'
	URL_SECURE = 'https://www.ex.ua'
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
	skinOptimizations = (
		{#Confluence
			'list': 50,
			'info': 50,
			'icons': 500,
		},
		{#Transperency!
			'list': 50,
			'info': 51,
			'icons': 53,
		}
	)
	
	# Private and system methods
	def __init__(self, localization):
		self.localization = localization
		if 'true' == self.__settings__.getSetting("usegate"):
			self.URL = 'http://fex.net'
		if 'true' == self.__settings__.getSetting("useproxy"):
			self.URL = 'http://uaproxy.com/index.php?hl=2e7&q=http%3A%2F%2Fwww.ex.ua'

	def localize(self, text):
		try:
			return self.localization[self.LANGUAGE][text]
		except:
			return text

	def createPlaylist(self, playlist, content, flv = True):
		xbmc.executebuiltin("Action(Stop)")
		resultPlaylist = xbmc.PlayList(xbmc.PLAYLIST_VIDEO)
		resultPlaylist.clear()
		image = re.compile("<img.*?src='(.+?\.jpg)\?800'.+?>").search(content)
		if image:
			image = image.group(1) + '?200'
		else:
			image = self.ROOT + '/icons/video.png'
		for episode in playlist:
			episodeName = re.compile("([^'\" ]+get(?:%2F|/)" + episode + ").*?>(.*?)</a>").search(content)
			if episodeName:
				listitem = xbmcgui.ListItem(self.unescape(self.stripHtml(episodeName.group(2))), iconImage=image, thumbnailImage=image)
				if flv:
					episodeName = re.compile("\"url\": \"http://www.ex.ua(/show/%s/[abcdef0-9]+.flv)\"" % episode).search(content)
				resultPlaylist.add(self.formUrl(episodeName.group(1)), listitem)
		if 1 == resultPlaylist.size():
			player = xbmc.Player(xbmc.PLAYER_CORE_AUTO)
			player.play(resultPlaylist)
		else:
			xbmc.executebuiltin("ActivateWindow(VideoPlaylist)")

	def drawPaging(self, videos, action):
		nextButton = re.compile("<td><a href='([\w\d\?=&/_]+)'><img src='/t3/arr_r.gif'").search(videos)
		pages = re.compile("<font color=#808080><b>(\d+\.\.\d+)</b>").search(videos)
		if nextButton:
			self.drawItem('[%s] ' % pages.group(1) + self.localize('Next >>'), action, self.URL + nextButton.group(1), self.ROOT + '/icons/next.png')

	def drawItem(self, title, action, link = '', image=ROOT + '/icons/video.png', isFolder = True, contextMenu=None):
		listitem = xbmcgui.ListItem(title, iconImage=image, thumbnailImage=image)
		url = '%s?action=%s&url=%s' % (sys.argv[0], action, urllib.quote_plus(link))
		if contextMenu:
			listitem.addContextMenuItems(contextMenu)
		if isFolder:
			listitem.setProperty("Folder", "true")
		else:
			listitem.setInfo(type = 'Video', infoLabels = {"Title":title})
		xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]), url=url, listitem=listitem, isFolder=isFolder)

	def formUrl(self, url):
		if re.search("^/", url):
			url = self.URL + url
		if re.search("uaproxy", url):
			url = url + '&hl=2e7'

		return url
	
	def fetchData(self, url):
		url = self.formUrl(url)
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
		if 'true' == self.__settings__.getSetting("lock_view"):
			try:
				xbmc.executebuiltin("Container.SetViewMode(%s)" % str(self.skinOptimizations[int(self.__settings__.getSetting("skin_optimization"))][viewId]))
			except:
				return

	def getParameters(self, parameterString):
		commands = {}
		splitCommands = parameterString[parameterString.find('?')+1:].split('&')
		for command in splitCommands: 
			if (len(command) > 0):
				splitCommand = command.split('=')
				name = splitCommand[0]
				value = ''
				if len(splitCommand) == 2:
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
		
	# Executable actions methods
	def executeAction(self, params = {}):
		get = params.get
		if hasattr(self, get("action")):
			getattr(self, get("action"))(params)
		else:
			self.sectionMenu()

	def sectionMenu(self):
		sections = self.fetchData("/%s/video" % (self.LANGUAGE))
		soup = BeautifulSoup(sections)
		for section in soup.find('table', {'class': 'include_0'}).findAll('td', {'align': 'center', 'valign': 'center'}):
			link = section.a.get('href')
			sectionName = section.b.string.encode('utf8')
			count = re.sub('^.+?(\d+)$', '\g<1>', section.p.a.string.encode('utf8'))
			# Remove megogo category
			if re.compile("/17031949\?").search(link):
				continue
			self.drawItem(sectionName + ' (' + count + ')', 'openSection', link)
		self.drawItem(self.localize('< Search Everywhere >'), 'searchAll', image=self.ROOT + '/icons/search.png')
		self.drawItem(self.localize('< Search User Page >'), 'searchUser', image=self.ROOT + '/icons/search_user.png')
		if self.__settings__.getSetting("auth"):
			self.drawItem(self.localize('< User Bookmarks >'), 'openSearch', '/buffer', self.ROOT + '/icons/bookmarks.png')
			self.drawItem(self.localize('< User Logout >'), 'logoutUser', image=self.ROOT + '/icons/logout.png')
		else:
			self.drawItem(self.localize('< User Login >'), 'loginUser', image=self.ROOT + '/icons/login.png')
		self.lockView('list')
		xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)

	def openSection(self, params = {}):
		get = params.get
		url = urllib.unquote_plus(get("url"))
		if 'True' == get("contentReady"):
			videos = self.__settings__.getSetting("lastContent")
			soup = BeautifulSoup(videos)
			if 0 == len(soup.find('table', {'class': 'include_0'}).findAll('td', {'align': 'center', 'valign': 'center'})):
				videos = self.fetchData(url)
		else:
			videos = self.fetchData(url)
		originalId = re.search("<input type=hidden name=original_id value='(\d+)'>", videos)
		if originalId and originalId.group(1):
			self.drawItem(self.localize('< Search >'), 'openSearch', originalId.group(1), self.ROOT + '/icons/search.png')
		else:
			self.drawItem(self.localize('< Search >'), 'openSearch', re.search("(\d+)$", url).group(1), self.ROOT + '/icons/search.png')
		soup = BeautifulSoup(videos)
		for video in soup.find('table', {'class': 'include_0'}).findAll('td', {'align': 'center', 'valign': 'center'}):
			link = video.p.a.get('href')
			image = video.a.img.get('src')
			title = video.p.a.b.string.encode('utf8')
			if video.find('a', {'class': 'info'}):
				title = "%s [%s]" % (title, video.find('a', {'class': 'info'}).string.encode('utf8'))
			contextMenu = [
				(
					self.localize('Search Like That'),
					'XBMC.Container.Update(%s)' % ('%s?action=%s&url=%s&like=%s' % (sys.argv[0], 'openSearch', re.search("(\d+)$", url).group(1), urllib.quote_plus(self.unescape(title))))
				)
			]
			self.drawItem(self.unescape(title), 'openPage', link, image, contextMenu=contextMenu)
		self.drawPaging(videos, 'openSection')
		self.lockView('info')
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
				url = '/search?original_id=%s&s=%s' % (re.search("(\d+)$", get("url")).group(1), urllib.quote_plus(query))
			else:
				return
		else:
			url = urllib.unquote_plus(get("url"))
		videos = self.fetchData(url)
		soup = BeautifulSoup(videos)
		for video in soup.find('table', {'class': 'panel'}).findAll('td'):
			if not video.contents[1].b:
				continue
			link = video.a.get('href')
			image = video.a.img.get('src')
			title = video.contents[1].b.string.encode('utf8')
			if video.find('a', {'class': 'info'}):
				title = "%s [%s]" % (title, video.find('a', {'class': 'info'}).string.encode('utf8'))
			self.drawItem(self.unescape(title), 'openPage', link, image)
		self.drawPaging(videos, 'openSearch')
		self.lockView('info')
		xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)

	def searchAll(self, params = {}):
		keyboard = xbmc.Keyboard("", self.localize("Input Search Phrase:"))
		keyboard.doModal()
		query = keyboard.getText()
		if not query:
			return
		elif keyboard.isConfirmed():
			params["url"] = urllib.quote_plus('/search?s=' + query)
			self.openSearch(params)

	def searchUser(self, params = {}):
		keyboard = xbmc.Keyboard("", self.localize("Input Search Username:"))
		keyboard.doModal()
		query = keyboard.getText()
		if not query:
			return
		elif keyboard.isConfirmed():
			params["url"] = '/user/' + query
			self.openSearch(params)
	
	def leaveComment(self, params = {}):
		get = params.get
		if re.match('\d+', get("url")) and self.__settings__.getSetting("auth"):
			content = self.fetchData('/edit?original_id=' + get("url") + '&link_id=2')
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

				request = urllib2.Request('/r_edit/' + commentId, urllib.urlencode({'avatar_id' : 0, 'post' : text, 'public' : -1, 'title' : title}))
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
					print self.__plugin__ + " leaveComment() exception: " + str(e)
					return
		else:
			return

	def loginUser(self, params = {}):
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

		content = self.fetchData(self.URL_SECURE + '/login')
		captcha = re.compile("<img src='/captcha\?captcha_id=(\d+)'").search(content)
		if captcha:
			urllib.URLopener().retrieve(self.URL_SECURE + '/captcha?captcha_id=' + captcha.group(1), tempfile.gettempdir() + '/captcha.png')
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
			value = opener.open(self.URL_SECURE + "/login", data).read()
			if re.compile("<a href='/logout'>").search(value):
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

	def logoutUser(self, params = {}):
		if not self.__settings__.getSetting("auth"):
			xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Auth'), self.localize('User not logged in')))
			return

		self.__settings__.setSetting("auth", '')
		xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Auth'), self.localize('User successfully logged out')))
		xbmc.executebuiltin("Container.Refresh()")

	def playM3U(self, params = {}):
		content = self.__settings__.getSetting("lastContent")
		if content:
			m3uPlaylistUrl = re.compile("([^'\" ]+).m3u").search(content)
			if m3uPlaylistUrl:
				m3uPlaylist = re.compile(".*/get/(\d+).*").findall(self.fetchData(m3uPlaylistUrl.group(1) + '.m3u'))
				if m3uPlaylist:
					self.createPlaylist(m3uPlaylist, content, False)

	def playFLV(self, params = {}):
		content = self.__settings__.getSetting("lastContent")
		if content:
			flvPlaylist = re.compile("\"url\": \"http://www.ex.ua/show/(\d+)/[abcdef0-9]+.flv\"").findall(content)
			if flvPlaylist:
				self.createPlaylist(flvPlaylist, content)

	def showDetails(self, params = {}):
		xbmc.executebuiltin("Action(Info)")
		if '1' == self.__settings__.getSetting("skin_optimization"):#Transperency
			xbmc.executebuiltin("ActivateWindow(1113)")
			xbmc.executebuiltin("Action(Right)")
		if '0' == self.__settings__.getSetting("skin_optimization"):#Confluence
			xbmc.executebuiltin("Action(Up)")

	def openPage(self, params = {}):
		get = params.get
		content = self.fetchData(urllib.unquote_plus(get("url")))
		self.__settings__.setSetting("lastContent", content)
		soup = BeautifulSoup(content)
		artistMenu = re.compile("<div class=\"pg_menu\">.*?<a.+?</a>.*?<a(.+?)>.+?</div>", re.DOTALL).search(content)
		if artistMenu:
			if re.compile("class=\"active\"").search(artistMenu.group(1)):
				pass
			else:
				anchor = re.compile("href=\"(/view/\d+)\"").search(artistMenu.group(1))
				if anchor.group(1):
					params['url'] = urllib.quote_plus(anchor.group(1))
					return self.openPage(params)

		filelist = re.compile("(\d+).urls").search(soup.find('td', {'colspan': 3, 'valign': 'bottom'}).a.get('href'))
		details = re.compile(">(.+?)?<h1>(.+?)</h1>(.+?)</td>", re.DOTALL).search(content)
		if details and filelist:
			if re.compile("\"url\": \"http://www.ex.ua/show/\d+/[abcdef0-9]+.flv\"").search(content):
				self.drawItem(self.localize('FLV Playlist'), 'playFLV', '', self.ROOT + '/icons/flash.png', False)
			if re.compile("[^'\" ].m3u").search(content):
				self.drawItem(self.localize('M3U Playlist'), 'playM3U', '', self.ROOT + '/icons/video.png', False)
			image = re.compile("<img src='(http.+?\?800)'").search(details.group(1))
			if image:
				image = image.group(1)
			else:
				image = self.ROOT + '/icons/video.png'
			title = details.group(2)
			description = "-----------------------------------------------------------------------------------------\n"
			description += self.localize('\n[B]:::Description:::[/B]\n')
			description += details.group(3).replace('смотреть онлайн', '')
			comments = re.compile("<a href='(/view_comments/\d+).+?(\d+)</a>").search(content)
			if comments:
				description += self.localize('[B]:::Comments:::[/B]\n\n')
				commentsContent = self.fetchData(comments.group(1))
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
				self.drawItem(self.localize('To My\nPage'), 'toMyPage', filelist.group(1), self.ROOT + '/icons/add_to_user_page.png', False)
				self.drawItem(self.localize('To My\nBookmarks'), 'toBookmarks', filelist.group(1), self.ROOT + '/icons/add_bookmark.png', False)
			self.lockView('icons')
			xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)
		else:
			url = '%s?action=%s&url=%s&contentReady=True' % (sys.argv[0], 'openSection', get("url"))
			xbmc.executebuiltin("Container.Update(%s)" % url)

	def toMyPage(self, params = {}):
		get = params.get
		self.addLink(get("url"), 'page')

	def toBookmarks(self, params = {}):
		get = params.get
		self.addLink(get("url"), 'bookmark')

	def addLink(self, pageId, actionName):
		actions = {'page': 6, 'bookmark': 4}
		try:
			action = actions[actionName]
		except:
			action = actions['page']
		if re.match('\d+', pageId) and self.__settings__.getSetting("auth"):
			self.fetchData('/add_link/' + str(pageId) + '/?link_id=' + str(action))
			xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Item Saving'), self.localize('Item saved successfully')))
			xbmc.executebuiltin("Container.Refresh()")
		else:
			xbmc.executebuiltin("Notification(%s, %s, 2500)" % (self.localize('Item Saving'), self.localize('Item not saved')))
			xbmc.executebuiltin("Container.Refresh()")
