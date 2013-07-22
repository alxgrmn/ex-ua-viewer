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
import Localization
from BeautifulSoup import BeautifulSoup

class Parser:
	__plugin__ = sys.modules[ "__main__"].__plugin__
	__settings__ = sys.modules[ "__main__" ].__settings__
	URL = 'http://www.ex.ua'
	URL_SECURE = 'https://www.ex.ua'
	USERAGENT = "Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.0"
	ROWCOUNT = (15, 30, 50, 100)[int(__settings__.getSetting("rowcount"))]
	LANGUAGE = ('ru', 'uk', 'en')[int(__settings__.getSetting("language"))]
	ROOT = sys.modules[ "__main__"].__root__
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

	def createPlaylist(self, playlist, content, flv = True):
		xbmc.executebuiltin("Action(Stop)")
		resultPlaylist = xbmc.PlayList(xbmc.PLAYLIST_VIDEO)
		resultPlaylist.clear()
		image = re.compile("<img.*?src='(.+?\.jpg)\?800'.+?>").search(content)
		if image:
			image = image.group(1) + '?200'
		else:
			image = self.ROOT + '/resources/media/icons/video.png'
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

	def unescape(self, string):
		for (symbol, code) in self.htmlCodes:
			string = re.sub(code, symbol, string)
		return string

	def stripHtml(self, string):
		for (html, replacement) in self.stripPairs:
			string = re.sub(html, replacement, string)
		return string

	def parseItem(self, item):
		link = item.a.get('href')
		if item.a.img:
			image = item.a.img.get('src')
			title = item.findAll('a')[1].b.string.encode('utf8')
		else:
			image = self.ROOT + '/resources/media/icons/video.png'
			title = item.findAll('a')[0].b.string.encode('utf8')
		if item.find('a', {'class': 'info'}):
			title = "%s [%s]" % (title, item.find('a', {'class': 'info'}).string.encode('utf8'))

		return {'link': link, 'title': self.unescape(title), 'image': image}
		
	def search(self, data):
		result = []
		if BeautifulSoup(data).find('table', {'class': 'panel'}):
			for section in BeautifulSoup(data).find('table', {'class': 'panel'}).findAll('td'):
				if section.a:
					result.append(self.parseItem(section))
				
		return result

	def sections(self, data):
		result = []
		if BeautifulSoup(data).find('table', {'class': 'include_0'}):
			for section in BeautifulSoup(data).find('table', {'class': 'include_0'}).findAll('td', {'align': 'center', 'valign': 'center'}):
				if section.a:
					item = self.parseItem(section)
					# Remove megogo category
					if re.compile("/17031949\?").search(item['link']) or re.compile("%2F17031949%3F").search(item['link']):
						continue
					result.append(item)
			
		return result

	def originalId(self, data):
		if BeautifulSoup(data).find('input', {'name': 'original_id'}):
			return BeautifulSoup(data).find('input', {'name': 'original_id'})['value']

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

		filelist = None
		if soup.find('td', {'colspan': 3, 'valign': 'bottom'}):
			filelist = re.compile("(\d+).urls").search(soup.find('td', {'colspan': 3, 'valign': 'bottom'}).a.get('href'))
		details = re.compile(">(.+?)?<h1>(.+?)</h1>(.+?)</td>", re.DOTALL).search(content)
		if details and filelist:
			if re.compile("\"url\": \"http://www.ex.ua/show/\d+/[abcdef0-9]+.flv\"").search(content):
				self.drawItem(self.localize('FLV Playlist'), 'playFLV', '', self.ROOT + '/resources/media/icons/flash.png', False)
			if re.compile("[^'\" ].m3u").search(content):
				self.drawItem(self.localize('M3U Playlist'), 'playM3U', '', self.ROOT + '/resources/media/icons/video.png', False)
			image = re.compile("<img src='(http.+?\?800)'").search(details.group(1))
			if image:
				image = image.group(1)
			else:
				image = self.ROOT + '/resources/media/icons/video.png'
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
				listitem = xbmcgui.ListItem(self.localize('Description &\nComments') + ' [%s]' % comments.group(2), iconImage=self.ROOT + '/resources/media/icons/description.png')
			else:
				listitem = xbmcgui.ListItem(self.localize('Description &\nComments') + ' [0]', iconImage=self.ROOT + '/resources/media/icons/description.png')
			description += "-----------------------------------------------------------------------------------------\n\n\n\n\n\n\n"
			listitem.setInfo(type = 'Video', infoLabels = {
				"Title": 		self.unescape(self.stripHtml(title)),
				"Plot": 		self.unescape(self.stripHtml(description)) } )
			url = '%s?action=%s' % (sys.argv[0], 'showDetails')
			xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]), url=url, listitem=listitem, isFolder=True)
			if self.__settings__.getSetting("auth"):
				self.drawItem(self.localize('Leave\nComment'), 'leaveComment', filelist.group(1), self.ROOT + '/resources/media/icons/comment.png', False)
				self.drawItem(self.localize('To My\nPage'), 'toMyPage', filelist.group(1), self.ROOT + '/resources/media/icons/add_to_user_page.png', False)
				self.drawItem(self.localize('To My\nBookmarks'), 'toBookmarks', filelist.group(1), self.ROOT + '/resources/media/icons/add_bookmark.png', False)
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
