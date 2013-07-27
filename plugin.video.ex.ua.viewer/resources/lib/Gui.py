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

class Gui:
    __plugin__ = sys.modules[ "__main__"].__plugin__
    __settings__ = sys.modules[ "__main__" ].__settings__
    URL = 'http://www.ex.ua'
    URL_SECURE = 'https://www.ex.ua'
    USERAGENT = "Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.0"
    ROWCOUNT = (15, 30, 50, 100)[int(__settings__.getSetting("rowcount"))]
    LANGUAGE = ('ru', 'uk', 'en')[int(__settings__.getSetting("language"))]
    ROOT = sys.modules[ "__main__"].__root__
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

    def localize(self, text):
        try:
            return Localization.__localization__[self.LANGUAGE][text]
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

    def drawPaging(self, videos, action):
        nextButton = re.compile("<td><a href='([\w\d\?=&/_]+)'><img src='/t3/arr_r.gif'").search(videos)
        pages = re.compile("<font color=#808080><b>(\d+\.\.\d+)</b>").search(videos)
        if nextButton:
            self.drawItem('[%s] ' % pages.group(1) + self.localize('Next >>'), action, self.URL + nextButton.group(1), self.ROOT + '/resources/media/icons/next.png')

    def drawItem(self, title, action, link = '', image=ROOT + '/resources/media/icons/video.png', isFolder = True, contextMenu=None):
        listitem = xbmcgui.ListItem(title, iconImage=image, thumbnailImage=image)
        url = '%s?action=%s&url=%s' % (sys.argv[0], action, urllib.quote_plus(link))
        if contextMenu:
            listitem.addContextMenuItems(contextMenu)
        if isFolder:
            listitem.setProperty("Folder", "true")
        else:
            listitem.setInfo(type = 'Video', infoLabels = {"Title":title})
        xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]), url=url, listitem=listitem, isFolder=isFolder)

    def drawDetails(self, details, comments, count):
        description = "-----------------------------------------------------------------------------------------\n"
        description += self.localize('\n[B]:::Description:::[/B]\n')
        description += details['description'].replace('смотреть онлайн', '')
        if 0 < len(comments):
            description += self.localize('[B]:::Comments:::[/B]\n\n')
            for comment in comments:
                description += "[B]%s[/B]%s" % (comment['title'], comment['comment'])
        listitem = xbmcgui.ListItem(self.localize('Description &\nComments') + ' [%s]' % count, iconImage=self.ROOT + '/resources/media/icons/description.png')
        description += "-----------------------------------------------------------------------------------------\n\n\n\n\n\n\n"
        listitem.setInfo(type = 'Video', infoLabels = {
            "Title": details['title'],
            "Plot": description,
        })
        url = '%s?action=%s' % (sys.argv[0], 'showDetails')
        xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]), url=url, listitem=listitem, isFolder=False)

    def lockView(self, viewId):
        if 'true' == self.__settings__.getSetting("lock_view"):
            try:
                xbmc.executebuiltin("Container.SetViewMode(%s)" % str(self.skinOptimizations[int(self.__settings__.getSetting("skin_optimization"))][viewId]))
            except:
                pass
        xbmcplugin.endOfDirectory(handle=int(sys.argv[1]), succeeded=True)

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

    def showDetails(self):
        xbmc.executebuiltin("Action(Info)")
        if '1' == self.__settings__.getSetting("skin_optimization"):#Transperency
            xbmc.executebuiltin("ActivateWindow(1113)")
            xbmc.executebuiltin("Action(Right)")
        if '0' == self.__settings__.getSetting("skin_optimization"):#Confluence
            xbmc.executebuiltin("Action(Up)")
