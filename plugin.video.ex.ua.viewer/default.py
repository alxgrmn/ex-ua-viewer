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

import sys, xbmc, xbmcaddon, os

__settings__ = xbmcaddon.Addon(id='plugin.video.ex.ua.viewer')
__version__ = __settings__.getAddonInfo('version')
__plugin__ = __settings__.getAddonInfo('name') + " v." + __version__
__root__ = os.getcwd()

if (__name__ == "__main__" ):
	print __plugin__
	import Core
	import Localization
	core = Core.Core(Localization.__localization__)
	if (not sys.argv[2]):
		core.sectionMenu()
	else:
		params = core.getParameters(sys.argv[2])
		core.executeAction(params)
