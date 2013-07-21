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

from Core import Core

class Router:
	def __init__(self, action):
		core = Core()
		if (not action):
			core.sectionMenu()
		else:
			params = self.getParameters(action)
			get = params.get
			if hasattr(core, get("action")):
				getattr(core, get("action"))(params)
			else:
				core.sectionMenu()

	def getParameters(self, parameterString):
		commands = {}
		for command in parameterString[parameterString.find('?')+1:].split('&'): 
			if (len(command) > 0):
				(name, value) = command.split('=')
				commands[name] = value
		return commands
