import hashlib
import os
import re

class Generator:
    def __init__(self, workingDir):
        self._generate_addons_file(workingDir)
        self._generate_md5_file()
        print "Finished updating addons xml and md5 files"

    def _generate_addons_file(self, addon):
        addons_xml = u"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<addons>\n"
        try:
            _path = os.path.join(addon, "addon.xml")
            xml_lines = open(_path, "r").read().splitlines()
            addon_xml = ""
            for line in xml_lines:
                if (line.find("<?xml") >= 0): continue
                addon_xml += unicode(line.rstrip() + "\n", "UTF-8")
            addons_xml += addon_xml.rstrip() + "\n\n"
        except Exception, e:
            print "Excluding %s for %s" % (_path, e,)
        addons_xml = addons_xml.strip() + u"\n</addons>\n"
        self._save_file(addons_xml.encode("UTF-8"), file="addons.xml")

    def _generate_md5_file(self):
        try:
            hash = hashlib.md5()
            md5v = open("addons.xml", 'rb').read()
            hash.update(md5v)
            md5v = hash.hexdigest()
            self._save_file(md5v, file="addons.xml.md5")
        except Exception, e:
            print "An error occurred creating addons.xml.md5 file!\n%s" % (e,)

    def _save_file(self, data, file):
        try:
            open(file, "w").write(data)
        except Exception, e:
            print "An error occurred saving %s file!\n%s" % (file, e,)


workingDir = os.path.dirname(os.path.realpath(__file__)) + os.path.sep
Generator(workingDir + 'plugin.video.ex.ua.viewer')

for fname in os.listdir(workingDir + 'plugin.video.ex.ua.viewer' + os.path.sep):
    if re.match('plugin\.video\.ex\.ua\.viewer-[\.0-9]+\.zip', fname):
        os.remove(workingDir + 'plugin.video.ex.ua.viewer' + os.path.sep + fname)
infile = open(workingDir + 'plugin.video.ex.ua.viewer' + os.path.sep + 'addon.xml', 'r')
text = infile.read()
infile.close()
version = re.search('name="Ex.Ua Viewer" version="(.+?)"', text, re.DOTALL).group(1)
os.system('7z.exe a plugin.video.ex.ua.viewer-%s.zip plugin.video.ex.ua.viewer' % version)
os.rename(workingDir + 'plugin.video.ex.ua.viewer-%s.zip' % version, workingDir + 'plugin.video.ex.ua.viewer' + os.path.sep + 'plugin.video.ex.ua.viewer-%s.zip' % version)

os.system('hg add *')
os.system('hg addremove')
os.system('hg commit -u vadim.skorba@gmail.com')
os.system('hg push -f https://vadim.skorba@ex-ua-viewer.googlecode.com/hg/')
os.remove(workingDir + 'plugin.video.ex.ua.viewer' + os.path.sep + 'plugin.video.ex.ua.viewer-' + version + '.zip')
