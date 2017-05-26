import re
import syslog
reg_comment_line = re.compile(r'^#')
reg_clean = re.compile(r'[:]')


class ConfigParser(object):

    def __init__(self, config_file):
        self.config_file = config_file

        self.parse()

    def parse(self):
        l = list()
        d = dict()

        try:
            with open(self.config_file, 'r') as f:
                l += [re.sub(r':\s', ':', line.strip()) for line in f if not reg_comment_line.search(line) if reg_clean.search(line)]
                d = dict(map(str, x.split(':')) for x in l)

        except IOError as ioe:
            print(ioe)
            syslog.syslog(syslog.LOG_INFO, str(ioe))
            exit()

        return d
