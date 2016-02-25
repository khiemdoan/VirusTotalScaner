
import os
import time
import urllib
import urllib2
import json
import postfile
import ConfigParser

from File import File


__author__ = 'Khiem Doan'


class VirusTotal:

    _host = "www.virustotal.com"
    _url_scan = "https://www.virustotal.com/vtapi/v2/file/scan"
    _url_rescan = "https://www.virustotal.com/vtapi/v2/file/rescan"
    _url_report = "https://www.virustotal.com/vtapi/v2/file/report"
    _key = '0b2ad8232af7a0dbe0352aeacf865601082e35049e7d0f5de720d8bc083fa744'
    _result_folder = "result"
    _scan_folder = 'scan'
    _timeout = 60
    _report_ok = False

    def __init__(self, key=None):
        if key is not None:
            self._key = key

    def set_config_file(self, file_path):
        config = ConfigParser.ConfigParser()
        config.read(file_path)
        self._key = config.get('VirusTotal_Config', 'key')
        self._result_folder = config.get('VirusTotal_Config', 'result_folder')
        self._scan_folder = config.get('VirusTotal_Config', 'scan_folder')
        self._timeout = int(config.getfloat('VirusTotal_Config', 'timeout'))

    def set_result_folder(self, folder):
        self._result_folder = folder

    def scan_folder(self, folder=None):
        if folder is not None:
            self._scan_folder = folder

        list_file = os.listdir(self._scan_folder)
        for file_name in list_file:
            file_path = os.path.join(self._scan_folder, file_name)
            if os.path.isfile(file_path):
                print file_name
                self.scan_file(file_path)
                report_file_path = os.path.join(self._result_folder, file_name + ".txt")
                self._save_report(report_file_path, file_name)

    def _save_report(self, file_path, file_scan=None):
        if self._report_ok is False:
            return

        content = ''

        if file_scan is not None:
            content += 'Filename:      ' + file_scan + '\r\n'

        content += 'MD5:           ' + self._report['md5'] + '\r\n'
        content += 'SHA1:          ' + self._report['sha1'] + '\r\n'
        content += 'SHA256:        ' + self._report['sha256'] + '\r\n'
        content += 'Permalink:     ' + self._report['permalink'] + '\r\n'
        content += '\r\n'

        long_white_space = '                                '

        for key, value in self._report['scans'].items():
            if value['detected'] is True:
                content += key + ': ' + long_white_space[len(key):] + value['result'] + '\r\n'

        target_file = File(file_path)
        target_file.write(content)
        del target_file

    def scan_file(self, file_path):
        target_file = File(file_path)
        sha1 = target_file.get_sha1()
        del target_file

        # kiem tra file da co tren virustotal va rescan
        if self._rescan(sha1) is False:
            if self._send_file(file_path) is False:
                return

        self._report_ok = False
        for i in range(0, self._timeout / 5, 1):
            self._report_ok = self._get_report(sha1)
            if self._report_ok is True:
                break
            else:
                time.sleep(5)

    def _get_report(self, sha1):
        parameters = {"resource": sha1, "apikey": self._key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self._url_report, data)
        response = urllib2.urlopen(req)
        json_str = response.read()
        if json_str == '':
            return False
        self._report = json.loads(json_str)
        return True

    def _rescan(self, sha1):
        parameters = {"resource": sha1, "apikey": self._key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self._url_rescan, data)
        response = urllib2.urlopen(req)
        json_str = response.read()
        if json_str == '':
            return False
        data = json.loads(json_str)
        if data['response_code'] == 1:
            return True
        else:
            return False

    def _send_file(self, file_path):
        fields = [("apikey", self._key)]
        target_file = File(file_path)
        content = target_file.read()
        del target_file
        
        files = [("file", os.path.basename(file_path), content)]
        json_str = postfile.post_multipart(self._host, self._url_scan, fields, files)
        if json_str == '':
            return False
        data = json.loads(json_str)
        if data['response_code'] == 1:
            return True
        else:
            return False
