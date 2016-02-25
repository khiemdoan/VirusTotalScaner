from VirusTotal import VirusTotal

__author__ = 'Khiem Doan'

if __name__ == "__main__":
    print '\n'
    print 'VirusTotal Scanner - KhiemDH'
    print '\n\n'

    virustotal = VirusTotal()
    virustotal.set_config_file('config.ini')
    virustotal.scan_folder()
