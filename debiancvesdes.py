#!/usr/bin/python3

import os
import json

affect_file = "/Users/wangli/cvechecker/debian.desc"
def parse_data(data):
    header_dir = data['Header']
    cve_id = header_dir['ID']

    pkg_name = None
    if data['Annotations']:
        should_record = False
        for pkg in data['Annotations']:
            if pkg['Type'] == 'package':
                release = pkg.get('Release', 'none')
                package = pkg.get('Package', 'none')
                kind = pkg.get('Kind', 'none')
                if release == 'buster' and package == 'linux':
                    if kind != 'not-affected' and kind != 'ignored':
                        should_record = True
        if should_record:
            desc = get_desc(cve_id)
            with open(affect_file, "a+") as f:
                f.write(cve_id)
                f.write('\n')
                if desc is not None:
                    f.write(desc)
                f.write('\n--- ---\n\n')
        else:
            print(cve_id)
    else:
        print("%s: need check manually because of data" % cve_id)

def get_desc(cve_id):
    lar = cve_id.split('-')
    cve_des = None
    data = None
    dpath = "/Users/wangli/develop/vuln-list-nvd/api/" + str(lar[1]) + "/" + cve_id + ".json"
    if (not os.access(dpath, os.F_OK)):
        return None
    with open(dpath, "r") as f:
        data = json.load(f)
    descs = data.get('descriptions', None)
    for desc in descs:
        if desc['lang'] == 'en':
            return desc['value']


vuln_dir = "/Users/wangli/develop/vuln-list-debian/tracker/CVE/"
year_dir_list = [str(i) for i in range(2018, 2025)]
for year_dir_name in year_dir_list:
    vuln_dir_sub = vuln_dir + year_dir_name
    vuln_dir_sub_files = os.listdir(vuln_dir_sub)
    for f in vuln_dir_sub_files:
        file_full_name = vuln_dir_sub + "/" + f
        print(file_full_name)
        if not os.path.isfile(file_full_name):
            continue
        with open(file_full_name, "r") as jfp:
            data = json.load(jfp)
            parse_data(data)

