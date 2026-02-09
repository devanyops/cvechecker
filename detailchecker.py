#!/usr/bin/python3

import os
import json

filename = "/Users/wangli/cvechecker/result.csv"
def parse_data(data):
    maybe_affect = False
    pkg_line = data['name'] + ","
    pkg_rhel7_affected = "--"
    pkg_rhel8_affected = "--"
    has_rhel7_state = False
    has_rhel8_state = False
    pkg_name = None
    if data['package_state']:
        is_kernel = False
        for pkg in data['package_state']:
            if 'kernel' in pkg['package_name'] and 'kernel' != pkg['package_name']:
                is_kernel = True
                continue;
            pkg_name = pkg['package_name']
            if 'python' in pkg['package_name']:
                print("%s: need check manually because of python package" % data['name'])
                return
            if pkg['product_name'] == 'Red Hat Enterprise Linux 7':
                if is_kernel and 'kernel' != pkg['package_name']:
                    continue;
                has_rhel7_state = True
                pkg_rhel7_affected = pkg['fix_state']
            elif pkg['product_name'] == 'Red Hat Enterprise Linux 8':
                if is_kernel and 'kernel' != pkg['package_name']:
                    continue;
                has_rhel7_state = True
                pkg_rhel8_affected = pkg['fix_state']
        if ((not has_rhel7_state) or (not has_rhel8_state)) and data['affected_release']:
            for affected in data['affected_release']:
                if affected['product_name'] == 'Red Hat Enterprise Linux 7':
                    #print("%s affected, maybe has fixed" % data['name'])
                    pkg_rhel7_affected = "maybe fixed"
                elif affected['product_name'] == 'Red Hat Enterprise Linux 8':
                    pkg_rhel8_affected = "maybe fixed"
        if pkg_rhel7_affected == "Not affected":
            pkg_rhel7_affected = "不受影响"
        if pkg_rhel8_affected == "Not affected":
            pkg_rhel8_affected = "不受影响"
        if pkg_name is None:
            pkg_name = 'NULL'
        pkg_line += pkg_name + "," + pkg_rhel7_affected + "," + pkg_rhel8_affected
        print("--------------%s-----------------"%data['name'])
        print("%s"%data['details'])
    else:
        print("%s: need check manually because of data" % data['name'])

with open("/Users/wangli/cvechecker/updated", "r") as fp:
    for line in fp.readlines():
        if line == '\n':
            continue
        line = line.strip().upper()
        lar = line.split('-')
        jpath = "/Users/wangli/develop/vuln-list-redhat.git/api/" + str(lar[1]) + "/" + line + ".json"
        if (not os.access(jpath, os.F_OK)):
            print("%s not affected" % line)
            continue
        with open(jpath, "r") as jfp:
            data = json.load(jfp)
            parse_data(data)

