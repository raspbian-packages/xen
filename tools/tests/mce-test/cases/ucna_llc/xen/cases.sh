#!/bin/bash
#
# Copyright (c) 2010, Intel Corporation
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; If not, see <http://www.gnu.org/licenses/>.
#
# Author: Xudong Hao <xudong.hao@intel.com>
#

sd=$(dirname $0)
export ROOT=`(cd $sd/../../../; pwd)`
export this_case=ucna_llc_xen

. $ROOT/lib/xen-mceinj-tool.sh

usage()
{
    echo "Usage: ./cases.sh [-options] [arguments]"
    echo "================Below are the optional options================"
    echo -e "\t-c injcpu\t: which cpu to inject error"
    echo -e "\t-p pageaddr\t: Guest Physical Address to inject error"
    echo -e "\t\t\tBy default, the GPA is 0x180020"
    echo -e "\t-h help"
    exit 0
}

while getopts ":c:p:h" option
do
    case "$option" in
    c) injcpu=$OPTARG;;
    p) pageaddr=$OPTARG;;
    h) usage;;
    *) echo "invalid option!"; usage;;
    esac
done

inject()
{
    mce_inject_trigger $CMCI_UCNA_LLC -u $injcpu -p $pageaddr 
    if [ $? -eq 0 ]; then
        show "  Passed: Successfully to fake and inject a MCE error"
    else
        show "  Failed: Fake error and inject fail !!"
        return 1
    fi
    return 0
}

do_main()
{
    ret_val=0
    clean_env
    inject || ret_val=1
    mcelog_verify $CMCI_UCNA_LLC || ret_val=1
    gen_result $ret_val
}

do_main "$@"
