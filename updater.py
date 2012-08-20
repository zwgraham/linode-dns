from linode import api
import json
import sys
import logging
from optparse import OptionParser, OptionGroup
KEY='ZhqCgadxLgkXxKg0A8IPUZYMJwEli4YS38FKdCmR3eFCiOkDVKHxijLAS6jCyYoM'
DOMAIN_ID=291947

linode=api.Api(KEY)


def list_eligible_subdomains():
    eligible_subdomains=[ x for x in linode.domain_resource_list(DomainID=DOMAIN_ID)
            if ( x['NAME']!='' ) and ( x['TYPE']=='a' or x['TYPE']=='AAAA') ]
    return eligible_subdomains

def get_subdomain_ids_by_name(sub):
    matched_sub_names= [ x for x in list_eligible_subdomains() if (x['NAME']==sub)]
    return matched_sub_names

usage = "usage: %prog [options] <subdomain>"
parser = OptionParser(usage)
ip_update_group=OptionGroup(parser, "IP address update options",
        "These options are used to update the ipaddress associated with a subdomain")
ip_update_group.add_option("-4", "--ipv4", dest="ipv4_address", metavar="addr",
        help="Update IPv4 address update")
ip_update_group.add_option("-6", "--ipv6", dest="ipv6_address", metavar="addr",
        help="Update IPv6 address update")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
        help="Be verbose", default=False)
parser.add_option("-q", "--quiet", dest="verbose", action="store_false",
        help="Be quiet", default=False)
parser.add_option_group(ip_update_group)

(options, args) = parser.parse_args()
if len(args)== 1:
    logger = logging.getLogger('linode_dns')    
    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    subdomain=args[0]

    IDs = get_subdomain_ids_by_name(subdomain)
    if IDs:
        logger.debug("%s - valid subdomain" %(subdomain))
        if options.ipv4_address:
            logger.debug("Updating %s's ipv4 address"%(options.ipv4_address))
            
        if options.ipv6_address:
            logger.debug("Updating %s's ipv6 address"%(options.ipv6_address))

    else:
        logger.debug('invalid subdomain')
else:
    if len(args) == 0: print "Please enter a subdomain."
    if len(args)  > 1: print "Too many arguments."
    parser.print_usage()
    exit()








