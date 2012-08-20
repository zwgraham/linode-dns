from linode import api
import json
import sys
import logging
from optparse import OptionParser, OptionGroup
DEFAULT_API_CONFIG_FILE="linodeapi.conf"
linode=api.Api()


def list_eligible_subdomains(domain_id):
    eligible_subdomains=[ x for x in linode.domain_resource_list(DomainID=domain_id)
            if ( x['NAME']!='' ) and ( x['TYPE']=='a' or x['TYPE']=='AAAA') ]
    return eligible_subdomains

def get_subdomain_by_name(sub, domain_id):
    matched_sub_names= [ x for x in list_eligible_subdomains(domain_id) if (x['NAME']==sub)]
    return matched_sub_names

usage = "usage: %prog [options] <subdomain>"
parser = OptionParser(usage)
ip_update_group=OptionGroup(parser, "IP address update options",
        "These options are used to update the ipaddress associated with a subdomain")
ip_update_group.add_option("-4", "--ipv4", dest="ipv4_address", metavar="addr",
        help="Update IPv4 address update")
ip_update_group.add_option("-6", "--ipv6", dest="ipv6_address", metavar="addr",
        help="Update IPv6 address update")
parser.add_option("-C", "--config", dest="config_file", metavar="file.conf",
        help="linode API config file", default=DEFAULT_API_CONFIG_FILE)
parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
        help="Be verbose", default=False)
parser.add_option("-q", "--quiet", dest="verbose", action="store_false",
        help="Be quiet", default=False)
parser.add_option_group(ip_update_group)

(options, args) = parser.parse_args()
if len(args)== 1:
    import ConfigParser
    logging.basicConfig()
    logger = logging.getLogger('linode_dns')    
    if options.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        logger.debug("Parsing config file.")
        Config = ConfigParser.ConfigParser()
        Config.read(options.config_file)
    except Exception, e:
        logger.error("Problem reading config file. %s" %(str(e)))
        sys.exit()

    try:
        key=Config.get('Account', 'Key')
        domain_id=Config.get('Account', 'DomainID')
    except:
        logger.error("Malformed config file.")
        sys.exit()

    linode=api.Api(key)
    
    subdomain=args[0]

    subs = get_subdomain_by_name(subdomain, domain_id)
    if subs:
        logger.debug("%s - valid subdomain" %(subdomain))
        for sub in subs:
            if options.ipv4_address and sub['TYPE']=='a':
                logger.debug("Verifying %s's ipv4 address against %s"%
                        (subdomain, options.ipv4_address))
                if options.ipv4_address == sub['TARGET']:
                    logger.debug('IPv4 address is already up-to-date.')
                else:
                    try:
                        linode.domain_resource_update(DomainID=DOMAIN_ID, 
                                ResourceID=sub['RESOURCEID'],Target=options.ipv4_address)
                    except api.ApiError, e:
                        logger.error(" %d - %s"%( e.value[0]['ERRORCODE'], e.value[0]['ERRORMESSAGE']))
            
            if options.ipv6_address and sub['TYPE']=='AAAA':
                logger.debug("Updating %s's ipv6 address to %s"%
                        (subdomain, options.ipv6_address))
                if options.ipv6_address == sub['TARGET']:
                    logger.debug('IPv6 addresss is already up-to-date.')
                else:
                    try:
                        linode.domain_resource_update(DomainID=DOMAIN_ID,
                                ResourceID=sub['RESOURCEID'],Target=options.ipv6_address)
                    except api.ApiError, e:
                        logger.error(" %d - %s"%( e.value[0]['ERRORCODE'], e.value[0]['ERRORMESSAGE']))


    else:
        logger.debug('%s - invalid subdomain'%(subdomain))
else:
    if len(args) == 0: print "Please enter a subdomain."
    if len(args)  > 1: print "Too many arguments."
    parser.print_usage()
    exit()








