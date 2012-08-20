from linode import api
import json

def pp(text=None): print(json.dumps(text, indent=2))

l=api.Api('ZhqCgadxLgkXxKg0A8IPUZYMJwEli4YS38FKdCmR3eFCiOkDVKHxijLAS6jCyYoM')

for domain in l.domain_list():
    print '----------'+domain['DOMAIN']
    for rr in l.domain_resource_list(DomainID=domain['DOMAINID']):
        pp(rr)
        
