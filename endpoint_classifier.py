#!/usr/bin/env python3
"""Classify URL paths into bug bounty testing categories.

This is a local/offline helper. It reads URLs and labels interesting endpoint types
such as auth, admin, upload, billing, webhook, GraphQL, and profile endpoints.
"""
import argparse
import csv
from urllib.parse import urlparse

RULES = {
    'auth': ['login', 'logout', 'signin', 'signup', 'register', 'oauth', 'sso', 'session'],
    'password-reset': ['reset', 'forgot', 'password'],
    'admin': ['admin', 'dashboard', 'manage', 'internal'],
    'upload': ['upload', 'file', 'avatar', 'import'],
    'billing': ['billing', 'invoice', 'payment', 'subscription', 'checkout'],
    'profile-user-data': ['user', 'users', 'profile', 'account', 'me', 'settings'],
    'webhook-callback': ['webhook', 'callback', 'redirect_uri', 'return'],
    'graphql': ['graphql', 'graphiql'],
    'api': ['/api/', 'api.', 'v1', 'v2', 'v3'],
}


def classify(url):
    low = url.lower()
    labels=[]
    for label, needles in RULES.items():
        if any(n in low for n in needles):
            labels.append(label)
    return labels or ['uncategorized']


def main():
    ap=argparse.ArgumentParser(description='Classify endpoints for manual bug bounty testing.')
    ap.add_argument('urls')
    ap.add_argument('-o','--output',default='classified-endpoints.csv')
    args=ap.parse_args()

    rows=[]
    for line in open(args.urls, encoding='utf-8'):
        u=line.strip()
        if not u or u.startswith('#'):
            continue
        p=urlparse(u if u.startswith(('http://','https://')) else 'https://'+u)
        rows.append({'url':u,'host':p.netloc,'path':p.path or '/','labels':','.join(classify(u))})

    with open(args.output,'w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['url','host','path','labels'])
        w.writeheader(); w.writerows(rows)
    print(f'Saved {args.output}')

if __name__ == '__main__':
    main()
