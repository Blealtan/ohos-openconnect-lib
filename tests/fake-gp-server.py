#!/usr/bin/env python3
#
# Copyright © 2021 Daniel Lenski
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import sys
import ssl
from random import randint
import base64
from json import dumps
from functools import wraps
from flask import Flask, request, abort, redirect, url_for, session

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, HOST=host, PORT=int(port), SESSION_COOKIE_NAME='fake')


########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())


def check_form_against_session(*fields, use_query=False, on_failure=None):
    def inner(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            source = request.args if use_query else request.form
            source_name = 'args' if use_query else 'form'
            for f in fields:
                fs = f.replace('_', '-')
                if on_failure:
                    if session.get(f) != source.get(fs):
                        return on_failure
                else:
                    assert session.get(f) == source.get(fs), \
                        f'at step {session.get("step")}: {source_name} {f!r} {source.get(fs)!r} != session {f!r} {session.get(f)!r}'
            return fn(*args, **kwargs)
        return wrapped
    return inner

########################################


if_path2name = {'global-protect': 'portal', 'ssl-vpn': 'gateway'}

# Get parameters into the initial session setup in order to configure:
#   gateways: list of gateway names for portal to offer (all will point to same HOST:PORT as portal)
#   portal_2fa: if set, require challenge-based 2FA to complete /global-protect/getconfig.esp request
#   gateway_2fa: if set, require challenge-based 2FA to complete /ssl-vpn/login.esp request
#   portal_saml: set to 'portal-userauthcookie' or 'prelogin-cookie' to require SAML on portal (and
#                expect the named cookie to be provided to signal SAML completion)
#   gateway_saml: likewise, set to require SAML on gateway
#   portal_cookie: if set (to 'portal-userauthcookie' or 'portal-prelogonuserauthcookie'), then
#                  the portal getconfig response will include the named "cookie" field which should
#                  be used to automatically continue login on the gateway
@app.route('/<any("global-protect", "ssl-vpn"):interface>/testconfig.esp', methods=('GET','POST',))
def testconfig(interface):
    gateways, portal_2fa, gw_2fa, portal_cookie, portal_saml, gateway_saml = request.args.get('gateways'), request.args.get('portal_2fa'), request.args.get('gw_2fa'), request.args.get('portal_cookie'), request.args.get('portal_saml'), request.args.get('gateway_saml')
    session.update(gateways=gateways and gateways.split(','), portal_cookie=portal_cookie,
                   portal_2fa=portal_2fa and bool(portal_2fa), gw_2fa=gw_2fa and bool(gw_2fa),
                   portal_saml=portal_saml, gateway_saml=gateway_saml)
    prelogin = url_for('prelogin', interface=interface)
    return redirect(prelogin)


# Respond to initial prelogin requests
@app.route('/<any("global-protect", "ssl-vpn"):interface>/prelogin.esp', methods=('GET','POST',))
def prelogin(interface):
    ifname = if_path2name[interface]
    if session.get(ifname + '_saml'):
        saml = '<saml-auth-method>REDIRECT</saml-auth-method><saml-request>{}</saml-request>'.format(
            base64.urlsafe_b64encode(url_for('saml_form', interface=interface, _external=True).encode()).decode())
    else:
        saml = ''
    session.update(step='%s-prelogin' % ifname)
    return '''
<prelogin-response>
<status>Success</status>
<ccusername/>
<autosubmit>false</autosubmit>
<msg/>
<newmsg/>
<authentication-message>Please login to this fake GP VPN {ifname}</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>{saml}
<region>EARTH</region>
</prelogin-response>'''.format(ifname=ifname, saml=saml)


# Simple SAML form (not actually hooked up, for now)
@app.route('/<any("global-protect", "ssl-vpn"):interface>/SAML_FORM')
def saml_form(interface):
    abort(503)


def challenge_2fa(where):
    # select a random inputStr of 4 hex digits, and randomly return challenge in either XML or Javascript-y form
    inputStr = '%04x' % randint(0x1000, 0xffff)
    session.update(step='%s-2FA' % where, inputStr=inputStr)
    if randint(1, 2) == 1:
        tmpl = '<challenge><respmsg>2FA challenge from %s</respmsg><inputstr>%s</inputstr></challenge>'
    else:
        tmpl = ('var respStatus = "Challenge";\n'
                'var respMsg = "2FA challenge from %s";\n'
                'thisForm.inputStr.value = "%s";\n')
    return tmpl % (where, inputStr)


# Respond to portal getconfig request
@app.route('/global-protect/getconfig.esp', methods=('POST',))
def portal_config():
    portal_2fa = session.get('portal_2fa')
    portal_saml = session.get('portal_saml')
    portal_cookie = session.get('portal_cookie')
    inputStr = request.form.get('inputStr') or None

    if portal_2fa and not inputStr:
        return challenge_2fa('portal')

    okay = False
    if portal_saml and request.form.get('user') and request.form.get(portal_saml):
        okay = True
    elif request.form.get('user') and request.form.get('passwd') and inputStr == session.get('inputStr'):
        okay = True
    if not okay:
        return 'Invalid username or password', 512

    session.update(step='portal-config', user=request.form.get('user'), passwd=request.form.get('passwd'),
                   # clear SAML result fields to ensure failure if blindly retried on gateway
                   saml_user=None, saml_value=None,
                   # clear inputStr to ensure failure if same form fields are blindly retried on another challenge form:
                   inputStr=None)
    gateways = session.get('gateways') or ('Default gateway',)
    gwlist = ''.join('<entry name="{}:{}"><description>{}</description></entry>'.format(app.config['HOST'], app.config['PORT'], gw)
                     for gw in gateways)
    if portal_cookie:
        val = session[portal_cookie] = 'portal-cookie-%d' % randint(1, 10)
        pc = '<{0}>{1}</{0}>'.format(portal_cookie, val)
    else:
        pc = ''

    return '''<?xml version="1.0" encoding="UTF-8" ?>
    <policy><version> 6.7.8-9 </version><gateways><external><list>{}</list></external></gateways>
    <hip-collection><hip-report-interval>600</hip-report-interval></hip-collection>
    {}</policy>'''.format(gwlist, pc)


# Respond to gateway login request
@app.route('/ssl-vpn/login.esp', methods=('POST',))
def gateway_login():
    gw_2fa = session.get('gw_2fa')
    gateway_saml = session.get('gateway_saml')
    inputStr = request.form.get('inputStr') or None

    if session.get('portal_cookie') and request.form.get(session['portal_cookie']) == session.get(session['portal_cookie']):
        # a correct portal_cookie explicitly allows us to bypass other gateway login forms
        pass
    elif gw_2fa and not inputStr:
        return challenge_2fa('gateway')
    else:
        okay = False
        if gateway_saml and request.form.get('user') and request.form.get(gateway_saml):
            okay = True
        elif request.form.get('user') and request.form.get('passwd') and inputStr == session.get('inputStr'):
            okay = True
        if not okay:
            return 'Invalid username or password', 512
    session.update(step='gateway-login', user=request.form.get('user'), passwd=request.form.get('passwd'),
                   # clear inputStr to ensure failure if same form fields are blindly retried on another challenge form:
                   inputStr=None)

    for k, v in (('jnlpReady', 'jnlpReady'), ('ok', 'Login'), ('direct', 'yes'), ('clientVer', '4100'), ('prot', 'https:')):
        if request.form.get(k) != v:
            abort(500)
    for k in ('clientos', 'os-version', 'server', 'computer'):
        if not request.form.get(k):
            abort(500)

    portal = 'Portal%d' % randint(1, 10)
    auth = 'Auth%d' % randint(1, 10)
    domain = 'Domain%d' % randint(1, 10)
    preferred_ip = request.form.get('preferred-ip') or '192.168.%d.%d' % (randint(2, 254), randint(2, 254))
    if request.form.get('ipv6-support') == 'yes':
        preferred_ipv6 = request.form.get('preferred-ipv6') or 'fd00::%x' % randint(0x1000, 0xffff)
    else:
        preferred_ipv6 = None
    session.update(preferred_ip=preferred_ip, portal=portal, auth=auth, domain=domain, computer=request.form.get('computer'),
                   ipv6_support=request.form.get('ipv6-support'), preferred_ipv6=preferred_ipv6)
    session.setdefault('portal-prelogonuserauthcookie', '')
    session.setdefault('portal-userauthcookie', '')
    session['authcookie'] = cookify(dict(session)).decode()

    return '''<?xml version="1.0" encoding="utf-8"?> <jnlp> <application-desc>
        <argument>(null)</argument>
            <argument>{authcookie}</argument>
            <argument>PersistentCookie</argument>
            <argument>{portal}</argument>
            <argument>{user}</argument>
            <argument>TestAuth</argument>
            <argument>vsys1</argument>
            <argument>{domain}</argument>
            <argument>(null)</argument>
            <argument/>
            <argument></argument>
            <argument></argument>
            <argument>tunnel</argument>
            <argument>-1</argument>
            <argument>4100</argument>
            <argument>{preferred_ip}</argument>
            <argument>{portal-userauthcookie}</argument>
            <argument>{portal-prelogonuserauthcookie}</argument>
            <argument>{ipv6}</argument>
            </application-desc></jnlp>'''.format(ipv6=preferred_ipv6 or '', **session)


# Respond to gateway getconfig request
@app.route('/ssl-vpn/getconfig.esp', methods=('POST',))
@check_form_against_session('user', 'portal', 'domain', 'authcookie', 'preferred_ip', 'preferred_ipv6', 'ipv6_support', on_failure="errors getting SSL/VPN config")
def getconfig():
    session.update(step='gateway-config')
    addrs = '<ip-address>{}</ip-address>'.format(session['preferred_ip'])
    if session['ipv6_support'] == 'yes':
        addrs += '<ip-address-v6>{}</ip-address-v6>'.format(session['preferred_ipv6'])
    return '''<response>{}<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>'''.format(addrs)


# Respond to gateway hipreportcheck request
@app.route('/ssl-vpn/hipreportcheck.esp', methods=('POST',))
@check_form_against_session('user', 'portal', 'domain', 'authcookie', 'computer')
def hipcheck():
    session.update(step='gateway-config')
    return '''<response><hip-report-needed>no</hip-report-needed></response>'''


# Respond to faux-CONNECT GET-tunnel with 502
# (what the real GP server responds with when it doesn't like the cookie, intended
# to trigger "cookie rejected" error in OpenConnect)
@app.route('/ssl-tunnel-connect.sslvpn')
# Can't use because OpenConnect doesn't send headers here
# @check_form_against_session('user', 'authcookie', use_query=True)
def tunnel():
    assert 'user' in request.args and 'authcookie' in request.args
    session.update(step='GET-tunnel')
    abort(502)


# Respond to 'GET /ssl-vpn/logout.esp' by clearing session and MRHSession
@app.route('/ssl-vpn/logout.esp')
# XX: real server really requires all these fields; see auth-globalprotect.c
@check_form_against_session('authcookie', 'portal', 'user', 'computer')
def logout():
    return '<response status="success"/>'


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=True, ssl_context=context)
