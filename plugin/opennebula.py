#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import urlparse
import json
import base64
import random
import string
import sys
import traceback
import xmlrpclib
from xml.dom.minidom import parseString

import sqlite3

def list_params():
    RequestParams = []
    ConfParams = [
        # the following are the service.$id.plugin.$key parameter
        # where key is one of the names following

        # URL of the XML-RPC API of the OpeNebula server
        {'name':'api_endpoint', 'type':'string', 'default':'http://localhost:2633/RPC2'},
        # User to access the API
        {'name':'sessionid', 'type':'string', 'default':'oneadmin:somepass'},
        # DB to store the data about the users
        # IMPORTANT!!! Must be only accesible by the user which executes this script!!!
        # ALSO IMPORTANT!!! Must be only stored in persistent storage (be careful in containers)
        {'name':'db_file', 'type':'string', 'default':'/tmp/users.db'},
        # Prefix to add to all user names created
        {'name':'user_prefix', 'type':'string', 'default':'watts'},
        # Group ID to add the users created
        {'name':'user_group', 'type':'string', 'default':'105'}
    ]
    Version = "0.1.0"
    return json.dumps({'result':'ok', 'conf_params': ConfParams, 'request_params': RequestParams, 'version':Version})


def create_one_user(username, group, oidc, password, config):
    """
    Create the specified user in the OpenNebula site
    """
    api_endpoint = config['api_endpoint']
    sessionid = config['sessionid']
    server = xmlrpclib.ServerProxy(api_endpoint, allow_none=True)

    template = ('ISS="%s"\nSUB="%s"\nName="%s"' % (oidc['iss'],
                                                   oidc['sub'],
                                                   oidc['name']))

    success, userid, _ = server.one.user.allocate(sessionid, username, password, "core")
    if not success:
        return False, userid

    success, msg, _ = server.one.user.update(sessionid, userid, template, 0)
    if not success:
        delete_one_user(userid)
        return False, msg

    success, msg, _ = server.one.user.chgrp(sessionid, userid, group)
    if not success:
        delete_one_user(userid)
        return False, msg

    return True, userid


def delete_one_user(userid, config):
    """
    Delete the specified user from the OpenNebula site
    """
    api_endpoint = config['api_endpoint']
    sessionid = config['sessionid']
    server = xmlrpclib.ServerProxy(api_endpoint, allow_none=True)

    success, userid, _ = server.one.user.delete(sessionid, userid)
    if not success:
        return False, userid
    return True, ""


def id_generator(size=16, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    """
    Genererate a random password
    """
    return ''.join(random.choice(chars) for _ in range(size))


def user_exist(username, config):
    """
    Check if a username exists in the OpenNebula site, and return the ID
    """
    api_endpoint = config['api_endpoint']
    sessionid = config['sessionid']
    db_file = config['db_file']
    server = xmlrpclib.ServerProxy(api_endpoint, allow_none=True)

    success, userpool, _ = server.one.userpool.info(sessionid)
    if not success:
        return False, userpool

    userpool_info = parseString(userpool)
    for user in userpool_info.getElementsByTagName("USER"):
        user_name = user.getElementsByTagName('NAME')[0].firstChild.nodeValue.strip()
        user_id = int(user.getElementsByTagName('ID')[0].firstChild.nodeValue.strip())
        if username == user_name:
            return True, user_id

    return False, ""


def init_db(config):
    """
    Initialize the users DB
    """
    db_file = config['db_file']
    connection = sqlite3.connect(db_file)
    cursor = connection.cursor()
    sql = 'select name from sqlite_master where type="table" and name="one_users"'
    cursor.execute(sql)
    res = cursor.fetchall()
    if (len(res) == 0):
        cursor.execute("CREATE TABLE one_users(username VARCHAR(255) PRIMARY KEY, password VARCHAR(255))")
        connection.commit()
        connection.close()
        return True

    connection.close()
    return False


def save_user_data(username, password, config):
    """
    Save the user data into the DB
    """
    init_db(config)
    db_file = config['db_file']

    connection = sqlite3.connect(db_file)
    cursor = connection.cursor()
    sql = 'insert into one_users values ("%s", "%s")' % (username, password)
    cursor.execute(sql)
    connection.commit()
    connection.close()

    return True


def delete_user_data(username, config):
    """
    Delete the user data from the DB
    """
    db_file = config['db_file']
    created = init_db(config)
    if created:
        return False
    else:
        connection = sqlite3.connect(db_file)
        cursor = connection.cursor()
        sql = 'delete from one_users where username = "%s"' % username
        cursor.execute(sql)
        connection.commit()
        connection.close()
        return True


def get_user_password(username, config):
    """
    Get the user password stored in the DB
    """
    db_file = config['db_file']
    created = init_db(config)
    if created:
        return None
    else:
        connection = sqlite3.connect(db_file)
        cursor = connection.cursor()
        sql = 'select password from one_users where username = "%s"' % username
        cursor.execute(sql)
        res = cursor.fetchall()
        connection.close()
        if len(res) > 0:
            return res[0][0]
        else:
            return None


def create_user(username, group, oidc, config):
    """
    Create a new user and return the appropriate credentials
    """
    api_endpoint = config['api_endpoint']
    sessionid = config['sessionid']
    exists, user_id = user_exist(username, config)
    if not exists:
        password = id_generator()
        success, userid = create_one_user(username, group, oidc, password, config)
        if not success:
            return json.dumps({'result':'error', 'log_msg': 'Error creating user: %s' % userid})

        save_user_data(username, password, config)
    else:
        password = get_user_password(username, config)
        if not password:
            # This case only happens in case of previous error
            # The user has been created without storing the password in the DB
            # First delete the incorrect user data from DB
            delete_user_data(username, config)
            # Generate new password
            password = id_generator()
            # Update in ONE
            server = xmlrpclib.ServerProxy(api_endpoint, allow_none=True)
            success, user, _ = server.one.user.passwd(sessionid, user_id, password)
            if not success:
                return json.dumps({'result':'error', 'log_msg':'Error setting user password: %s' % user})
            else:
                # And save in the DB
                save_user_data(username, password, config)

    credential = [{'name': 'Username', 'type': 'text', 'value': username},
                  {'name': 'Password', 'type': 'text', 'value': password}]
    return json.dumps({'result':'ok', 'credential': credential, 'state': username})


def revoke_user(username, config):
    """
    Revoke user credentials
    """
    exists, userid = user_exist(username, config)
    if exists:
        success, msg = delete_one_user(userid, config)
        if success:
            delete_user_data(username, config)
            return json.dumps({'result': 'ok'})
        else:
            usermsg = "revoke failed, please contact the administrator"
            logmsg = "revoke issue with userid %s : %s"%{userid, msg}
            return json.dumps({'result':'error', 'user_msg': usermsg, 'log_msg':logmsg})
    else:
        if userid == "":
            return json.dumps({'result': 'ok'})
        else:
            usermsg = "revoke failed, please contact the administrator"
            logmsg = "issue failed, user does not exist %s"%userid
            return json.dumps({'result':'error', 'user_msg': usermsg, 'log_msg':logmsg})


def process_request(request):
    """
    Process the WaTTS request from the json data provided
    """
    UserMsg = "Internal error, please contact the administrator"
    json_data = str(request) + '=' * (4 - len(request) % 4)
    jobject = json.loads(str(base64.urlsafe_b64decode(json_data)))

    action = jobject['action']
    if action == "parameter":
        print list_params()

    else:
        config = jobject['conf_params']
        user_info = jobject['user_info']
        user_group = int(config['user_group'])
        user_prefix = config['user_prefix']


        # oidc = user_info['oidc']
        iss = urlparse.urlparse(user_info['iss'])
        iss_host = iss[1]
        username = "%s_%s_%s" % (user_prefix, iss_host, user_info['sub'])

        if action == "request":
            return create_user(username, user_group, user_info, config)
        elif action == "revoke":
            state = jobject['cred_state']
            if state != username:
                UserMsg = "Internal error, please contact the administrator"
                LogMsg = "username and state different"
                return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
            else:
                return revoke_user(state, config)
        else:
            LogMsg = "the plugin was run with an unknown action '%s'"%action
            return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})


def main():
    UserMsg = "Internal error, please contact the administrator"
    try:
        if len(sys.argv) == 2:
            print process_request(sys.argv[1])
        else:
            LogMsg = "the plugin was run without an action"
            print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
    except Exception, E:
        TraceBack = traceback.format_exc(),
        LogMsg = "the plugin failed with %s - %s"%(str(E), TraceBack)
        print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
        pass

if __name__ == "__main__":
    main()
