# -*- coding: utf-8 -*-
__auther__ = '35942'


import datetime
from flask import Flask,request,jsonify,Response
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
from flask_restful import Api, Resource
from  flask_jwt import _jwt


app = Flask(__name__)
api = Api(app)


app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_EXPIRATION_DELTA']  =  datetime.timedelta(days=1000)
app.config['JWT_VERIFY_EXPIRATION'] = True
# app.config['JWT_ALGORITHM'] = ''
app.config['JWT_AUTH_URL_RULE'] = '/access_token/'


class User(object):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.id

users = [
    User('super', 'user1', 'abcxyz'),
    User('admin', 'user2', 'abcxyz'),
    User('visitor', 'user3', 'abcxyz')
]

username_table = {u.username: u for u in users}
userid_table = {u.id: u for u in users}

roles_allowed_permission  = {'super':['POST', 'GET', 'DELETE', 'PUT'], 'admin':['POST','GET'], 'visitor':['GET']}

def authenticate(username, password):
    user = username_table.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user

def identity(payload):
    user_id = payload['identity']
    return userid_table.get(user_id, None)

jwt = JWT(app, authenticate, identity)

def operate_access(fun):
    def wraps(*args, **kwargs):
        token = _jwt.request_callback()
        payload = _jwt.jwt_decode_callback(token)
        # {u'iat': 1551167595, u'exp': 1637567595, u'nbf': 1551167595, u'identity': u'super'}
        # print 'user  is %s, user roletype is %s'%(identity(payload).username,identity(payload).id)
        method = request.method
        roletype = identity(payload).id
        if token:
            if method not  in roles_allowed_permission.get(roletype):
                return jsonify({'message': "This user permission is not permitted for this operation",
                                'status_code': '401'})

        return  fun(*args, **kwargs)
    return  wraps

class Exception_None(Exception):
    status_code = 200

    def __init__(self, message='database has no context', return_code=None ,status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        self.return_code = return_code
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['return_code'] = self.return_code

        # rv = None
        return rv


@app.errorhandler(Exception_None)
def handle_json_none_usage(error):

    resp = jsonify(error.to_dict())
    resp.headers['Content-Type'] = 'application/json'
    resp.status_code = error.status_code
    return resp


# def write_info():
#     print request.url_root,request.url_rule, request.host, request.host_url
#
#
# app.before_first_request(write_info)   #

class Get_Data(Resource):


    @jwt_required()
    @operate_access
    # @before_request
    def get(self):
        token = _jwt.request_callback()
        return  'get ' + token

    @jwt_required()
    @operate_access
    def post(self):
        token = _jwt.request_callback()
        return 'post ' + token

    @jwt_required()
    @operate_access
    def put(self):
        token = _jwt.request_callback()
        return 'put ' + token


    @jwt_required()
    @operate_access
    def delete(self):
        token = _jwt.request_callback()
        a = 'a'
        try:
            a = a/12
        except Exception as err:

            raise  Exception_None(return_code='50000', message=str(err))
        return 'delete ' + token




api.add_resource(Get_Data, '/')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8085, debug=True)