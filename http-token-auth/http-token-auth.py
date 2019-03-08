# -*- coding: utf-8 -*-
__auther__ = '35942'
from flask import Flask,jsonify
from flask_restful import Api
from flask_restful import reqparse,Resource,request
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'super-secret'

api = Api(app)


from  flask_httpauth import  HTTPTokenAuth

auth = HTTPTokenAuth(scheme='Bearer')

# tokens = {'secret_token1':'super', 'secret_token2': 'admin'}
tokens = {"eyJhbGciOiJIUzI1NiIsImV4cCI6MTU1MTE1NjYwOSwiaWF0IjoxNTUxMTUzMDA5fQ.eyJwYXNzd29yZCI6IjEyMjMzMjQiLCJuYW1lIjoxfQ.eqNEocuWoqJuppAjmqjtDLTYUK3GopxvVtrzID_uwRQ":"super",
          "eyJhbGciOiJIUzI1NiIsImV4cCI6MTU1MTE1NjY1MSwiaWF0IjoxNTUxMTUzMDUxfQ.eyJwYXNzd29yZCI6IjEyMjMzMjQiLCJuYW1lIjoxfQ.cDdf0nX6iULDhq9JgNBZZnP-7GolaSI_4TfJ5jdYOsM":"admin",
          "eyJhbGciOiJIUzI1NiIsImV4cCI6MTU1MTE2NDAyOCwiaWF0IjoxNTUxMTYwNDI4fQ.eyJwYXNzd29yZCI6IjEyMjMzMjQiLCJuYW1lIjoiVjMifQ.mhZALfO78_YIPJz8GHIVBUa9nk4NjFU3JSvb-H8qyuw":"visitor"}


roles_allowed_permission  = {'super':['POST', 'GET', 'DELETE', 'PUT'], 'admin':['POST','GET'], 'visitor':['GET']}

@auth.verify_token
def verify_token(token):

    # # if token in tokens:
    # if token in tokens.keys():
    return  True

    # return  False



def operate_access(func):
    def wraps(*args, **kwargs):
        # if request.endpoint == 'data':
        """
        由token 获取角色权限
        :param args:
        :param kwargs:
        :return:
        """

        token = request.headers['Authorization'].split(' ')[-1]
        if token:
            method = request.method
            role = tokens.get(token)
            if role:
                if method not in roles_allowed_permission.get(role):
                    return jsonify({'message': "This user permission is not permitted for this operation",
                                    'status_code':'401'})
            else:
                return jsonify({'message': "Invalid token Unauthorized Access",
                                'status_code': '401'})
        else:
            return jsonify({'message': "Invalid token Unauthorized Access",
                            'status_code': '401'})
        return  func(*args, **kwargs)
    return  wraps

class Get_Data(Resource):



    @auth.login_required
    @operate_access
    def get(self):
        headers = request.headers['Authorization']
        print headers
        return  'get'  + '  +++++++ ' + headers

    @auth.login_required
    @operate_access
    def post(self):
        headers = request.headers['Authorization']
        return  'post' + '======='  +  headers

    @auth.login_required
    @operate_access
    def put(self):
        headers = request.headers['Authorization']
        return 'put' + '======='  +   headers

    @auth.login_required
    @operate_access
    def delete(self):
        headers = request.headers['Authorization']
        return 'delete' + '=======' + headers

class Get_token(Resource):
    def post(self):
        """
        meta登录验证  签发access_token,存储
        :return:
        """
        data = request.get_json()
        expiration = 3600
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)  # expiration是过期时间
        token = s.dumps(data)

        return   {'access_token':  token}

api.add_resource(Get_Data, '/', endpoint = 'data')
api.add_resource(Get_token, '/access_token')


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080,debug=True)


