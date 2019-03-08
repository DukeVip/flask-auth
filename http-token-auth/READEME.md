token-auth认证：
1 meta  post {'username':'admin','password':'abc123'}
2登录成功同时result=1, 签发access_token(生成,存储)
3Authorization Bearer access_token +++++ get resource,access_token获取角色权限
