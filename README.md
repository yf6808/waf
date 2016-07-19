# waf
waf for denycc by ngx_lua
参照一个网友写的waf改的，只提取了denycc的功能，分了三个维度 接口（uid）、域名、ip 进行拦截，超过频次了就返回403并记录日志
