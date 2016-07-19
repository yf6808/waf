--[[
 * waf for goodID
 * @author yf6808
 * @time 2016-06-08
 * 在nginx.conf的HTTP中加入
 * lua_shared_dict limit 100m;
 * lua_shared_dict iplimit 20m;
 * lua_shared_dict blockiplimit 50m;
--]]
-------------------------------------------------------------
SecRuleEngine="on" --开启引擎
attacklog = "on"  --开启日志
CCDeny="on"     --cc攻击开关
CCrate="100/10"         --基于接口的计数 次/秒
comCCrate="500/10"      --基于域名的计数 次/秒
ipCCrate="800/10"       --基于ip的计数 次/秒
logpath = "/data/logs/waflog/"          --日志文件路径
-------------------------------------------------
ccdenyrules={"ccdeny1","ccdeny","","","","logon"}
function gethost()
        host = ngx.var.host
        if host == nil or type(host) ~= "string" then
                math.randomseed(os.time())
                host = "nohost"..math.random()
        end
        return host
end

function fail(service)
    pass
end

function denycc(clientdata)
        lua_use_default_type = "text/html"
    if CCDeny=="on" then
        local uri=clientdata[2]
        local host = gethost()
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        ipCCcount=tonumber(string.match(ipCCrate,'(.*)/'))
        ipCCseconds=tonumber(string.match(ipCCrate,'/(.*)'))
        comCCcount=tonumber(string.match(comCCrate,'(.*)/'))
        comCCseconds=tonumber(string.match(comCCrate,'/(.*)'))
        local useragent = clientdata[4]
        local uid = string.match(useragent,"/.*/(%d+)$")

        if tonumber(uid) ~= nil and  tonumber(uid) > 0 then
            token = clientdata[1]..host..uri.."_"..uid
            clientcom = clientdata[1]..host
            clientip = clientdata[1]
        else
            token = clientdata[1]..host..uri
            clientcom = clientdata[1]..host
            clientip = clientdata[1]
        end

        local limit = ngx.shared.limit
        local iplimit = ngx.shared.iplimit
        local blockiplimit = ngx.shared.blockiplimit
        local blocklimit = ngx.shared.blocklimit
        local comlimit = ngx.shared.comlimit
        local blockcomlimit = ngx.shared.blockcomlimit

        local req,_=limit:get(token)
        local blockreq,_=blocklimit:get(token)
        local ipreq,_=iplimit:get(clientip)
        local blockipreq,_=blockiplimit:get(clientip)
        local comreq,_=comlimit:get(clientcom)
        local blockcomreq,_=blockcomlimit:get(clientcom)

        local cishu = tostring(req)..tostring(blockreq)..tostring(comreq)..tostring(blockcomreq)..tostring(ipreq)..tostring(blockipreq)

        if blockipreq or ipreq then
            if blockcomreq or comreq then
                if blockreq or req then
                    if blockipreq or ipreq >= ipCCcount then
                        rulestype = "ip"
                        log(ccdenyrules,clientdata,token,cishu,rulestype)
                        blockiplimit:set(clientip,1,30)
                        ngx.exit(403)
                        return true
                    else
                        iplimit:incr(clientip,1)
                        if blockcomreq or comreq >= comCCcount then
                            rulestype = "com"
                            log(ccdenyrules,clientdata,token,cishu,rulestype)
                            blockcomlimit:set(clientcom,1,30)
                            ngx.exit(403)
                            return true
                        else
                            comlimit:incr(clientcom,1)
                            if blockreq or req >= CCcount then
                                rulestype = "uid"
                                log(ccdenyrules,clientdata,token,cishu,rulestype)
                                blocklimit:set(token,1,30)
                                ngx.exit(403)
                                return true
                            else
                                limit:incr(token,1)
                            end
                        end
                    end
                else
                    limit:set(token,1,CCseconds)
                end
            else
                comlimit:set(clientcom,1,comCCseconds)
            end
        else
            iplimit:set(clientip,1,ipCCseconds)
        end


    end
    return false
end

function getheaders()
        local header=""
        local headerstring = ngx.req.get_headers() or {}
        for key, val in pairs(headerstring) do
                if type(val) == "table" then
                        header=header..key..table.concat(val, "")
                elseif type(val) == "boolean" then
                        header=header..key
                else
                        header=header..key..val
                end
        end
        header=tostring(header)
        return header
end

function getargs()
        local args=""
        local argsstring = ngx.req.get_uri_args() or {}
        for key,val in pairs(argsstring) do
                if type(val) == "table" then
                        args=args..key..table.concat(val, "")
                elseif type(val) == "boolean" then
                        args=args..key
                else
                        args=args..key..val
                end
        end
        args=tostring(args)
        return args
end

function postargs()
        ngx.req.read_body()
        local post=""
        local args, err = ngx.req.get_post_args() or {}
        for key, val in pairs(args) do
                if type(val) == "table" then
                        post=post..key..table.concat(val, "")
                elseif type(val) == "boolean" then
                        post=post..key
                else
                        post=post..key..val
                end
        end
        post=tostring(post)
        return post
end

function yesorno(data)
        if data~=nil then
                return data
        else
                return "unknow"
        end
end

function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(rules,clientdata,token,cishu,rulestype)
    if attacklog then
        if rules[6]=="logon" then
            local servername=ngx.var.server_name
            local nowtime=ngx.var.time_local or "-"
            local request=ngx.var.request or "_"
            local nowstatus=ngx.var.status or "_"
            local bodybyte=ngx.var.body_bytes_sent or "_"
            local xforward=ngx.var.http_x_forwarded_for or "_"
            line = clientdata[1].."["..nowtime.."]".." \""..request.."\" "..nowstatus.." "..bodybyte.." \""..clientdata[3].."\" \""..clientdata[4].."\" \""..xforward.."\" \""..rulestype.."\" "..token.." " ..cishu.. "\n"
            local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
            write(filename,line)
        end
    end
end

function main()
        if SecRuleEngine=="on" then
                local ip=yesorno(ngx.var.remote_addr)
                local uri=yesorno(ngx.var.uri)
                local referer=yesorno(ngx.var.http_referer)
                local useragent=yesorno(ngx.var.http_user_agent)
                local cookie=yesorno(ngx.var.http_cookie)
                local method=yesorno(ngx.req.get_method())
                local args=""
                local post=""
                local header=yesorno(getheaders())
--[[
                if method=="GET" then
                        args=yesorno(ngx.unescape_uri(getargs()))
                elseif method=="POST" then
                        post=yesorno(ngx.unescape_uri(postargs()))
                else
                        ngx.exit(403)
                end
--]]
                clientdata={ip,uri,referer,useragent,cookie,args,post,method,header}
                if ip ~= "127.0.0.1" then
                    if denycc(clientdata) then
                    else
                        return
                    end
                end
        else
                return
        end
end

main()
