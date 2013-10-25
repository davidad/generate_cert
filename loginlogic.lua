local function loginlogic()
    local args = {}
    if ngx.var.request_method == "GET" then
        args = ngx.req.get_uri_args()
    else
        ngx.req.read_body()
        args = ngx.req.get_post_args()
    end

    if((not args.email or #args.email<3) and (not args.token or #args.token<3)) then
        return no_query
    elseif (args.email) then
        local users = pg.query('/db/pre_send_token',{email = args.email})
        if(not users or #users==0) then
            local res, check = have_token(args.email)
            if(check) then
                return {"<p>Well, that's not an email address, but I do have a record of that token.</p>",res}
            else
                return unknown_email(args.email)
            end
        else
            local user = users[1]
            local output = loginwrap(sending_token(user))
            ngx.print(output)
            ngx.flush(true)
            pg.exec('/db/send_token',{email = args.email})
            return [[<script>
                    $("section.login span.status")[0].innerHTML="has sent";
                    </script>]],true
        end
    elseif (not args.keygen) then
        local res = have_token(args.token)
        return res
    else
        local cert = ''
        if (not args.spkac or #args.spkac==0) then
            local p12s = pg.query('/db/generate_p12',{token=args.token,device=(args.device or '')})
            if(#p12s==0) then
                return failed_cert;
            else
                local p12 = p12s[1].p12
                cert = ngx.decode_base64(p12)
                ngx.header['Content-Type']='application/x-pkcs12'
            end
        else
            local certs = pg.query('/db/generate_cert',{token=args.token,spkac=args.spkac,device=(args.device or '')})
            if(#certs==0) then
                return failed_cert;
            else
                local pem = certs[1].cert
                local b64 = ngx.re.gsub(pem,[=[-[^\n]+-|\n]=],'','io')
                cert = ngx.decode_base64(b64)
                ngx.header['Content-Type']='application/x-x509-user-cert'
            end
        end
        ngx.header['Content-Length']=#cert
        if ngx.var.cookie_into then
            ngx.header['Refresh']='1;url='..ngx.var.cookie_into
        end
        ngx.print(cert)
        ngx.exit(0)
    end
end