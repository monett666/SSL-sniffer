# SSL-sniffer
Simple sniffer of SSL traffic. 

### How to run:

`sslsniff [-r <file>] [-i interface]`

* -r: pcapng file with network traffic
* -i: network interface on witch will the app listen (live)

### Output format

`<timestamp>,<client ip>,<client port>,<server ip>,<SNI>,<bytes>,<packets>,<duration sec>`

Example:

<pre>2020-09-22 14:12:47.838588,2a00:1028:83a0:65aa:21ae:c290:d8bd:4b66,51416,2001:67c:1220:809::93e5:91a,www.fit.vut.cz,99421,120,0.175</pre>
