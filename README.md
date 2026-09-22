# key-store-ssl-ssh-report

There are two mode for this command utility.

## Properties Mode

## Configuration File Mode

### Sample Command
<pre>java -jar keystore-ssl-ssh-report-0.0.1-SNAPSHOT.jar config=config.xml</pre>

### Sample Configuration File
<pre>&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
&lt;hosts&gt;
	&lt;host&gt;
		&lt;ip&gt;127.0.0.1&lt;/ip&gt;
		&lt;port&gt;2222&lt;/port&gt;
		&lt;user&gt;user&lt;/user&gt;
		&lt;password&gt;password&lt;/password&gt;
		&lt;keyStores&gt;
			&lt;keyStore&gt;
				&lt;path&gt;/etc/ssl/certs/java/cacerts&lt;/path&gt;
				&lt;passowrd&gt;password&lt;/passowrd&gt;
			&lt;/keyStore&gt;
		&lt;/keyStores&gt;
		&lt;urls&gt;
			&lt;url&gt;https://mvnrepository.com&lt;/url&gt;
		&lt;/urls&gt;
	&lt;/host&gt;
	&lt;host&gt;
		&lt;ip&gt;127.0.0.1&lt;/ip&gt;
		&lt;port&gt;2222&lt;/port&gt;
		&lt;user&gt;user&lt;/user&gt;
		&lt;password&gt;password&lt;/password&gt;
		&lt;keyStores&gt;
			&lt;keyStore&gt;
				&lt;path&gt;/etc/ssl/certs/java/cacerts&lt;/path&gt;
				&lt;passowrd&gt;password&lt;/passowrd&gt;
			&lt;/keyStore&gt;
		&lt;/keyStores&gt;
		&lt;urls&gt;
			&lt;url&gt;https://www.amazon.cn&lt;/url&gt;
		&lt;/urls&gt;
	&lt;/host&gt;
&lt;/hosts&gt;</pre>

### Sample Output
<pre>Host    =127.0.0.1
User    =user
File    =/etc/ssl/certs/java/cacerts
URL     =https://mvnrepository.com
KeyStore=mvnrepository.com         2026-12-05 19:22:43
HTTPS   =mvnrepository.com         2026-12-05 19:22:43
Host    =127.0.0.1
User    =user
File    =/etc/ssl/certs/java/cacerts
URL     =https://www.amazon.cn
KeyStore=www.amazon.cn             2027-04-04 07:59:59
HTTPS   =www.amazon.cn             2027-04-04 07:59:59
</pre>
