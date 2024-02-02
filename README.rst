=============
pydrda
=============

This is a DRDA protocol (https://en.wikipedia.org/wiki/DRDA) database driver.

- Pure python
- Compliant with PEP-249 (https://www.python.org/dev/peps/pep-0249/)

Requirements
=============

- Python 3.8+


Installation
=============

::

    $ pip install pydrda

If you want to connect to Db2, you may need to install pyDes.

::

    $ pip install pyDes


Supported Databases
======================


Db2
------------------------

https://www.ibm.com/analytics/db2

Example

No SSL
+++++++++++++++++++++++++++++++++++++++++

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', user='user', password='password', port=xxxxx)
   cur = conn.cursor()
   cur.execute('select * from foo where name=?', ['alice'])
   for r in cur.fetchall():
       print(r[0], r[1])

With SSL connection
+++++++++++++++++++++++++++++++++++++++++

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', use_ssl=True, user='user', password='password', port=xxxxx)
   cur = conn.cursor()
   cur.execute('select * from foo where name=?', ['alice'])
   for r in cur.fetchall():
       print(r[0], r[1])

With SSL and client certificate
+++++++++++++++++++++++++++++++++++++++++

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', use_ssl=True, ssl_ca_certs='/some/what/path/cert.crt', user='user', password='password', port=xxxxx)



Apache Derby
==============

https://db.apache.org/derby/

You need to start derby as a network server.
http://db.apache.org/derby/papers/DerbyTut/ns_intro.html#start_ns

Example

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', port=1527)
   cur = conn.cursor()
   cur.execute('select * from foo')
   for r in cur.fetchall():
       print(r[0], r[1])

This driver can't execute with parameters against Apache Derby.

Unit Tests
================

I have tested the following steps.

Db2
------

Start Db2 server
::

   $ docker run -itd --name db2 --privileged=true -p 50000:50000 -e LICENSE=accept -e DB2INST1_PASSWORD=password -e DBNAME=testdb --platform=linux/amd64 icr.io/db2_community/db2

Execute test
::

   $ python test_db2.py

Apache Derby
---------------

Install Apatch Derby https://db.apache.org/derby/ and start as a server
::

   $ curl -O https://downloads.apache.org//db/derby/db-derby-10.15.2.0/db-derby-10.15.2.0-bin.tar.gz
   $ tar zxf db-derby-10.15.2.0-bin.tar.gz
   $ echo 'grant {permission java.lang.RuntimePermission "getenv.SOURCE_DATE_EPOCH", "read";};' > ${HOME}/.java.policy
   $ db-derby-10.15.2.0-bin/bin/startNetworkServer &

Execute test
::

   $ python test_derby.py
