=============
pydrda
=============

This is a DRDA protocol (https://en.wikipedia.org/wiki/DRDA) database driver.

Currently, we support only DB2.

- Pure python
- Compliant with PEP-249 (https://www.python.org/dev/peps/pep-0249/)

Requirements
=============

- Python 3.8+


Installation
=============

::

    $ pip install pydrda

pyDes is required and is installed automatically as a dependency.


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

   conn = drda.connect(host='serverhost', database='dbname', user='user', password='password', port=xxxxx, timeout=30)
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

   conn = drda.connect(host='serverhost', database='dbname', use_ssl=True, ssl_client_cert_path='/some/what/path/cert.crt', user='user', password='password', port=xxxxx)

AsyncIO
+++++++++++++++++++++++++++++++++++++++++

::

   import asyncio
   import drda.aio

   async def main():
       conn = await drda.aio.connect(host='serverhost', database='dbname', user='user', password='password', port=xxxxx, timeout=30)
       cur = conn.cursor()
       await cur.execute('select * from foo where name=?', ['alice'])
       for r in await cur.fetchall():
           print(r[0], r[1])
       await conn.close()

   asyncio.run(main())

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
   $ python test_async_db2.py
