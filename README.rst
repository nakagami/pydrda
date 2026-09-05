=============
pydrda
=============

This is a DRDA protocol (https://en.wikipedia.org/wiki/DRDA) database driver.

Currently, we support only DB2.

- Pure python
- Compliant with PEP-249 (https://www.python.org/dev/peps/pep-0249/)

Requirements
=============

- Python 3.11+


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
-------

No SSL
+++++++++++++++++++++++++++++++++++++++++

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', user='user', password='password', port=xxxxx, timeout=30)
   cur = conn.cursor()
   cur.execute('select * from foo where name=?', ['alice'])
   for r in cur.fetchall():
       print(r[0], r[1])
   conn.close()

With SSL connection
+++++++++++++++++++++++++++++++++++++++++

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', use_ssl=True, user='user', password='password', port=xxxxx)
   cur = conn.cursor()
   cur.execute('select * from foo where name=?', ['alice'])
   for r in cur.fetchall():
       print(r[0], r[1])
   conn.close()

With SSL and CA certificate
+++++++++++++++++++++++++++++++++++++++++

To connect to a server with a self-signed certificate or custom CA (such as IBM Db2 on Cloud), pass the server's CA certificate file path via ``ssl_client_cert_path``:

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', use_ssl=True, ssl_client_cert_path='/path/to/ca-cert.crt', user='user', password='password', port=xxxxx)
   cur = conn.cursor()
   cur.execute('select * from foo where name=?', ['alice'])
   for r in cur.fetchall():
       print(r[0], r[1])
   conn.close()

Context Manager and Cursor Iteration
+++++++++++++++++++++++++++++++++++++++++

Connections and cursors support Python context managers (``with`` statement), and cursors can be iterated directly without calling ``fetchall()``:

::

   import drda

   with drda.connect(host='serverhost', database='dbname', user='user', password='password', port=xxxxx) as conn:
       with conn.cursor() as cur:
           cur.execute('select * from foo where name=?', ['alice'])
           for r in cur:
               print(r[0], r[1])

Transactions
+++++++++++++++++++++++++++++++++++++++++

Transactions can be explicitly committed or rolled back:

::

   cur.execute("insert into foo values (?, ?)", [1, 'alice'])
   conn.commit()

   # Or rollback changes:
   # conn.rollback()

AsyncIO
+++++++++++++++++++++++++++++++++++++++++

::

   import asyncio
   import drda.aio

   async def main():
       async with await drda.aio.connect(host='serverhost', database='dbname', user='user', password='password', port=xxxxx, timeout=30) as conn:
           async with conn.cursor() as cur:
               await cur.execute('select * from foo where name=?', ['alice'])
               async for r in cur:
                   print(r[0], r[1])

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

Optional environment variables for tests:

- ``DB2_HOST`` (default: ``localhost``)
- ``DB2_PORT`` (default: ``50000``)
- ``DB2_DATABASE`` (default: ``testdb``)
- ``DB2_USER`` (default: ``db2inst1``)
- ``DB2_PASSWORD`` (default: ``password``)
- ``SSL_CLIENT_CERT_PATH`` (default: ``None``)
