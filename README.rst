=============
pydrda
=============

This is a DRDA protocol (https://en.wikipedia.org/wiki/DRDA) database driver.

- Pure python
- Compliant with PEP-249 (https://www.python.org/dev/peps/pep-0249/)

Requirements
=============

- Python 3.5+


Installation
=============

::

    $ pip install pydrda

Supported Databases
======================


Db2
------------------------

https://www.ibm.com/analytics/db2

Example

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', user='user', password='password', port=50000)
   cur = conn.cursor()
   cur.execute('select * from foo where name=?', ['alice'])
   for r in cur.fetchall():
       print(r[0], r[1])

(with ssl connection)

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', use_ssl=True, user='user', password='password', port=50001)
   cur = conn.cursor()
   cur.execute('select * from foo where name=?', ['alice'])
   for r in cur.fetchall():
       print(r[0], r[1])


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
