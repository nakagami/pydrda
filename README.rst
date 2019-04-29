=============
pydrda
=============

This is a DRDA protocol (https://en.wikipedia.org/wiki/DRDA) python database driver.

Requirements
=============

- Python 3.5


Installation
=============

::

    $ pip install pydrda


Db2 example
======================

::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', user='user', password='password', port=50000)
   cur = conn.cursor()
   cur.execute('select * from foo')
   for r in cur.fetchall():
       print(r[0], r[1])


Apache Derby example
======================

You need Start the Network server. http://db.apache.org/derby/papers/DerbyTut/ns_intro.html#start_ns
::

   import drda

   conn = drda.connect(host='serverhost', database='dbname', port=1527)
   cur = conn.cursor()
   cur.execute('select * from foo')
   for r in cur.fetchall():
       print(r[0], r[1])


Restriction
======================

- SECMEC=1 (SECMEC_USRIDONL) for derby
- SECMEC=3 (SECMEC_USRIDPWD) for DB2

Because Db2 on IBM cloud needs SECMEC=9, this driver can't connect to Db2 on IBM cloud.

