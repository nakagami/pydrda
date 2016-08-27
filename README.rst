=============
pydrda
=============

This is a DRDA protocol (https://en.wikipedia.org/wiki/DRDA) python database driver.

We target *Apache Derby* now, and will add *DB2*.

Requirements
=============

- Python 3.5


Installation
=============

::

    $ pip install pydrda


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

