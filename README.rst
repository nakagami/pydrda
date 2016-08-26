=============
pydrda
=============

DRDA protocol python database driver

https://en.wikipedia.org/wiki/DRDA

Requirements
-----------------

- Python 3.5


Installation
-----------------

::

    $ pip install pydrda

Example
-----------------

Apache Derby::

   import drda

   conn = drda.connect(host='servername', databse='dbname', port=1527)
   cur = conn.cursor()
   cur.execute('select * from foo')
   for r in cur.fetchall():
       print(r[0], r[1])

