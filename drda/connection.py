##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2016-2026 Hajime Nakagami<nakagami@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
##############################################################################
import io
import socket
import ssl
import platform
import locale
import collections

from drda import codepoint as cp
from drda import consts
from drda import ddm
from drda import secmec9
from drda import utils
from drda.cursor import Cursor


def _infer_params_description(args):
    """Infer DRDA parameter descriptions from Python value types.

    Used as a fallback when the server (e.g. Derby) does not return
    a parameter SQLDARD in response to DSCSQLSTT.
    """
    import datetime
    import decimal as _decimal
    description = []
    for v in args:
        if v is None or isinstance(v, str):
            d = ('?', consts.DB2_SQLTYPE_NVARCHAR, 32672, 32672, 32672, 0, None)
        elif isinstance(v, bool):
            d = ('?', consts.DB2_SQLTYPE_NBOOLEAN, 1, 1, 1, 0, None)
        elif isinstance(v, int):
            if abs(v) > 2147483647:
                d = ('?', consts.DB2_SQLTYPE_NBIGINT, 8, 8, 19, 0, None)
            else:
                d = ('?', consts.DB2_SQLTYPE_NINTEGER, 4, 4, 10, 0, None)
        elif isinstance(v, float):
            d = ('?', consts.DB2_SQLTYPE_NFLOAT, 8, 8, 15, 0, None)
        elif isinstance(v, _decimal.Decimal):
            sign, digits, exponent = v.as_tuple()
            precision = max(len(digits), 1)
            scale = max(0, -exponent)
            d = ('?', consts.DB2_SQLTYPE_NDECIMAL, precision * 256 + scale, precision * 256 + scale, precision, scale, None)
        elif isinstance(v, datetime.datetime):
            d = ('?', consts.DB2_SQLTYPE_NTIMESTAMP, 32, 32, 0, 0, None)
        elif isinstance(v, datetime.date):
            d = ('?', consts.DB2_SQLTYPE_NDATE, 10, 10, 0, 0, None)
        elif isinstance(v, datetime.time):
            d = ('?', consts.DB2_SQLTYPE_NTIME, 8, 8, 0, 0, None)
        elif isinstance(v, (bytes, bytearray)):
            d = ('?', consts.DB2_SQLTYPE_NVARBINARY, len(v), len(v), len(v), 0, None)
        else:
            d = ('?', consts.DB2_SQLTYPE_NVARCHAR, 32672, 32672, 32672, 0, None)
        description.append(d)
    return description


def _replace_binary_params(query, args, params_description):
    binary_param_indices = {
        i for i, d in enumerate(params_description)
        if d[1] == consts.DB2_SQLTYPE_NBLOB and isinstance(args[i], (bytes, bytearray))
    }
    if not binary_param_indices:
        return None

    rewritten_query = []
    rewritten_args = []
    param_index = 0
    in_string = False
    i = 0
    while i < len(query):
        c = query[i]
        if c == "'":
            rewritten_query.append(c)
            if in_string and i + 1 < len(query) and query[i + 1] == "'":
                rewritten_query.append(query[i + 1])
                i += 2
                continue
            in_string = not in_string
        elif c == '?' and not in_string:
            if param_index >= len(args):
                return None
            if param_index in binary_param_indices:
                rewritten_query.append("BLOB(X'{}')".format(bytes(args[param_index]).hex()))
            else:
                rewritten_query.append(c)
                rewritten_args.append(args[param_index])
            param_index += 1
        else:
            rewritten_query.append(c)
        i += 1

    if param_index != len(args):
        return None
    return ''.join(rewritten_query), rewritten_args


class Connection:
    def _parse_response(self, continue_on_sqldard_only=False):
        results = collections.deque()
        params_description = None
        description = None
        err = qrydsc = None
        chained = True
        err_msg = None

        more_data = False
        need_cntqry = False  # set by OPNQRYRM; survives subsequent read_dss calls
        qryinsid = 0         # query instance ID from OPNQRYRM, needed for CNTQRY on LOB queries
        cntqry_cur_id = 1    # correlation ID to use for CNTQRY (matches the OPNQRY request)
        extdta_list = []     # accumulate EXTDTA objects for LOB columns
        while True:
            while chained:
                dss_type, chained, correlation_id, code_point, obj, more_data = ddm.read_dss(self.sock, self.db_type)
                _X_chained = False
                while more_data:
                    # server is waiting for us to request more query data
                    # may want to check code_point here
                    ddm.write_request_dss(
                        self.sock,
                        ddm.packCNTQRY(
                            self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz,
                        ),
                        1, False, True
                    )
                    _X_dss_type, _X_chained, _X_correlation_id, _X_xcode_point, extra_obj, more_data = ddm.read_dss(self.sock,self.db_type)
                    obj += extra_obj
                # Drain any chained packets (e.g. ENDQRYRM, SQLCARD) after the last page
                while _X_chained:
                    _X_dss_type, _X_chained, _X_correlation_id, _X_code_point, _drain_obj, _ = ddm.read_dss(self.sock, self.db_type)
                    if _X_code_point == cp.ENDQRYRM:
                        need_cntqry = False
                    elif _X_code_point == cp.SQLCARD:
                        if err is None:
                            err, _ = ddm.parse_sqlcard(_drain_obj, self.encoding, self.endian)
                if code_point == cp.SQLERRRM:
                    err_msg = ddm.parse_reply(obj).get(cp.SRVDGN)
                elif code_point == cp.SQLCARD:
                    if err is None:
                        err, _ = ddm.parse_sqlcard(obj, self.encoding, self.endian)
                elif code_point == cp.SQLDARD:
                    if obj[0] == 0xFF:
                        err, params_description = ddm.parse_sqldard(
                            obj, 'utf-8', self.endian, self.db_type
                        )
                    elif description is None:
                        # First SQLDARD (obj[0]=0x00): result column descriptions
                        err, description = ddm.parse_sqldard(
                            obj, 'utf-8', self.endian, self.db_type
                        )
                    else:
                        # Second SQLDARD (obj[0]=0x00): parameter descriptions.
                        # Derby sends both SQDARDs with obj[0]=0x00 (unlike Db2 which uses
                        # obj[0]=0xFF for the params SQLDARD).
                        err, params_description = ddm.parse_sqldard(
                            obj, 'utf-8', self.endian, self.db_type
                        )
                elif code_point == cp.OPNQRYRM:
                    cntqry_cur_id = correlation_id  # must match the OPNQRY request's ID
                    qryinsid_bytes = ddm.parse_reply(obj).get(cp.QRYINSID, bytes(8))
                    qryinsid = int.from_bytes(qryinsid_bytes, 'big')
                    if self.db_type == 'db2':
                        # Db2 always requires CNTQRY after OPNQRYRM.
                        # Derby does NOT: for CLOB columns, Derby sends OPNQRYRM+QRYDSC
                        # (no QRYDTA) and hangs if CNTQRY is sent unexpectedly.
                        # Derby pagination is handled in the QRYDTA handler below.
                        need_cntqry = True
                elif code_point in (cp.ENDQRYRM, cp.ENDUOWRM):
                    more_data = False
                    need_cntqry = False
                elif code_point == cp.EXTDTA:
                    extdta_list.append(obj)
                elif code_point == cp.QRYDSC:
                    ln = obj[0]
                    b = obj[1:ln]
                    assert b[:2] == b'\x76\xd0'
                    b = b[2:]
                    # [(DRDA_TYPE_xxxx, size_binary), ...]
                    qrydsc = [(c[0], c[1:]) for c in [b[i:i+3] for i in range(0, len(b), 3)]]
                elif code_point == cp.QRYDTA:
                    rows_before = len(results)
                    stream = io.BytesIO(obj)
                    try:
                        while b := utils.read_from_stream(stream, 2):
                            if b[0] != 0xff:
                                break
                            r = []
                            for t, ps in qrydsc:
                                v = utils.read_field(t, ps, stream, self.endian)
                                r.append(v)
                            results.append(tuple(r))
                    except Exception:
                        pass
                    rows_added = len(results) - rows_before
                    if rows_added == 0:
                        # Empty QRYDTA = Derby's end-of-data signal
                        need_cntqry = False
                    elif self.db_type == 'derby':
                        # Derby multi-page: received rows, request next page via CNTQRY
                        need_cntqry = True

            if need_cntqry:
                cntqry_pkt = ddm.packCNTQRY(
                    self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz,
                    qryinsid=qryinsid,
                )
                ddm.write_request_dss(self.sock, cntqry_pkt, cntqry_cur_id, False, True)
                chained = True  # must read the CNTQRY response
            elif continue_on_sqldard_only and description is not None and qrydsc is None:
                # Derby CLOB: server sent SQLDARD(s) in chain 1 as the prepare response,
                # and is already sending chain 2 (OPNQRYRM+QRYDSC) for the OPNQRY we
                # included in the same request.  Keep reading without sending anything.
                chained = True
            else:
                break

        if extdta_list and qrydsc and results:
            _inline_lob_types = (
                utils.DRDA_TYPE_LOBBYTES, utils.DRDA_TYPE_NLOBBYTES,
                utils.DRDA_TYPE_LOBCSBCS, utils.DRDA_TYPE_NLOBCSBCS,
            )
            _lob_types = (
                utils.DRDA_TYPE_LOBLOC, utils.DRDA_TYPE_NLOBLOC,
                utils.DRDA_TYPE_CLOBLOC, utils.DRDA_TYPE_NCLOBLOC,
                utils.DRDA_TYPE_DBCSCLOBLOC, utils.DRDA_TYPE_NDBCSCLOBLOC,
            ) + _inline_lob_types
            _clob_types = (
                utils.DRDA_TYPE_CLOBLOC, utils.DRDA_TYPE_NCLOBLOC,
                utils.DRDA_TYPE_DBCSCLOBLOC, utils.DRDA_TYPE_NDBCSCLOBLOC,
                utils.DRDA_TYPE_LOBCSBCS, utils.DRDA_TYPE_NLOBCSBCS,
            )
            lob_col_indices = [i for i, (t, _) in enumerate(qrydsc) if t in _lob_types]
            extdta_idx = 0
            for row_idx in range(len(results)):
                row = list(results[row_idx])
                for col_idx in lob_col_indices:
                    if row[col_idx] is not None and extdta_idx < len(extdta_list):
                        data = extdta_list[extdta_idx]
                        if qrydsc[col_idx][0] in _inline_lob_types:
                            # EXTDTA for inline LOBs has a leading status byte (0x00 = valid)
                            data = data[1:]
                        if qrydsc[col_idx][0] in _clob_types:
                            if qrydsc[col_idx][0] in _inline_lob_types:
                                data = data.decode('utf-8')
                            else:
                                data = data.decode(self.encoding)
                        row[col_idx] = data
                        extdta_idx += 1
                results[row_idx] = tuple(row)

        if err:
            raise err
        return results, description, params_description

    def _parse_accsecrd(self):
        secmec = sectkn = None
        chained = True
        while chained:
            dss_type, chained, correlation_id, code_point, obj, more_data = ddm.read_dss(self.sock, self.db_type)
            if code_point == cp.ACCSECRD:
                while len(obj):
                    ln = int.from_bytes(obj[:2], byteorder='big')
                    sub_cp = int.from_bytes(obj[2:4], byteorder='big')
                    v = obj[4:ln]
                    obj = obj[ln:]
                    if sub_cp == cp.SECMEC:
                        secmec = int.from_bytes(v[:2], byteorder='big')
                    elif sub_cp == cp.SECTKN:
                        sectkn = v
            elif code_point == cp.RDBNFNRM:
                from drda import DatabaseError
                raise DatabaseError(0, 0, "database not found")

        return secmec, sectkn

    def __init__(self, host, database, port, user, password, use_ssl, ssl_client_cert_path, db_type, timeout):
        self.host = host
        self.database = (database + ' ' * 18)[:18]
        self.port = port
        self.user = user
        self.password = password
        self.db_type = db_type
        if self.db_type is None:
            if self.user is None:
                self.db_type = 'derby'
            else:
                self.db_type = 'db2'

        self.secmec = consts.SECMEC_EUSRIDPWD
        if self.db_type == 'derby':
            self.encoding = 'utf-8'
            self.endian = 'big'
            self.prdid = 'DNC10130'
            self.pkgid = 'SQLC2026'
            self.pkgcnstkn = 'AAAAAfAd'
            self.pkgsn = 201
            self.qryblksz = 32767
            self.user = 'APP'
            self.password = ''
            self.secmec = consts.SECMEC_USRIDONL
            self.private_key = None
        elif self.db_type == 'db2':
            self.encoding = 'cp500'
            self.endian = 'little'
            self.prdid = 'SQL12010'
            self.pkgid = 'SYSSH200'
            self.pkgcnstkn = 'SYSLVL01'
            self.pkgsn = 65
            self.qryblksz = 65535
            self.private_key = secmec9.get_private()
        else:
            raise ValueError('Unknown database type:{}'.format(self.db_type))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if timeout is not None:
            self.sock.settimeout(timeout)
        if use_ssl:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if ssl_client_cert_path:
                # Load the server's CA certificate to verify the server's identity.
                # For self-signed servers (e.g. IBM Db2 on Cloud), pass the
                # certificate_base64-decoded PEM file here.
                context.load_verify_locations(ssl_client_cert_path)
            # server_hostname enables SNI and hostname verification.
            # Required by ssl.PROTOCOL_TLS_CLIENT (check_hostname=True).
            self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
        self.sock.connect((self.host, self.port))

        cur_id = 1
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packEXCSAT(self, [
                cp.AGENT, 10,
                cp.SQLAM, 11,
                cp.CMNTCPIP, 5,
                cp.RDB, 12,
                cp.SECMGR, 9,
                cp.UNICODEMGR, 1208,
            ]),
            cur_id, False, False
        )

        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packACCSEC(
                self.database,
                self.secmec,
                secmec9.calc_public(self.private_key).to_bytes(32, byteorder='big')
                if self.secmec == consts.SECMEC_EUSRIDPWD else None
            ),
            cur_id, False, True
        )

        secmec, sectkn = self._parse_accsecrd()

        cur_id = 1
        if secmec != self.secmec:
            self.secmec = secmec
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packACCSEC(
                    self.database,
                    self.secmec,
                    secmec9.calc_public(self.private_key).to_bytes(32, byteorder='big')
                    if self.secmec == consts.SECMEC_EUSRIDPWD else None
                ),
                cur_id, False, False
            )

        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packSECCHK(
                secmec,
                sectkn,
                self.private_key,
                self.database,
                self.user,
                self.password,
                self.encoding
            ),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packACCRDB(self.prdid, self.database, self.encoding),
            cur_id, False, True
        )

        self._parse_response()

        self._set_variables()

    def __enter__(self):
        return self

    def __exit__(self, exc, value, traceback):
        self.close()

    def _set_variables(self):
        lc_type = locale.getlocale()[0]
        if lc_type is None:
            lc_type = "en_US"
        cur_id = 1
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packEXCSAT_MGRLVLLS([cp.CCSIDMGR, 1208]),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packEXCSQLSET(self.pkgid, None, 1, self.database),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packSQLSTT("SET CLIENT WRKSTNNAME '{}'".format(platform.node())),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packSQLSTT("SET CURRENT LOCALE LC_CTYPE='{}'".format(lc_type)),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        self._parse_response()

    def _execute(self, query, args):
        if args:
            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packDSCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, False, True
            )
            _, _, params_description = self._parse_response()

            replaced = _replace_binary_params(query, args, params_description)
            if replaced:
                return self._execute(*replaced)

            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packEXCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLDTA(params_description, args, self.endian),
                cur_id, False, False
            )

            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            self._parse_response()
        else:
            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packEXCSQLIMM(
                    self.pkgid,
                    self.pkgcnstkn,
                    self.pkgsn,
                    self.database
                ),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            self._parse_response()

    def _query(self, query, args):
        if args:
            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packDSCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, False, True
            )
            _, description, params_description = self._parse_response()

            replaced = _replace_binary_params(query, args, params_description)
            if replaced:
                return self._query(*replaced)

            sqldta = ddm.packSQLDTA(params_description, args, self.endian)

            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packOPNQRY_with_params(
                    self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz,
                ),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                sqldta,
                cur_id, False, True
            )
            rows, _, _ = self._parse_response()

            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            _, _, _ = self._parse_response()

            return rows, description
        else:
            if self.db_type == 'derby':
                # Derby LOB/CLOB: when PRPSQLSTT+SQLSTT+OPNQRY are sent together,
                # Derby sends SQLDARD(s) first and then waits before responding to OPNQRY.
                # Sending OPNQRY as a separate round-trip avoids this stall.
                cur_id = 1
                cur_id = ddm.write_request_dss(
                    self.sock,
                    ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                    cur_id, True, False
                )
                cur_id = ddm.write_request_dss(
                    self.sock,
                    ddm.packSQLSTT(query),
                    cur_id, False, True
                )
                _, description, _ = self._parse_response()

                cur_id = 1
                cur_id = ddm.write_request_dss(
                    self.sock,
                    ddm.packOPNQRY(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz),
                    cur_id, False, True
                )
                rows, _, _ = self._parse_response()
            else:
                # Db2: send all three together so Db2 includes EXTDTA (LOB data) in the
                # same response chain.  Sending OPNQRY separately causes Db2 to omit
                # EXTDTA, resulting in empty BLOB/CLOB/XML values.
                # continue_on_sqldard_only=True handles the rare case where Db2 sends
                # SQLDARD(s) in a separate chain before OPNQRYRM+QRYDSC.
                cur_id = 1
                cur_id = ddm.write_request_dss(
                    self.sock,
                    ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                    cur_id, True, False
                )
                cur_id = ddm.write_request_dss(
                    self.sock,
                    ddm.packSQLSTT(query),
                    cur_id, False, False
                )
                cur_id = ddm.write_request_dss(
                    self.sock,
                    ddm.packOPNQRY(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz),
                    cur_id, False, True
                )
                rows, description, _ = self._parse_response(continue_on_sqldard_only=True)
            return rows, description

    def is_connect(self):
        return bool(self.sock)

    def cursor(self):
        return Cursor(self)

    def begin(self):
        self._execute("START TRANSACTION", [])

    def commit(self):
        self._execute("COMMIT", [])

    def rollback(self):
        self._execute("ROLLBACK", [])

    def close(self):
        cur_id = 1
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        self._parse_response()
        self.sock.close()
