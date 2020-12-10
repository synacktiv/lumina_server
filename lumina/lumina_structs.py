import socket
import construct as con
from construct import (
    Byte, Bytes, Int8ub, Int16ub, Int16ul, Int16sb, Int32ub, Int32ul, Int64ub,
    CString, Hex,
    Struct, Array, Const, Rebuild, len_, this, FormatField,
    byte2int, int2byte, stream_read, stream_write, Construct, singleton, IntegerError, integertypes,
    Container,
    )

IDA_PROTOCOLE_VERSION = 2

#######################################
#
# Construct adapters
#
# Each adapter handles (de)serialization of variable length integer
#######################################

@singleton
class IdaVarInt16(Construct):
    r"""
    construct adapter that handles (de)serialization of variable length int16 (see pack_dw/unpack_dw in IDA API)
    """

    def _parse(self, stream, context, path):
        b = byte2int(stream_read(stream, 1, path))
        extrabytes, mask = [
            # lookup table
            [0, 0xff], # (0b0xxxxxxx)
            [0, 0xff], # (0b0xxxxxxx)
            [1, 0x7f], # 0x80 (0b10xxxxxx)
            [2, 0x00]  # 0xC0 (0b11xxxxxx)
        ][b >> 6]

        num = b & mask
        for _ in range(extrabytes):
            num = (num << 8) + byte2int(stream_read(stream, 1, path))

        return num

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, integertypes):
            raise IntegerError("value is not an integer", path=path)
        if obj < 0:
            raise IntegerError("cannot build from negative number: %r" % (obj,), path=path)
        if obj > 0xFFFF:
            raise IntegerError("cannot build from number above short range: %r" % (obj,), path=path)

        x = obj

        if (x > 0x3FFF):
            x |= 0xFF0000
            nbytes = 3
        elif (x > 0x7F):
            x |= 0x8000
            nbytes = 2
        else:
            nbytes = 1

        for i in range(nbytes, 0, -1):
            stream_write(stream, int2byte((x >> (8*(i-1))) & 0xFF), 1, path)

        return obj

@singleton
class IdaVarInt32(Construct):
    r"""
    construct adapter that handles (de)serialization of variable length int32 (see pack_dd/unpack_dd in IDA API)
    """

    def _parse(self, stream, context, path):
        b = byte2int(stream_read(stream, 1, path))
        extrabytes, mask = [
            [0, 0xff], [0, 0xff], [0, 0xff], [0, 0xff], # (0b0..xxxxx)
            [1, 0x7f], [1, 0x7f], # 0x80 (0b10.xxxxx)
            [3, 0x3f], # 0xC0 (0b110xxxxx)
            [4, 0x00]  # 0xE0 (0b111xxxxx)
        ][b>>5]

        num = b & mask
        for _ in range(extrabytes):
            num = (num << 8) + byte2int(stream_read(stream, 1, path))

        return num


    def _build(self, obj, stream, context, path):
        if not isinstance(obj, integertypes):
            raise IntegerError("value is not an integer", path=path)
        if obj < 0:
            raise IntegerError("cannot build from negative number: %r" % (obj,), path=path)
        if obj > 0xFFFFFFFF:
            raise IntegerError("cannot build from number above integer range: %r" % (obj,), path=path)
        x = obj

        if (x > 0x1FFFFFFF):
            x |= 0xFF00000000
            nbytes = 5
        elif (x > 0x3FFF):
            x |= 0xC0000000
            nbytes = 4
        elif (x > 0x7F):
            x |= 0x8000
            nbytes = 2
        else:
            nbytes = 1

        for i in range(nbytes, 0, -1):
            stream_write(stream, int2byte((x >> (8*(i-1))) & 0xFF), 1, path)

        return obj

@singleton
class IdaVarInt64(Construct):
    """
    construct adapter that handles (de)serialization of variable length int64 (see pack_dq/unpack_dq in IDA API)
    """

    def _parse(self, stream, context, path):
        low = IdaVarInt32._parse(stream, context, path)
        high = IdaVarInt32._parse(stream, context, path)
        num = (high << 32) | low
        return num

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, integertypes):
            raise IntegerError("value is not an integer", path=path)
        if obj < 0:
            raise IntegerError("cannot build from negative number: %r" % (obj,), path=path)
        if obj > 0xFFFFFFFFFFFFFFFF:
            raise IntegerError("cannot build from number above short range: %r" % (obj,), path=path)

        low = obj & 0xFFFFFFFF
        IdaVarInt32._build(low, stream, context, path)
        high = obj >> 32
        IdaVarInt32._build(high, stream, context, path)

        return obj




#######################################
#
# Basic types & helpers
#
#######################################

# String prefixed with a variable int size
VarString = con.PascalString(IdaVarInt32, "utf8")
# Bytes buffer prefixed with a variable int size
VarBuff = con.Prefixed(IdaVarInt32, con.GreedyBytes)
# IDA typedefs
ea_t = asize_t = adiff_t = con.ExprAdapter(IdaVarInt64, con.obj_-1, con.obj_+1)

# "template" for defining object list, prefixed with a variable int size
def ObjectList(obj):
    return con.PrefixedArray(IdaVarInt32, obj)


#######################################
#
# Lumina types
#
#######################################

# function signature
func_sig_t = con.Struct(
    "version" / Const(1, IdaVarInt32),  # protocol version (con.Default: 1)
    "signature" / VarBuff               # signature buffer
    )

# a.k.a func_info_t
func_metadata = con.Struct(
    "func_name" / CString("utf8"),      # function name
    "func_size" / IdaVarInt32,          # function size in bytes
    "serialized_data" / VarBuff         # metadata
    )

# extended func_metadata
func_info_t = con.Struct(
    "metadata" / func_metadata,                   #
    "popularity" / con.Default(IdaVarInt32, 0),   # unknown
    )

func_md_t = con.Struct(
    "metadata" / func_metadata,
    "signature" / func_sig_t
    )

# same as func_md_t with extra (unknown) field
func_md2_t = con.Struct(
    "metadata" / func_metadata,
    "signature" / func_sig_t,
    "field_0x58" / Hex(Const(0, IdaVarInt32)),
    )

#######################################
#
# Lumina message types
#
#######################################

RPC_TYPE = con.Enum(Byte,
    RPC_OK = 0xa,
    RPC_FAIL = 0xb,
    RPC_NOTIFY = 0xc,
    RPC_HELO = 0xd,
    PULL_MD = 0xe,
    PULL_MD_RESULT = 0xf,
    PUSH_MD = 0x10,
    PUSH_MD_RESULT = 0x11,
    # below messages are not implemented or not used by Lumina. Enjoy yourselves ;)
    GET_POP = 0x12,
    GET_POP_RESULT = 0x13,
    LIST_PEERS = 0x14,
    LIST_PEERS_RESULT = 0x15,
    KILL_SESSIONS = 0x16,
    KILL_SESSIONS_RESULT = 0x17,
    DEL_ENTRIES = 0x18,
    DEL_ENTRIES_RESULT = 0x19,
    SHOW_ENTRIES = 0x1a,
    SHOW_ENTRIES_RESULT = 0x1b,
    DUMP_MD = 0x1c,
    DUMP_MD_RESULT = 0x1d,
    CLEAN_DB = 0x1e,
    DEBUGCTL = 0x1f
)

RpcMessage_FAIL = con.Struct(
    "status" / IdaVarInt32,
    "message" / CString("utf-8"),                   # null terminated string
)

RpcMessage_HELO = con.Struct(
    "protocole" / con.Default(IdaVarInt32, IDA_PROTOCOLE_VERSION),
    "hexrays_licence" / VarBuff,                    # ida.key file content
    "hexrays_id" / Hex(Int32ul),                    # internal licence_info
    "watermak" / Hex(Int16ul),                      # internal licence_info
    "field_0x36" / IdaVarInt32,                     # always zero ?
)

RpcMessage_NOTIFY = con.Struct(
    "protocole" / con.Default(IdaVarInt32, IDA_PROTOCOLE_VERSION),
    "message" / CString("utf-8"),                   # null terminated string
)

RpcMessage_PULL_MD  = con.Struct(
    "flags" / IdaVarInt32,
    "ukn_list" / ObjectList(IdaVarInt32),           # list of IdaVarInt32
    "funcInfos" / ObjectList(func_sig_t)            # list of func_sig_t
)

RpcMessage_PULL_MD_RESULT = con.Struct(
    "found" / ObjectList(IdaVarInt32),              # list of boolean for each request in PULL_MD (1 if matching/found)
    "results" / ObjectList(func_info_t)             # list of func_info_t for each matching result
)

RpcMessage_PUSH_MD = con.Struct(
    "field_0x10" / IdaVarInt32,
    "idb_filepath" / CString("utf-8"),              # absolute file path of current idb
    "input_filepath" / CString("utf-8"),            # absolute file path of input file
    "input_md5" / Bytes(16),                        # input file md5
    "hostname" / CString("utf-8"),                  # machine name
    "funcInfos" / ObjectList(func_md_t),            # list of func_md_t to push
    "funcEas" / ObjectList(IdaVarInt64),            # absolute (!?) address of each pushed function
)


RpcMessage_PUSH_MD_RESULT = con.Struct(
    "resultsFlags" / ObjectList(IdaVarInt32),       # status for each function pushed
)



# Generic RPC message 'union'
RpcMessage = con.Switch(this.code,
        {
            RPC_TYPE.RPC_OK : con.Pass,
            RPC_TYPE.RPC_FAIL : RpcMessage_FAIL,
            RPC_TYPE.RPC_NOTIFY : RpcMessage_NOTIFY,
            RPC_TYPE.RPC_HELO : RpcMessage_HELO,
            RPC_TYPE.PULL_MD : RpcMessage_PULL_MD,
            RPC_TYPE.PULL_MD_RESULT : RpcMessage_PULL_MD_RESULT,
            RPC_TYPE.PUSH_MD : RpcMessage_PUSH_MD,
            RPC_TYPE.PUSH_MD_RESULT : RpcMessage_PUSH_MD_RESULT,
            #RPC_TYPE.GET_POP : RpcMessage_GET_POP,
            #RPC_TYPE.GET_POP_RESULT : RpcMessage_GET_POP_RESULT,
            #RPC_TYPE.LIST_PEERS : RpcMessage_LIST_PEERS,
            #RPC_TYPE.LIST_PEERS_RESULT : RpcMessage_LIST_PEERS_RESULT,
            #RPC_TYPE.KILL_SESSIONS : RpcMessage_KILL_SESSIONS,
            #RPC_TYPE.KILL_SESSIONS_RESULT : RpcMessage_KILL_SESSIONS_RESULT,
            #RPC_TYPE.DEL_ENTRIES : RpcMessage_DEL_ENTRIES,
            #RPC_TYPE.DEL_ENTRIES_RESULT : RpcMessage_DEL_ENTRIES_RESULT,
            #RPC_TYPE.SHOW_ENTRIES : RpcMessage_SHOW_ENTRIES,
            #RPC_TYPE.SHOW_ENTRIES_RESULT : RpcMessage_SHOW_ENTRIES_RESULT,
            #RPC_TYPE.DUMP_MD : RpcMessage_DUMP_MD,
            #RPC_TYPE.DUMP_MD_RESULT : RpcMessage_DUMP_MD_RESULT,
            #RPC_TYPE.CLEAN_DB : RpcMessage_CLEAN_DB,
            #RPC_TYPE.DEBUGCTL : RpcMessage_DEBUGCTL,
        },
        default = None
    )

# RPC packet common header
rpc_packet_t = con.Struct(
    "length" / Rebuild(Hex(Int32ub), len_(this.data)),
    "code" / RPC_TYPE,
    "data" / con.HexDump(con.Bytes(this.length))
    )

def rpc_message_build(code, **kwargs):
    """
    Build and serialize an RPC packet
    """
    data = RpcMessage.build(kwargs, code = code)

    return rpc_packet_t.build(Container(code = code,
        data = data)
    )

def rpc_message_parse(source):
    """
    Read and deserilize RPC message from a file-like object or socket)
    """
    if isinstance(source, str):
        # parse source as filename
        packet = rpc_packet_t.parse_stream(source)
    elif isinstance(source, bytes):
        # parse source as bytes
        packet = rpc_packet_t.parse(source)
    else:
        # parse source as file-like object
        if isinstance(source, socket.socket):
            # construct requires a file-like object with read/write methods:
            source = source.makefile(mode='rb')

        packet = rpc_packet_t.parse_stream(source)

    message = RpcMessage.parse(packet.data , code = packet.code)
    # Warning: parsing return a Container object wich hold a io.BytesIO to the socket
    # see https://github.com/construct/construct/issues/852
    return packet, message
