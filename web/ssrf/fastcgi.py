import struct
from dataclasses import dataclass
from typing import Tuple
import random

class FCGIRequestType:
    FCGI_BEGIN_REQUEST      = 1
    FCGI_ABORT_REQUEST      = 2
    FCGI_END_REQUEST        = 3
    FCGI_PARAMS             = 4
    FCGI_STDIN              = 5
    FCGI_STDOUT             = 6
    FCGI_STDERR             = 7
    FCGI_DATA               = 8
    FCGI_GET_VALUES         = 9
    FCGI_GET_VALUES_RESULT  = 10
    FCGI_UNKOWN_TYPE        = 11

class FCGIRecord:
    """FastCGI Record 结构体 - 使用struct完整定义"""
    
    # 定义完整的格式：所有字段一次性定义
    # >: 大端序网络字节序
    # B: unsigned char (1字节)
    # B: unsigned char
    # H: unsigned short (2字节) - requestId
    # H: unsigned short (2字节) - contentLength
    # B: unsigned char - paddingLength
    # B: unsigned char - reserved
    # {contentLength}s: 变长content
    # {paddingLength}s: 变长padding
    HEADER_FORMAT = '> BB H H BB'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 应该是8字节
    
    def __init__(self, type: int, requestId: int, content: bytes, version=1, padding=None, reserved=0):
        self.version = version
        self.type = type
        self.requestId = requestId
        self.content = content
        if padding is None:
            padding = b'\x00' * (len(content) % 8)
        self.padding = padding
        self.reserved = reserved
    
    @property
    def contentLength(self):
        return len(self.content)
    
    @property
    def paddingLength(self):
        return len(self.padding)
    
    def pack(self):
        """打包整个记录，让struct处理所有字节序"""
        # 使用完整的格式字符串，包含变长部分
        format_str = f'>{self.HEADER_FORMAT[1:]} {self.contentLength}s {self.paddingLength}s'
        
        return struct.pack(
            format_str,
            self.version,
            self.type,
            self.requestId,
            self.contentLength,
            self.paddingLength,
            self.reserved,
            self.content,
            self.padding
        )
    
    @classmethod
    def unpack(cls, data):
        """从字节数据解包"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Data too short, need at least {cls.HEADER_SIZE} bytes")
        
        # 先解包头部获取长度信息
        header_data = data[:cls.HEADER_SIZE]
        version, type_, requestId, contentLength, paddingLength, reserved = struct.unpack(
            cls.HEADER_FORMAT, header_data
        )
        
        # 验证数据长度
        expected_len = cls.HEADER_SIZE + contentLength + paddingLength
        if len(data) < expected_len:
            raise ValueError(f"Data too short: expected {expected_len}, got {len(data)}")
        
        # 使用完整格式解包
        full_format = f'>{cls.HEADER_FORMAT[1:]} {contentLength}s {paddingLength}s'
        
        # 注意：解包时返回的是元组，需要正确处理
        result = struct.unpack(full_format, data[:expected_len])
        
        # result的结构: (version, type, requestId, contentLength, paddingLength, reserved, content, padding)
        content = result[6]
        padding = result[7]
        
        return cls(
            version=result[0],
            type=result[1],
            requestId=result[2],
            content=content,
            padding=padding,
            reserved=result[5]
        ), expected_len
    
    def __repr__(self):
        return (f"FCGI_Record(version={self.version}, type={self.type}, "
                f"requestId={self.requestId}, contentLength={self.contentLength}, "
                f"paddingLength={self.paddingLength})")

class FCGINameValuePair:
    """
    FastCGI Name-Value Pair 统一实现
    
    支持四种格式：
    11: nameLength (1B, bit7=0), valueLength (1B, bit7=0)
    14: nameLength (1B, bit7=0), valueLength (4B, bit7=1 in first byte)
    41: nameLength (4B, bit7=1 in first byte), valueLength (1B, bit7=0)
    44: nameLength (4B, bit7=1 in first byte), valueLength (4B, bit7=1 in first byte)
    """
    
    # 长度字段的掩码
    LENGTH_MASK = 0x7F  # 01111111, 用于去除最高位
    LONG_FLAG = 0x80     # 10000000, 长长度标志
    
    def __init__(self, name: bytes = b'', value: bytes = b''):
        self.name = name
        self.value = value
    
    @property
    def name_length(self) -> int:
        return len(self.name)
    
    @property
    def value_length(self) -> int:
        return len(self.value)
    
    def _encode_length(self, length: int) -> Tuple[bytes, bool]:
        """
        编码长度值
        
        Returns:
            (encoded_bytes, is_long): 编码后的字节和是否是长格式
        """
        if length < 128:  # 短格式，最高位为0
            return struct.pack('>B', length), False
        else:  # 长格式，最高位为1，后跟3字节
            # 确保长度在合法范围内 (24位)
            if length > 0x7FFFFF:  # 2^23 - 1
                raise ValueError(f"Length too large: {length}")
            # 第一个字节：最高位1 + 高7位
            first_byte = self.LONG_FLAG | ((length >> 24) & 0x7F)
            return struct.pack('>I', (first_byte << 24) | length)[:4], True
    
    @classmethod
    def _decode_length(cls, data: bytes, offset: int) -> Tuple[int, int, bool]:
        """
        从指定偏移解码长度
        
        Returns:
            (length, bytes_consumed, was_long): 长度值、消耗的字节数、是否是长格式
        """
        first_byte = data[offset]
        
        if first_byte & cls.LONG_FLAG:  # 长格式
            # 读取4字节
            if len(data) - offset < 4:
                raise ValueError("Insufficient data for long length")
            
            # 组合长度值
            # 第一个字节的低7位是最高位，后面三个字节是完整的
            long_bytes = data[offset:offset+4]
            # 将第一个字节的低7位作为高7位，与后面三字节组合
            length = ((long_bytes[0] & cls.LENGTH_MASK) << 24) | \
                     (long_bytes[1] << 16) | \
                     (long_bytes[2] << 8) | \
                     long_bytes[3]
            return length, 4, True
        else:  # 短格式
            return first_byte, 1, False
    
    def pack(self) -> bytes:
        """
        打包 name-value pair
        
        自动选择最合适的格式：
        - 如果 name 和 value 都 < 128: 用11格式
        - 如果 name < 128, value >= 128: 用14格式
        - 如果 name >= 128, value < 128: 用41格式
        - 如果 name 和 value 都 >= 128: 用44格式
        """
        name_len = self.name_length
        value_len = self.value_length
        
        # 编码长度字段
        name_bytes, name_long = self._encode_length(name_len)
        value_bytes, value_long = self._encode_length(value_len)
        
        # 组合结果：长度字段 + name数据 + value数据
        return name_bytes + value_bytes + self.name + self.value
    
    @classmethod
    def unpack(cls, data: bytes) -> 'Tuple[FCGINameValuePair, int]':
        """
        从字节数据解包 name-value pair
        
        自动检测格式并解码
        """
        if not data:
            raise ValueError("Empty data")
        
        offset = 0
        
        # 解码 name 长度
        name_len, name_bytes_used, name_long = cls._decode_length(data, offset)
        offset += name_bytes_used
        
        # 解码 value 长度
        value_len, value_bytes_used, value_long = cls._decode_length(data, offset)
        offset += value_bytes_used
        
        # 检查数据长度
        if len(data) < offset + name_len + value_len:
            raise ValueError(f"Incomplete data: need {offset + name_len + value_len}, got {len(data)}")
        
        # 提取 name 和 value
        name = data[offset:offset + name_len]
        offset += name_len
        value = data[offset:offset + value_len]
        
        return cls(name, value), offset + value_len
    
    @classmethod
    def from_dict(cls, d: dict) -> list:
        """从字典创建多个 name-value pair"""
        pairs = []
        for key, value in d.items():
            # 确保键和值是字节串
            if isinstance(key, str):
                key = key.encode('utf-8')
            if isinstance(value, str):
                value = value.encode('utf-8')
            pairs.append(cls(key, value))
        return pairs
    
    @classmethod
    def to_dict(cls, pairs: list) -> dict:
        """将多个 name-value pair 转换为字典"""
        result = {}
        for pair in pairs:
            key = pair.name.decode('utf-8', errors='replace')
            value = pair.value.decode('utf-8', errors='replace')
            result[key] = value
        return result
    
    def __repr__(self):
        name_str = self.name[:20].decode('ascii', errors='replace')
        value_str = self.value[:20].decode('ascii', errors='replace')
        if len(self.name) > 20:
            name_str += '...'
        if len(self.value) > 20:
            value_str += '...'
        return f"FCGI_NameValuePair(name='{name_str}'[{self.name_length}], value='{value_str}'[{self.value_length}])"

class FCGIRole:
    FCGI_RESPONDER = 1
    FCGI_AUTHORIZER = 2
    FCGI_FILTER = 3

class FCGIBeginRequestBody:
    FCGI_KEEP_CONN = 1
    def __init__(self, role: int, keepAlive: int):
        self.role = role
        self.keepAlive = keepAlive
    
    def pack(self):
        format_str = f'> H B 5s'
        return struct.pack(format_str, 
                           self.role,
                           self.keepAlive,
                           b"\x00\x00\x00\x00\x00")

def force_bytes(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        return s
    else:
        return s.encode('utf-8', 'strict')

class FastCGIClient:
    def __init__(self):
        self.message: bytes = b''
        self.request_id = random.randint(1, (1 << 16) - 1)
        
    def begin_request(self):
        self.message += FCGIRecord(
                                    type=FCGIRequestType.FCGI_BEGIN_REQUEST, 
                                    content=FCGIBeginRequestBody(role=FCGIRole.FCGI_RESPONDER, keepAlive=0).pack(),
                                    requestId=self.request_id
                                   ).pack()
    
    def send_stream(self, type: int, stream: bytes):
        index = 0
        while index < len(stream):
            send_length = min(len(stream) - index, 65535)
            self.message += FCGIRecord(
                type=type,
                requestId=self.request_id,
                content=stream[index: index+send_length]
            ).pack()
            index += send_length
        self.message += FCGIRecord(
            type=type,
            requestId=self.request_id,
            content=b''
        ).pack()

    def send_params(self, params: "dict[str | bytes, str | bytes]"):
        stream = b''
        for key, value in params.items():
            stream += FCGINameValuePair(force_bytes(key), force_bytes(value)).pack()
        self.send_stream(FCGIRequestType.FCGI_PARAMS, stream)

    def send_post(self, payload: bytes):
        # self.message += FCGIRecord(
        #         type=FCGIRequestType.FCGI_STDIN,
        #         requestId=self.request_id,
        #         content=payload
        #     ).pack()
        self.send_stream(FCGIRequestType.FCGI_STDIN, payload)

    def receive_stream(self, stream: bytes):
        index = 0
        reqs: 'list[FCGIRecord]' = []
        while index < len(stream):
            req, length = FCGIRecord.unpack(stream[index:])
            index += length
            reqs.append(req)
        return reqs