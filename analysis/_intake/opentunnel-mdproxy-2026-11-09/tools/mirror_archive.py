"""Bounded reader for this mirror's stream of stored APK local ZIP entries.

Its stream omits an outer central directory; zipfile sees the last inner APK.
No archive paths are extracted, no code is executed, each inner APK CRC is checked; stale wrapper lengths are never trusted.
"""
import struct,zlib,zipfile
from io import BytesIO
def apk_members(raw):
    pos=0;rows=[];total=0
    while raw[pos:pos+4]==b'PK\x03\x04':
        if len(rows)>=100 or pos+30>len(raw):raise ValueError('ZIP_BOUNDS')
        _,version,flags,method,tm,dt,crc,packed,plain,n,e=struct.unpack_from('<IHHHHHIIIHH',raw,pos)
        start=pos+30+n+e;end=start+packed
        if flags&9 or method!=0 or plain!=packed or end>len(raw) or packed>100*1024*1024:raise ValueError('ZIP_METHOD_OR_BOUNDS')
        name=raw[pos+30:pos+30+n].decode('utf-8')
        if not name.endswith('.apk') or '/' in name or '\\' in name or raw[start:start+4]!=b'PK\x03\x04':raise ValueError('ZIP_MEMBER_INVALID')
        # This mirror also advertises stale wrapper lengths/CRCs. Recover only
        # a COMPLETE inner APK whose own central directory and every CRC verify.
        candidate=start;valid=False
        for attempt in range(40):
            candidate=raw.find(b'PK\x05\x06',candidate+1,min(len(raw),start+100*1024*1024))
            if candidate<0:break
            if candidate+22>len(raw):continue
            _,disk,cd_disk,on_disk,count,cd_size,cd_offset,comment=struct.unpack_from('<4s4H2IH',raw,candidate)
            actual_end=candidate+22+comment
            if disk or cd_disk or on_disk!=count or not 0<count<=10000 or start+cd_offset+cd_size!=candidate or actual_end>len(raw):continue
            data=raw[start:actual_end]
            with zipfile.ZipFile(BytesIO(data)) as inner:
                infos=inner.infolist()
                if len(infos)!=count or sum(i.file_size for i in infos)>300*1024*1024 or inner.testzip() is not None:raise ValueError('INNER_APK_INVALID')
            valid=True;end=actual_end;plain=len(data);break
        if not valid:raise ValueError('COMPLETE_INNER_APK_NOT_FOUND')
        total+=plain
        if total>250*1024*1024:raise ValueError('ZIP_TOTAL_BOUNDS')
        rows.append((name,data));pos=end
    if not rows or pos!=len(raw):raise ValueError('ZIP_TRAILING_OR_MISSING_MEMBER')
    return rows
