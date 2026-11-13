"""Provision private commerce secrets without enabling accounts or payments."""
from pathlib import Path
import os,re,secrets,stat,sys,tempfile
from urllib.parse import urlsplit,unquote

def prepare_configuration(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise ValueError('Protected regular cloud.env required')
    lines=path.read_text().splitlines()
    def value(key):
        matches=[line.split('=',1)[1]for line in lines if line.startswith(key+'=')]
        if len(matches)>1:raise ValueError('Duplicate commerce setting')
        return matches[0]if matches else ''
    existing_support=value('SPDECODE_SUPPORT_ENCRYPTION_KEY')
    if existing_support and not re.fullmatch(r'[a-fA-F0-9]{64}',existing_support):
        raise ValueError('Invalid existing support encryption key; refusing rotation')
    support_key=existing_support or secrets.token_hex(32)
    password=value('SPDECODE_SHOP_DB_PASSWORD')or secrets.token_hex(32)
    app_password=value('SPDECODE_SHOP_APP_PASSWORD')or secrets.token_hex(32)
    values={'SPDECODE_SHOP_DB_PASSWORD':password,
      'SPDECODE_SHOP_APP_PASSWORD':app_password,
      'SPDECODE_DATABASE_URL':value('SPDECODE_DATABASE_URL')or 'postgresql://spdecode_shop_app:'+app_password+'@shop-db:5432/spdecode_shop',
      'BETTER_AUTH_SECRET':value('BETTER_AUTH_SECRET')or secrets.token_urlsafe(48),
      'SPDECODE_SHOP_TOKEN_KEY':value('SPDECODE_SHOP_TOKEN_KEY')or secrets.token_urlsafe(48),
      'SPDECODE_SUPPORT_ENCRYPTION_KEY':support_key}
    # Fail before overwriting configuration if the connection string and the
    # non-superuser role password disagree (PostgreSQL SQLSTATE 28P01).
    try:
        parsed=urlsplit(values['SPDECODE_DATABASE_URL'])
        if not (parsed.scheme in ('postgres','postgresql') and
                parsed.username=='spdecode_shop_app' and
                parsed.hostname=='shop-db' and
                parsed.port in (None,5432) and
                parsed.path=='/spdecode_shop' and
                unquote(parsed.password or '')==app_password):
            raise ValueError('Inconsistent commerce database credentials')
    except (TypeError, ValueError) as exc:
        raise ValueError('Inconsistent commerce database credentials') from None
    for flag in ['SPDECODE_ACCOUNTS_ENABLED','SPDECODE_STORE_ENABLED','SPDECODE_PAYMENTS_LIVE',
                 'SPDECODE_COMMERCIAL_API_ENABLED','SPDECODE_OFFLINE_LICENSE_READY']:
        values[flag]=value(flag)or 'false'
    output=[line for line in lines if not any(line.startswith(key+'=')for key in values)]
    output += [key+'='+val for key,val in values.items()]
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='.commerce-',delete=False)as stream:
            temporary=Path(stream.name);os.fchmod(stream.fileno(),0o600)
            stream.write('\n'.join(output)+'\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary and temporary.exists():temporary.unlink()

def prepare_support_only(path):
    """Idempotently provision just the support key; never print or rotate it."""
    path=Path(path)
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise ValueError('Protected regular cloud.env required')
    content=path.read_text()
    lines=content.splitlines()
    matches=[line.split('=',1)[1] for line in lines
             if line.startswith('SPDECODE_SUPPORT_ENCRYPTION_KEY=')]
    if len(matches)>1:
        raise ValueError('Duplicate support encryption keys')
    if matches:
        if not re.fullmatch(r'[a-fA-F0-9]{64}',matches[0]):
            raise ValueError('Invalid existing support encryption key; refusing rotation')
        return False
    secret=secrets.token_hex(32)
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='.support-',delete=False) as f:
        temp=Path(f.name)
        try:
            os.fchmod(f.fileno(),0o600)
            f.write(content.rstrip('\\n')+'\\nSPDECODE_SUPPORT_ENCRYPTION_KEY='+secret+'\\n')
            f.flush()
            os.fsync(f.fileno())
        finally:
            pass
    try:
        os.replace(temp,path)
    finally:
        if temp.exists():temp.unlink()
    return True

if __name__=='__main__':
    try:
        if os.geteuid()!=0:raise ValueError('Run through the root VPS CLI')
        if len(sys.argv)==3 and sys.argv[1]=='--support-only':
            prepare_support_only(sys.argv[2])
            print('Support key ready in protected cloud.env (value not displayed).')
        else:
            if len(sys.argv)!=2:raise ValueError('Expected cloud.env path')
            prepare_configuration(sys.argv[1])
            print('Private commerce and support encryption configuration prepared; existing values preserved.')
    except Exception:
        print('COMMERCE_CONFIGURATION_FAILED: verify cloud.env permissions and duplicate settings.',file=sys.stderr);raise SystemExit(1)
