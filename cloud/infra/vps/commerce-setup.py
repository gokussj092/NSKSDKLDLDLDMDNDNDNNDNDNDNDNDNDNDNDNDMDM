"""Provision private commerce secrets without enabling accounts or payments."""
from pathlib import Path
import os,secrets,stat,sys,tempfile

def prepare_configuration(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise ValueError('Protected regular cloud.env required')
    lines=path.read_text().splitlines()
    def value(key):
        matches=[line.split('=',1)[1]for line in lines if line.startswith(key+'=')]
        if len(matches)>1:raise ValueError('Duplicate commerce setting')
        return matches[0]if matches else ''
    password=value('SPDECODE_SHOP_DB_PASSWORD')or secrets.token_hex(32)
    app_password=value('SPDECODE_SHOP_APP_PASSWORD')or secrets.token_hex(32)
    values={'SPDECODE_SHOP_DB_PASSWORD':password,
      'SPDECODE_SHOP_APP_PASSWORD':app_password,
      'SPDECODE_DATABASE_URL':value('SPDECODE_DATABASE_URL')or 'postgresql://spdecode_shop_app:'+app_password+'@shop-db:5432/spdecode_shop',
      'BETTER_AUTH_SECRET':value('BETTER_AUTH_SECRET')or secrets.token_urlsafe(48),
      'SPDECODE_SHOP_TOKEN_KEY':value('SPDECODE_SHOP_TOKEN_KEY')or secrets.token_urlsafe(48)}
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

if __name__=='__main__':
    try:
        if os.geteuid()!=0:raise ValueError('Run through the root VPS CLI')
        prepare_configuration(sys.argv[1]);print('Private commerce configuration prepared; activation flags preserved or defaulted OFF.')
    except Exception:
        print('COMMERCE_CONFIGURATION_FAILED: verify cloud.env permissions and duplicate settings.',file=sys.stderr);raise SystemExit(1)
