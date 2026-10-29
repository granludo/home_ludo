"""Strict Pages-to-Apache adapter for static sites; unsupported syntax fails closed."""
import re
from urllib.parse import unquote

def quote(value):
    if any(c in value for c in '\n\r\x00"\\'):
        raise ValueError('Unsupported quoting in rule value')
    return '"'+value+'"'

def pattern(path):
    if not path.startswith('/') or path.count('*')>1 or any(c in path for c in '?"\\#'):
        raise ValueError('Unsupported path pattern: '+path)
    return re.escape(path).replace(r'\*','(.*)')

def compile_rules(redirects, headers):
    lines=['# Generated; publish only through the validated receiver.','RewriteEngine On','RewriteOptions AllowNoSlash']
    for line in redirects.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        fields=line.split()
        if len(fields)!=3:raise ValueError('Unsupported redirect: '+line)
        source,target,status=fields
        if status not in ['200','301','302']:raise ValueError('Unsupported status')
        if not target.startswith(('/', 'https://','http://')) or target.startswith('//'):raise ValueError('Unsupported target')
        if status=='200' and not target.startswith('/'):raise ValueError('Remote proxy rewrites forbidden')
        if (':' in source and ';s:' not in source) or (':splat' in target and '*' not in source):raise ValueError('Unsupported placeholder')
        target=target.replace(':splat','$1')
        pat=pattern(unquote(source))[1:]
        flag='END' if status=='200' else 'R='+status+',END,NE'
        lines.append('RewriteRule "^'+pat+'$" '+quote(target).replace('%',r'\%')+' ['+flag+']')
    match=None
    allowed={'Content-Type','Cache-Control','X-Robots-Tag','X-Content-Type-Options','Referrer-Policy','Content-Security-Policy','Permissions-Policy'}
    for line in headers.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        if not line[0].isspace():match=pattern(line.strip());continue
        if match is None or ':' not in line:raise ValueError('Invalid header rule')
        name,value=line.strip().split(':',1)
        if name not in allowed:raise ValueError('Unsupported header '+name)
        value=value.strip().replace('%','%%')
        lines.append('Header always set '+name+' '+quote(value)+' "expr=%{REQUEST_URI} =~ m#^'+match+'$#"')
    return '\n'.join(lines)+'\n'
