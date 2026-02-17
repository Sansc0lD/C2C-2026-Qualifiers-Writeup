def remove_scheme(url):
    if url.startswith('https://'):
        return url[8:]
    elif url.startswith('http://'):
        return url[7:]
    return url

def extract_scheme(url):
    if url.startswith('https://'):
        return 'https'
    elif url.startswith('http://'):
        return 'http'
    return None

def extract_domain(url):
    url_without_scheme = remove_scheme(url)
    domain_and_port = url_without_scheme.split('/')[0]
    
    if '@' in domain_and_port:
        parts = domain_and_port.split('@')
        domain_and_port = parts[1]
    
    return domain_and_port

def extract_path(url):
    url_without_scheme = remove_scheme(url)
    
    if '/' in url_without_scheme:
        path_parts = url_without_scheme.split('/', 1)
        return '/' + path_parts[1]
    return '/'

def validate_jku_url(url):
    allowed_domains = ['localhost', '127.0.0.1']
    allowed_ports = ['80', '443', '5000', '8080']

    if not url:
        return False
    
    scheme = extract_scheme(url)
    if not scheme:
        return False
    
    domain = extract_domain(url)
    path = extract_path(url)

    domain_only = domain
    if ':' in domain:
        domain_only, port = domain.split(':', 1)
        if port not in allowed_ports:
            return False
    
    if domain_only not in allowed_domains:
        return False
    
    if not path.endswith('jwks.json'):
        return False
    
    return True
