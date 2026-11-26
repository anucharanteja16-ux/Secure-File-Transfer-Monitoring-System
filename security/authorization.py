import os
from security.sensitive_files import BASE, classify_file, load_config
def is_inside(path, folder):
    try:
        p, f = [os.path.normcase(os.path.realpath(x)) for x in (path, folder)]
        return os.path.commonpath([p,f]) == f
    except ValueError:
        return False
def check_authorization(source, destination):
    c = load_config(); label = classify_file(source)
    allowed = any(is_inside(destination, BASE / os.path.expandvars(x)) for x in c['allowed_destinations'])
    return allowed or (label == 'NORMAL' and c['allow_normal_file_transfer']), label
