import unittest, tempfile
from pathlib import Path
from security.sensitive_files import classify_file
from security.authorization import check_authorization
from security.integrity import calculate_hash
class CoreTests(unittest.TestCase):
    def test_classes(self):
        for path,label in [('notes.txt','NORMAL'),('secret.txt','SENSITIVE'),('monitored/Finance/report.txt','CONFIDENTIAL'),('server.key','SENSITIVE')]: self.assertEqual(classify_file(path),label)
    def test_policy(self):
        self.assertFalse(check_authorization('monitored/secret.txt','external/secret.txt')[0])
        self.assertTrue(check_authorization('monitored/notes.txt','external/notes.txt')[0])
        self.assertTrue(check_authorization('monitored/secret.txt','monitored/Backup/secret.txt')[0])
    def test_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test'; p.write_bytes(b'abc'); self.assertEqual(calculate_hash(p),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
if __name__=='__main__': unittest.main()
