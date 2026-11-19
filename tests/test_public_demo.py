"""Exercise the shipped synthetic corpus and the real authenticated HTTP UI."""
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from public_demo import open_demo
from aurum_arks.doc_service import make_server


class PublicDemoTests(unittest.TestCase):
    def test_authenticated_catalogue_assets_search_original_and_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            store = open_demo(folder)
            server, code = make_server(store)
            # The store uses SQLite's thread ownership; requests run in this
            # thread, while a client thread supplies HTTP requests.
            errors = []
            def client():
                try:
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=10)
                    def request(method, path, body=None, headers=None):
                        conn.request(method, path, body, headers or {})
                        response = conn.getresponse()
                        return response.status, response.read(), dict(response.getheaders())
                    self.assertEqual(request('GET', '/')[0], 401)
                    status, _, headers = request('POST', '/login', urlencode({'code': code}),
                        {'Content-Type': 'application/x-www-form-urlencoded'})
                    self.assertEqual(status, 200)
                    cookie = {'Cookie': headers['Set-Cookie'].split(';')[0]}
                    status, body, _ = request('GET', '/', headers=cookie)
                    self.assertEqual(status, 200)
                    self.assertIn('Recherche lexicale', body.decode())
                    self.assertIn('demo-luma', body.decode())
                    for asset in ['catalogue.js', 'catalogue.css', 'aurum-themes.css', 'aurum-research-lab-logo.png']:
                        status, body, _ = request('GET', '/ui/' + asset, headers=cookie)
                        self.assertEqual(status, 200)
                        self.assertTrue(body)
                    status, body, _ = request('GET', '/search.json?' + urlencode({'q': 'luminosité'}), headers=cookie)
                    self.assertEqual(status, 200)
                    found = json.loads(body)
                    self.assertEqual(found['state'], 'FOUND')
                    self.assertIn('42', found['results'][0]['evidence']['content_exact'])
                    status, body, _ = request('GET', '/source?id=demo-luma', headers=cookie)
                    self.assertEqual(status, 200)
                    self.assertEqual(body, (ROOT / 'examples/observatoire.txt').read_bytes())
                    self.assertEqual(request('GET', '/source?id=..%2Fsecret', headers=cookie)[0], 403)
                    conn.close()
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=client)
            thread.start()
            try:
                while thread.is_alive():
                    server.handle_request()
                thread.join()
                if errors:
                    raise errors[0]
            finally:
                server.server_close()
                store.close()
            store = open_demo(folder)
            try:
                self.assertEqual(store.search('luminosité')['state'], 'FOUND')
                self.assertEqual(store.db.execute('select count(*) from acquisitions').fetchone()[0], 1)
            finally:
                store.close()
