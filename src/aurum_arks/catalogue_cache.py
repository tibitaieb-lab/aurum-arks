"""One HTTP catalogue snapshot, reused only for byte-identical dependencies.

No TTL, stat-only trust, persisted cache, policy override or query-result cache.
All misses use the existing full documentary validator.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
from .paths import reject_links
from .serialization import fingerprint


class CatalogueCache:
    def __init__(self, store):
        self.store = store
        self.key = self.rows = None

    def signature(self):
        from .documentary import DocumentaryStore
        # Custom adapters may have dependencies outside the documentary store.
        # Keep their original behavior instead of guessing their cache boundary.
        if (type(self.store) is not DocumentaryStore or
                getattr(self.store.catalogue, '__func__', None) is not DocumentaryStore.catalogue):
            return None
        try:
            if self.store.db.in_transaction:
                return None
            version = self.store.db.execute('pragma data_version').fetchone()[0]
            changes = self.store.db.total_changes
            root = self.store.root
            reject_links(root)
            paths = [self.store.config_path]
            # Include originals, extraction receipts/images, database and any
            # journal/WAL. New, removed and renamed files invalidate the view.
            for path in root.rglob('*'):
                reject_links(path)
                if path.is_file(): paths.append(path)
            paths += list(Path(__file__).parent.glob('*.py'))
            identities = []
            for path in sorted(set(paths)):
                reject_links(path)
                with path.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                identities.append((str(path), digest))
            # These are the actual schemas loaded by this store instance.
            schemas = fingerprint(self.store.contracts.base.schemas)
            if (self.store.db.in_transaction or changes != self.store.db.total_changes
                    or version != self.store.db.execute('pragma data_version').fetchone()[0]):
                return None
            return version, changes, self.store.restore_ready, schemas, tuple(identities)
        except (OSError, ValueError):
            # An unreadable/changing dependency is never a cache authorization.
            return None

    def get(self):
        before = self.signature()
        if before is not None and before == self.key:
            return deepcopy(self.rows)
        rows = self.store.catalogue()
        after = self.signature()
        if before is not None and before == after:
            self.key, self.rows = after, deepcopy(rows)
        else:
            self.key = self.rows = None
        return rows
