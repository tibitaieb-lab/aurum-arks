"""Content-safe PDF warning provenance; scope never implies harmlessness."""
import ast
from contextlib import contextmanager
import hashlib
import logging
from pathlib import Path
import sys
import warnings

VERSION = 'ARKS_PDF_WARNINGS_V1'
XREF_MESSAGE = 'Xref table not zero-indexed. ID numbers for objects will be corrected.'


def digest(value):
    return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()


def static_messages(package):
    """Only trusted library literals can be rendered in warning evidence."""
    result = set()
    for path in Path(package).rglob('*.py'):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
            arg = node.args[0]
            if name in ('logger_warning', 'logger_error', 'warning', 'error', 'warn') and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                result.add(arg.value)
    return result


class ScopedWarnings(logging.Handler):
    """Preserve every observed warning, without document string interpolation."""
    def __init__(self, package):
        super().__init__()
        self.templates = static_messages(package)
        self.document_warnings = []
        self.pages = {}
        self.current_scope = 'document_scope'
        self.page_number = None
        self.event_count = 0

    def page_events(self, number):
        return self.pages.setdefault(number, [])

    def install(self):
        logger = logging.getLogger('pypdf')
        logger.handlers[:] = [self]
        logger.propagate = False
        logger.setLevel(logging.WARNING)

    def _message(self, template, args, rendered):
        value = {'warning_message': None, 'warning_message_sha256': digest(rendered),
                 'warning_message_length': len(rendered.encode('utf-8', errors='replace')),
                 'warning_message_status': 'HASH_ONLY_CONTENT_PROTECTION'}
        if isinstance(template, str) and template in self.templates:
            value['warning_template'] = template
            if not args:
                value.update(warning_message=template, warning_message_status='STATIC_LIBRARY_STRING')
            elif isinstance(args, dict) and all(isinstance(v, int) and not isinstance(v, bool) and abs(v) < 10**18 for v in args.values()):
                numeric = {k: int(v) for k, v in args.items()}
                message = template % numeric
                if message == rendered:
                    value.update(warning_message=message, warning_message_status='STATIC_TEMPLATE_NUMERIC_ONLY')
        return value

    def _append(self, value):
        if self.event_count >= 4096:
            raise RuntimeError('PDF_WARNING_EVENT_LIMIT')
        self.event_count += 1
        value.update(warning_scope=self.current_scope, page_number=self.page_number,
                     warning_id=self.event_count)
        origin = value['warning_origin']
        known_xref = (value.get('warning_message') == XREF_MESSAGE and
                      origin.get('module') == 'pypdf._reader' and
                      origin.get('function') == '_read_standard_xref_table')
        value['warning_code'] = ('DOCUMENT_WARNING_XREF_NOT_ZERO_INDEXED' if known_xref and self.current_scope == 'document_scope'
                                 else 'PDF_WARNING_' + value['warning_message_sha256'][:16].upper())
        target = self.document_warnings if self.current_scope == 'document_scope' else self.page_events(self.page_number)
        target.append(value)

    def emit(self, record):
        origin = {'module': record.name, 'function': record.funcName,
                  'file': Path(record.pathname).name, 'line': record.lineno}
        frame = sys._getframe(1)
        while frame:
            module = frame.f_globals.get('__name__', '')
            if module.startswith('pypdf.') and frame.f_code.co_name not in ('logger_warning', 'logger_error'):
                origin = {'module': module, 'function': frame.f_code.co_name,
                          'file': Path(frame.f_code.co_filename).name, 'line': frame.f_lineno}
                break
            frame = frame.f_back
        self._append({'warning_type': 'logging.LogRecord/' + record.levelname,
                      'warning_origin': origin, **self._message(record.msg, record.args, record.getMessage())})

    @contextmanager
    def scope(self, name, page_number=None):
        if name not in ('document_scope', 'page_scope') or (name == 'page_scope' and (type(page_number) is not int or page_number < 1)):
            raise RuntimeError('PDF_WARNING_SCOPE_INVALID')
        old = self.current_scope, self.page_number
        self.current_scope, self.page_number = name, page_number
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                try:
                    yield
                finally:
                    for item in caught:
                        message = str(item.message)
                        self._append({'warning_type': item.category.__module__ + '.' + item.category.__name__,
                                      'warning_origin': {'file': Path(item.filename).name, 'line': item.lineno},
                                      **self._message(message, (), message)})
        finally:
            self.current_scope, self.page_number = old
