"""HTTP Parameter Pollution (HPP) guard.

Security policy, fixed in one place so every layer (gateway / framework /
application) interprets a query string identically:

1. duplicate keys are auditable (``duplicate_keys``) and rejected (``guard``)
2. percent-encoding is normalized with a single decode pass before any
   comparison, so ``%72ole`` can no longer bypass the whitelist
3. ``&`` is the ONLY parameter separator; ``;`` is ordinary data
4. empty keys are filtered at every stage
5. keys are case-normalized to lowercase so ``Role`` / ``role`` cannot be
   treated as two fields
6. PHP-style array syntax (``id[]``, ``id[0]``) is rejected
7. an exact key whitelist is enforced by ``validate_keys``
8. value selection order is fixed: first value by default, explicit
   ``last=True`` for the last -- never "whatever the framework happens to do"
9. duplicate keys are reported for auditing instead of being silently merged
10. errors never echo the raw parameter table (see ``ParamGuardError``)
"""

from urllib.parse import unquote

__all__ = [
    'ParamGuardError',
    'parse_query',
    'single_value',
    'validate_keys',
    'normalize_params',
    'duplicate_keys',
    'guard',
]


class ParamGuardError(ValueError):
    """Policy violation.

    Carries only a generic reason and (optionally) the offending *key name*.
    It deliberately never stores the raw query string or value list, so error
    pages built from it cannot echo the full parameter table back to clients.
    """

    def __init__(self, reason, key=None):
        super().__init__(reason)
        self.reason = reason
        self.key = key

    def public(self):
        """Return a client-safe payload (no parameter echo, no internals)."""
        return {'error': 'invalid_request', 'reason': self.reason}


def _decode_key(raw_key):
    """Percent-decode a key once and canonicalize its case.

    A single ``unquote`` pass is intentional: repeated decoding would itself
    be a bypass (``%2561`` -> ``%61`` -> ``a``). ``+`` is left untouched --
    only percent-encoding is normalized, per the strict parser policy.
    """
    return unquote(raw_key).lower()


def _pairs(query):
    """Split a query string into ``(key, value)`` pairs.

    Only ``&`` separates parameters -- a literal ``;`` stays inside the value
    (defense against parameter injection via semicolons). Each pair is split
    on its first ``=``; a pair without ``=`` yields an empty value. Empty
    keys (``=x``, bare ``=``) are dropped here, once, for every caller.
    """
    if not query:
        return []

    pairs = []
    for part in query.split('&'):
        if not part:
            continue
        if '=' in part:
            raw_key, raw_value = part.split('=', 1)
        else:
            raw_key, raw_value = part, ''

        key = _decode_key(raw_key)
        if key == '':
            continue  # empty-key filter
        pairs.append((key, unquote(raw_value)))
    return pairs


def parse_query(query):
    """Parse ``query`` into an ordered mapping of key -> list of values.

    Values keep their on-the-wire order; duplicate keys are preserved as
    multi-element lists rather than silently collapsed, so callers can audit
    them via :func:`duplicate_keys` and select deterministically via
    :func:`single_value`.
    """
    params = {}
    for key, value in _pairs(query):
        params.setdefault(key, []).append(value)
    return params


def duplicate_keys(query):
    """Return canonical names of keys appearing more than once.

    Keys are percent-decoded and case-folded before counting, so encoded
    (``%61=1&a=2``) and case-variant (``A=1&a=2``) repetitions are detected.
    Names are returned in first-occurrence order, each at most once; an empty
    list means no duplication was found.
    """
    counts = {}
    order = []
    for key, _ in _pairs(query):
        if key not in counts:
            counts[key] = 0
            order.append(key)
        counts[key] += 1
    return [key for key in order if counts[key] > 1]


def single_value(query, key, last=False):
    """Return one value for ``key`` with a fixed, explicit selection order.

    The first occurrence wins by default; pass ``last=True`` to take the last
    one. This removes the proxy-vs-framework disagreement where one layer
    reads the first value and another the last. Raises :class:`ParamGuardError`
    (without echoing the query) when the key is absent.
    """
    wanted = _decode_key(key)
    values = [value for k, value in _pairs(query) if k == wanted]
    if not values:
        raise ParamGuardError('missing required parameter', key=wanted)
    return values[-1] if last else values[0]


def validate_keys(params, allowed):
    """Enforce an exact key whitelist.

    Returns ``True`` only when every key is non-empty, free of array syntax
    (``[`` / ``]``, covering ``id[]`` and ``id[0]``), and member of
    ``allowed``. An empty key is rejected even when ``''`` is present in the
    whitelist, so a misconfigured whitelist cannot reopen that hole.
    """
    for key in params:
        if not key:
            return False
        if '[' in key or ']' in key:
            return False
        if key not in allowed:
            return False
    return True


def normalize_params(params):
    """Canonicalize a parsed parameter mapping.

    Lowercases every key, drops empty keys, and merges values when distinct
    spellings collapse onto the same canonical name (e.g. ``A`` and ``a``),
    preserving value order. Values themselves are returned untouched.
    """
    normalized = {}
    for key, values in params.items():
        if not key:
            continue
        canonical = key.lower()
        normalized.setdefault(canonical, []).extend(values)
    return normalized


def guard(query, allowed):
    """Full HPP pipeline: audit -> parse -> normalize -> whitelist.

    Raises :class:`ParamGuardError` on duplicate keys or policy violations;
    the exception carries at most the offending key name, never the raw
    query. Returns the normalized, validated mapping on success. Whitelist
    entries are matched against lowercased canonical keys.
    """
    dupes = duplicate_keys(query)
    if dupes:
        raise ParamGuardError('duplicate parameter rejected', key=dupes[0])

    params = normalize_params(parse_query(query))

    if not validate_keys(params, allowed):
        raise ParamGuardError('parameter rejected by policy')

    return params
