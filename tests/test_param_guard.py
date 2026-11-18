from security.param_guard import (
    parse_query,
    single_value,
    validate_keys,
    normalize_params,
    duplicate_keys
)


def test_parse():
    assert parse_query('a=1&b=2') == {'a': ['1'], 'b': ['2']}

def test_dupes():
    assert duplicate_keys('a=1&a=2') == ['a']

def test_single():
    assert single_value('a=1&a=2', 'a') == '1'

def test_validate():
    assert validate_keys({'role': ['user']}, {'role'}) is True

def test_unknown():
    assert validate_keys({'debug': ['1']}, {'role'}) is False

def test_encoded_dupe():
    assert duplicate_keys('%61=1&a=2') == ['a']

def test_array():
    assert validate_keys({'id[]': ['1']}, {'id'}) is False

def test_semicolon():
    assert parse_query('a=1;b=2') == {'a': ['1;b=2']}

def test_empty():
    assert parse_query('') == {}

def test_case():
    assert normalize_params({'Role': ['admin']}) == {'role': ['admin']}

def test_normalize():
    assert normalize_params({'a': ['1']}) == {'a': ['1']}

def test_repeat_same():
    assert single_value('a=1&a=1', 'a') == '1'

def test_bad():
    assert validate_keys({'': ['1']}, {''}) is False

def test_dupe_list():
    assert duplicate_keys('a=1&b=2') == []

def test_order():
    assert single_value('a=1&a=2', 'a', last=True) == '2'
