def hash_password(password, salt=None, rounds=3000000):
    from os import urandom
    from hashlib import sha512
    from functools import reduce

    salt = (urandom(128).hex(), salt)[bool(salt)]

    result = sha512(salt.encode() + password.encode())
    result = reduce(lambda x, y: sha512(x.digest()), range(rounds), result)
    result = result.hexdigest()

    return '{rounds}${salt}${result}'.format(rounds=rounds, salt=salt, result=result)

def test_password(password_hash, test_phrase):
    rounds, salt, result = password_hash.split('$')

    result = hash_password(test_phrase, salt=salt, rounds=int(rounds))

    return result == password_hash

def validate_password(password):
    from re import search
    result = [] 
    
    if search(r'^.{0,7}$', password):
        result.append('be at least 8 characters long')

    if search(r'(\w)\1{3,}', password):
        result.append('have no more than 3 consecutive duplicate characters')

    matchers = {
        'a number': r'^[^0-9]+$',
        'a lower-case letter': r'^[^a-z]+$',
        'an upper-case letter': r'^[^A-Z]+$',
        'a symbol': r'^[A-z0-9](?=[A-z0-9]+$)'
    }

    matched = [key for key, value in matchers.items() if search(value, password)]
    if len(matched) > 1:
        matched_last = matched.pop()
        matched = 'contain {} & {}'.format(', '.join(matched), matched_last)
        result.append(matched)
    elif len(matched) == 1:
        matched = 'contain {}'.format(matched[0])
        result.append(matched)

    if len(result) > 1:
        result_last = result.pop()
        result = '{} & {}'.format(', '.join(result), result_last)
    elif len(result) == 1:
        result = '{}'.format(result[0])
    else:
        return False

    result = 'Your password must: {}'.format(result)

    return result
