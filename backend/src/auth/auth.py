import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


# TODO: Reinstate: AUTH0_DOMAIN = 'udacity-fsnd.auth0.com'
AUTH0_DOMAIN = 'fsnd.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'dev'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():   

    if 'Authorization' not in request.headers:
        # 401 unauthorized 
        raise AuthError({
            "code": "invalid_header",
            "description": "Invalid header"
        }, 401)

    auth_header = request.headers['Authorization']
    header_parts = auth_header.split(' ')

    if len(header_parts) != 2: 
        raise AuthError({
            "code": "invalid_header",
            "description": "Invalid header"
        }, 401)

    elif header_parts[0].lower() != 'bearer':
        raise AuthError({
            "code": "invalid_header",
            "description": "Invalid header"
        }, 401)

    return header_parts[1]

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    raise Exception('Not Implemented')

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    # Get public key from Auth0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    # Returns an array of key objects and each key object includes a key id (kid)
    jwks = json.loads(jsonurl.read()) # Returns and 
    # Get header from token. Ex {'typ': 'JWT', 'alg': 'RS256', 'kid': 'some key id'}
    unverified_header = jwt.get_unverified_header(token)
    # Find a key object with key id that matches the key id in our header 
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization malformed."
        })

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    raise Exception('Not Implemented')

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik56Z3lSVFZEUmpKQ1FrUkJSRGN3TjBReFJUQTFPVUl5UlRORk9EQXhPVGMwTmpjNU9USkVPQSJ9.eyJpc3MiOiJodHRwczovL2ZzbmQuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVkMDNkM2U2NzI2YjhmMGNiNGJmNzFjOSIsImF1ZCI6ImltYWdlIiwiaWF0IjoxNTYwNTU2MTc0LCJleHAiOjE1NjA1NjMzNzQsImF6cCI6ImtpNEI2alprdUpkODdicEIyTXc4emRrajFsM29mcHpqIiwic2NvcGUiOiIiLCJwZXJtaXNzaW9ucyI6WyJnZXQ6aW1hZ2VzIiwicG9zdDppbWFnZXMiXX0.ENxNT1lo_sX9rpgmGJmiu14lugmYXqb8siJwC1nPuGSb_ycK02KyS5IkA-YkhySMBcDD5IJfawPkJNmJPtUAB1wYVP8hlNsBuvLjtYxzH_VHNeXzVXWQvM7RiuPwrmWJmJN2onmZPh3bjiUZxvyAp0Yp0Rvm54SsiDjO_Dj1Qx-Az_Zjo-mY2ECfFgAo0ifnqDMIgE5YDZ3uOzMni4oEU5Ok-TrQOSwyfJyUC1KQ7ubQ-Bnbh-0Aii9UK9R4JBH7iIMva8_edQkgR4MuRXatYhsqvHsxQ2Iv5rjMmTAmjknsYWE5VYrzafRGVigbPD9A6ELEnyjADBQ9vMtSdPQe2w"
verify_decode_jwt(token)

'''
TESTING

'''


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator