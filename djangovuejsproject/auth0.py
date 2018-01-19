from jose import jwt

class Auth0Middleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # GET TOKEN
        if (request.method == 'OPTIONS'):
            response = self.get_response(request)
            return response

        auth = request.META.get('HTTP_AUTHORIZATION')

        if not auth:
            raise ValueError("Authorization header is expected")

        parts = auth.split()

        if parts[0].lower() != "bearer":
            raise ValueError("Authorization header must start with 'bearer'")

        elif len(parts) == 1:
            raise ValueError("Token not found")

        elif len(parts) > 2:
            raise ValueError("Authorization header must be a bearer token")

        token = parts[1]

        # VALIDATE TOKEN

        jwks = {"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["MIIC6DCCAdCgAwIBAgIJIKf97zsX63ziMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEGJrcmVicy5hdXRoMC5jb20wHhcNMTcwMjE0MjI0ODIzWhcNMzAxMDI0MjI0ODIzWjAbMRkwFwYDVQQDExBia3JlYnMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1msHo+9YrTu8eaG9cm+7p2nymT/GtTN061CK9eSj37hT7TTR60AYyMfEzf/Nniqb4g1cOIPZcm9ovtrcuJddFXFdLJs72cqRN5kMTgTM+J6x9KASd2H57rNUyQwZnPlMmdnSayp8wMPCdURWa5BTjLeWs17zZYzJ5mEaOsVCR05sg5kaooWJYDlVs6Bnl9oQaIczQ9k10XLm+mbMlZvl+tvbgyzKnbvBh207MYor3BFOnLxY1TTzTn06Fz/t7Dg20+CHaq9tKqIUa4UxAXhqZiuIpBeA8DZ2+/Auz8Ge+tT+5uZpuFWTG2OMxYw7S1uYD8pV9i2+tyteFduSesytswIDAQABoy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBTRZOw4cT2k1SqHCn13w6WqEMuHgDANBgkqhkiG9w0BAQUFAAOCAQEAxP/ASjeTjbhsifVZTjh3vyfOK5zZ5Zi8HY0xfsvpxCZgU+VCSuTceSBKMnjEz44RNAid57aF+2zhmyL1Hdf4Ku7aFiSdTKJY3jrxa4kBYvpbhf1VTltOGHpdRKjixb9r2NXZh1wJkldaM5py2eUpNkgySGOMM/b7WlmPU+iSU/9TsNXt+/EHWm4Qy2prNZbbv+1B16dlfmkccqGuIK8mwes4MgdYXFAB1n6bQS9lU96y/kOMuJ+33G5c+LuljmEMLWm8bSsyhIK3FT0tpr73OV/g7ybk4nrgMXZCd48+Dp4ML8ahXN8rkhWkDXmwqswzaJO0sE/gyFx7mRzcOhrRZQ=="],"n":"1msHo-9YrTu8eaG9cm-7p2nymT_GtTN061CK9eSj37hT7TTR60AYyMfEzf_Nniqb4g1cOIPZcm9ovtrcuJddFXFdLJs72cqRN5kMTgTM-J6x9KASd2H57rNUyQwZnPlMmdnSayp8wMPCdURWa5BTjLeWs17zZYzJ5mEaOsVCR05sg5kaooWJYDlVs6Bnl9oQaIczQ9k10XLm-mbMlZvl-tvbgyzKnbvBh207MYor3BFOnLxY1TTzTn06Fz_t7Dg20-CHaq9tKqIUa4UxAXhqZiuIpBeA8DZ2-_Auz8Ge-tT-5uZpuFWTG2OMxYw7S1uYD8pV9i2-tyteFduSesytsw","e":"AQAB","kid":"RDUzRkIxMEQ1MTVDNTY4MDAwNENCNUYzNkM3RjRFQjEyOUU5NzA3Qg","x5t":"RDUzRkIxMEQ1MTVDNTY4MDAwNENCNUYzNkM3RjRFQjEyOUU5NzA3Qg"}]}
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            raise ValueError("Use an RS256 signed JWT Access Token")

        if unverified_header["alg"] == "HS256":
            raise ValueError("Use an RS256 signed JWT Access Token")

        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = key['x5c'][0]
        if rsa_key:
            try:
                jwt.decode(
                    token,
                    rsa_key,
                    algorithms=['RS256'],
                    audience='https://aliens-go-home.digituz.com.br',
                    issuer="https://bkrebs.auth0.com/"
                )

            except jwt.ExpiredSignatureError:
                raise ValueError("Token is expired")

            except jwt.JWTClaimsError:
                raise ValueError("Please, check the audience and issuer")

            except Exception:
                raise ValueError("Unable to parse authentication token.")

        else:
            raise ValueError("Unable to find appropriate key")

        response = self.get_response(request)
        return response