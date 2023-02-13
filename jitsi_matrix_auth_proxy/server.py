import logging
from functools import wraps
from os import environ
from time import monotonic
from typing import Any, Mapping, Optional
from urllib.parse import urlencode

from async_lru import alru_cache
from blacksheep import Application, Content, Request, ok, see_other
from blacksheep.client import ClientSession
from jwt import decode as jwt_decode
from jwt import encode as jwt_encode

JITSI_APPID = environ["JITSI_APPID"]
JITSI_APPSECRET = environ["JITSI_APPSECRET"]
JITSI_DOMAIN = environ["JITSI_DOMAIN"]
JITSI_TOPLEVEL_REDIRECT_PATH = environ.get(
    "JITSI_TOPLEVEL_REDIRECT_PATH", "jwt-handled"
)
LOG_LEVEL = environ.get("LOG_LEVEL", "INFO")


logging.basicConfig(
    format="%(levelname)s: %(message)s",
    level=getattr(logging, LOG_LEVEL.upper()),
)


def timed_alru_cache(seconds: int = 30, maxsize: int = 128):
    def wrapper_cache(func: Any):
        func = alru_cache(maxsize=maxsize)(func)
        func.expiration = monotonic() + seconds

        @wraps(func)
        async def wrapped_func(*args, **kwargs):
            current_monotonic_clock = monotonic()
            if current_monotonic_clock >= func.expiration:
                logging.debug(
                    f"Expiration reached for cached function: {func.__name__} ({current_monotonic_clock} >= {func.expiration})"
                )
                func.cache_clear()
                func.expiration = monotonic() + seconds
            return await func(*args, **kwargs)

        return wrapped_func

    return wrapper_cache


def extract_matrix_claims(jwt: str) -> Optional[Mapping[str, str]]:
    claims = jwt_decode(jwt, options={"verify_signature": False})
    logging.debug(f"Jitsi JWT claims: {claims}")
    matrix_claims = claims.get("context", {}).get("matrix", {})
    if (server_name := matrix_claims.get("server_name")) and (
        openid_token := matrix_claims.get("token")
    ):
        return {
            "server_name": server_name,
            "openid_token": openid_token,
        }


@timed_alru_cache(300)
async def get_homeserver_base_url(http_client: ClientSession, server_name: str) -> str:
    autodiscovery_url = f"https://{server_name}/.well-known/matrix/client"
    response = await http_client.get(autodiscovery_url)
    data = await response.json()
    homeserver_base_url = data.get("m.homeserver", {}).get("base_url", "").rstrip("/")
    if not homeserver_base_url:
        raise ValueError(f"bad autodiscovery data: {data}")
    logging.debug(f"Homeserver base url: {homeserver_base_url}")
    return homeserver_base_url


@timed_alru_cache()
async def check_openid_token(
    http_client: ClientSession, server_name: str, openid_token: str
) -> bool:
    homeserver_base_url = await get_homeserver_base_url(http_client, server_name)
    logging.debug(
        f"Cached function get_homeserver_base_url: {get_homeserver_base_url.cache_info()}"
    )
    url = f"{homeserver_base_url}/_matrix/federation/v1/openid/userinfo?access_token={openid_token}"
    response = await http_client.get(url)
    data = await response.json()
    mx_userid = data.get("sub")
    if mx_userid:
        logging.info(f"Valid OpenID token (Matrix) for user: {mx_userid}")
        return True
    else:
        logging.warning(f"Invalid OpenID token (Matrix): {data}")
        return False


def generate_jitsi_jwt() -> str:
    payload = {
        "aud": "jitsi",
        "iss": JITSI_APPID,
        "sub": JITSI_DOMAIN,
        "room": "*",
    }
    jwt = jwt_encode(payload, JITSI_APPSECRET, algorithm="HS256")
    logging.debug(f"Generated Jitsi JWT: {jwt}")
    return jwt


def build_redirect_url(request: Request, query) -> str:
    params = urlencode(query, doseq=True)
    return (
        f"https://{JITSI_DOMAIN}/{JITSI_TOPLEVEL_REDIRECT_PATH}{request.path}?{params}"
    )


async def configure_http_client(app: Application):
    http_client = ClientSession()
    app.services.add_instance(http_client)


async def dispose_http_client(app: Application):
    http_client = app.service_provider.get(ClientSession)
    await http_client.close()


app = Application()
app.on_start += configure_http_client
app.on_stop += dispose_http_client


@app.router.get("/*")
async def handle_all_get(
    http_client: ClientSession,
    request: Request,
    jwt: Optional[str] = None,
):
    query = request.query.copy()
    if jwt and (matrix_claims := extract_matrix_claims(jwt)):
        if await check_openid_token(http_client, **matrix_claims):
            query["jwt"] = [generate_jitsi_jwt()]
        logging.debug(f"Cached function: {check_openid_token.cache_info()}")

    redirect_url = build_redirect_url(request, query)
    return see_other(redirect_url)


@app.router.post("/http-bind")
async def handle_bosh(
    http_client: ClientSession,
    request: Request,
    token: Optional[str] = None,
):
    query = request.query.copy()
    if token and (matrix_claims := extract_matrix_claims(token)):
        if await check_openid_token(http_client, **matrix_claims):
            query["token"] = [generate_jitsi_jwt()]
        logging.debug(f"Cached function: {check_openid_token.cache_info()}")

    redirect_url = build_redirect_url(request, query)

    xmpp_request_xml = await request.text()
    logging.debug(f"XMPP request: {xmpp_request_xml}")

    content = Content(request.content_type(), xmpp_request_xml.encode())
    response = await http_client.post(redirect_url, content)

    xmpp_response_xml = await response.text()
    logging.debug(f"XMPP response: {xmpp_response_xml}")

    return ok(xmpp_response_xml)
