from fastapi import FastAPI, Request, Form
from typing import Optional
from starlette.responses import RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()


saml_settings = {
    "strict": False,
    "debug": True,
    "idp": {
        "entityId": os.getenv("SAML_ENTITY_ID"),
        "singleSignOnService": {
            "url": os.getenv("SAML_SSO_URL"),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "x509cert": os.getenv("SAML_CERT"),
    },
    "sp": {
        "entityId": os.getenv("SAML_ENTITY_ID"),
        "assertionConsumerService": {
            "url": os.getenv("SAML_ACS_URL"),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "x509cert": os.getenv("SAML_CERT"),
    },
}


async def prepare_from_fastapi_request(request: Request):
    form_data = await request.form()
    rv = {
        "http_host": request.client.host,
        "server_port": request.url.port,
        "script_name": request.url.path,
        "post_data": {},
        "get_data": {},
    }
    if request.query_params:
        rv["get_data"] = dict(request.query_params)
    if "SAMLResponse" in form_data:
        rv["post_data"]["SAMLResponse"] = form_data["SAMLResponse"]
    if "RelayState" in form_data:
        rv["post_data"]["RelayState"] = form_data["RelayState"]
    return rv


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/api/saml/login")
async def saml_login(request: Request):
    req = await prepare_from_fastapi_request(request)
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    callback_url = auth.login()
    return RedirectResponse(url=callback_url)


@app.post("/api/saml/callback")
async def saml_login_callback(request: Request):
    req = await prepare_from_fastapi_request(request)
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    auth.process_response()
    errors = auth.get_errors()
    if len(errors) == 0:
        if auth.is_authenticated():
            return {"message": "User authenticated"}
        else:
            return {"message": "User not authenticated"}
    else:
        return {"message": f"Error in callback: {', '.join(errors)}"}
