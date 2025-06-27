"""Minimal CrowdStrike Falcon OAuth2 API SDK for ta_crowdstrike_xdr.

This is a reduced version containing only Alerts and PreventionPolicy modules.
"""
from ._version import _VERSION, _MAINTAINER, _AUTHOR, _AUTHOR_EMAIL
from ._version import _CREDITS, _DESCRIPTION, _TITLE, _PROJECT_URL
from ._version import _DOCS_URL, _KEYWORDS, version
from ._auth_object import (
    BaseFalconAuth,
    BearerToken,
    FalconInterface,
    UberInterface,
    InterfaceConfiguration
    )
from ._service_class import BaseServiceClass, ServiceClass
from ._util import confirm_base_region, confirm_base_url
from ._constant import (
    MAX_DEBUG_RECORDS,
    ALLOWED_METHODS,
    USER_AGENT,
    MIN_TOKEN_RENEW_WINDOW,
    MAX_TOKEN_RENEW_WINDOW,
    GLOBAL_API_MAX_RETURN,
    MOCK_OPERATIONS
    )
from ._enum import (
    BaseURL,
    ContainerBaseURL,
    TokenFailReason,
    IngestBaseURL,
    IngestFormat,
    TimeUnit
    )
from ._log import LogFacility
from ._error import (
    APIError,
    SDKError,
    SDKWarning,
    NoContentWarning,
    SSLDisabledWarning,
    RegionSelectError,
    InvalidCredentials,
    InvalidMethod,
    InvalidOperation,
    TokenNotSpecified,
    KeywordsOnly,
    CannotRevokeToken,
    FunctionalityNotImplemented,
    InvalidBaseURL,
    PayloadValidationError,
    NoAuthenticationMechanism,
    InvalidIndex,
    InvalidCredentialFormat,
    UnnecessaryEncodingUsed,
    DeprecatedClass,
    DeprecatedOperation,
    SDKDeprecationWarning,
    InvalidRoute,
    InvalidServiceCollection,
    InvalidOperationSearch
    )
from ._result import (
    Result,
    ExpandedResult,
    BaseDictionary,
    BaseResource,
    Resources,
    ResponseComponent,
    Meta,
    Headers,
    Errors,
    RawBody,
    BinaryFile
    )
from ._api_request import (
    APIRequest,
    RequestBehavior,
    RequestConnection,
    RequestMeta,
    RequestPayloads,
    RequestValidator
    )
from ._ngsiem import (
    HTTPEventCollector,
    HEC,
    IngestPayload,
    IngestConfig,
    SessionManager
)
from ._helper import random_string, Indicator, Color, find_operation
from .alerts import Alerts
from .prevention_policy import PreventionPolicy, PreventionPolicies
from .oauth2 import OAuth2

__version__ = _VERSION
__maintainer__ = _MAINTAINER
__author__ = _AUTHOR
__author_email__ = _AUTHOR_EMAIL
__credits__ = _CREDITS
__description__ = _DESCRIPTION
__title__ = _TITLE
__project_url__ = _PROJECT_URL
__docs_url__ = _DOCS_URL
__keywords__ = _KEYWORDS
__all__ = [
    "confirm_base_url", "confirm_base_region", "BaseURL", "ServiceClass", "Alerts",
    "BaseServiceClass", "BaseFalconAuth", "FalconInterface", "UberInterface", "TokenFailReason",
    "OAuth2", "PreventionPolicy", "PreventionPolicies", "MAX_DEBUG_RECORDS",
    "Result", "APIError", "SDKError", "SDKWarning", "NoContentWarning", "SSLDisabledWarning",
    "RegionSelectError", "InvalidCredentials", "InvalidMethod", "InvalidOperation",
    "TokenNotSpecified", "KeywordsOnly", "ALLOWED_METHODS", "USER_AGENT", "APIRequest",
    "ExpandedResult", "CannotRevokeToken", "Headers", "Meta", "Resources",
    "ResponseComponent", "BaseDictionary", "Errors", "BaseResource", "RawBody", "BinaryFile",
    "FunctionalityNotImplemented", "BearerToken", "LogFacility", "InvalidBaseURL",
    "InterfaceConfiguration", "RequestBehavior", "RequestConnection", "RequestMeta",
    "RequestPayloads", "RequestValidator", "PayloadValidationError", "MIN_TOKEN_RENEW_WINDOW",
    "MAX_TOKEN_RENEW_WINDOW", "GLOBAL_API_MAX_RETURN", "MOCK_OPERATIONS",
    "NoAuthenticationMechanism", "InvalidIndex", "version", "InvalidCredentialFormat",
    "UnnecessaryEncodingUsed", "DeprecatedClass", "DeprecatedOperation",
    "SDKDeprecationWarning", "ContainerBaseURL", "IngestBaseURL", "IngestFormat",
    "IngestPayload", "HTTPEventCollector", "IngestConfig", "SessionManager", "TimeUnit",
    "Color", "Indicator", "random_string", "find_operation",
    "InvalidRoute", "InvalidServiceCollection", "InvalidOperationSearch", "HEC"
    ]
