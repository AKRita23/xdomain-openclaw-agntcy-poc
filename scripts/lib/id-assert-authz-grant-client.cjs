'use strict';

const qs = require('qs');

function _interopDefaultCompat (e) { return e && typeof e === 'object' && 'default' in e ? e.default : e; }

const qs__default = /*#__PURE__*/_interopDefaultCompat(qs);

var __defProp$4 = Object.defineProperty;
var __defNormalProp$4 = (obj, key, value) => key in obj ? __defProp$4(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField$4 = (obj, key, value) => {
  __defNormalProp$4(obj, typeof key !== "symbol" ? key + "" : key, value);
  return value;
};
class InvalidArgumentError extends Error {
  constructor(argument, message) {
    super(`Invalid argument ${argument}.${message ? ` ${message}` : ""}`);
    this.name = this.constructor.name;
  }
}
class InvalidPayloadError extends Error {
  constructor(message, data) {
    super(`Invalid payload. ${message}`);
    __publicField$4(this, "data");
    this.name = this.constructor.name;
    if (data && typeof data === "object") {
      this.data = data;
    }
  }
}

var OAuthGrantType = /* @__PURE__ */ ((OAuthGrantType2) => {
  OAuthGrantType2["JWT_BEARER"] = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  OAuthGrantType2["TOKEN_EXCHANGE"] = "urn:ietf:params:oauth:grant-type:token-exchange";
  OAuthGrantType2["ID_JAG"] = "urn:okta:params:oauth:grant-type:id-jag";
  return OAuthGrantType2;
})(OAuthGrantType || {});
var OAuthTokenType = /* @__PURE__ */ ((OAuthTokenType2) => {
  OAuthTokenType2["ACCESS_TOKEN"] = "urn:ietf:params:oauth:token-type:access_token";
  OAuthTokenType2["ID_TOKEN"] = "urn:ietf:params:oauth:token-type:id_token";
  OAuthTokenType2["JWT_ID_JAG"] = "urn:ietf:params:oauth:token-type:id-jag";
  OAuthTokenType2["SAML2"] = "urn:ietf:params:oauth:token-type:saml2";
  return OAuthTokenType2;
})(OAuthTokenType || {});
var OAuthClientAssertionType = /* @__PURE__ */ ((OAuthClientAssertionType2) => {
  OAuthClientAssertionType2["JWT_BEARER"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  return OAuthClientAssertionType2;
})(OAuthClientAssertionType || {});
const OAuthErrorTypes = [
  "invalid_request",
  "invalid_client",
  "invalid_grant",
  "unauthorized_client",
  "unsupported_grant_type",
  "invalid_scope"
];

var __defProp$3 = Object.defineProperty;
var __defNormalProp$3 = (obj, key, value) => key in obj ? __defProp$3(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField$3 = (obj, key, value) => {
  __defNormalProp$3(obj, typeof key !== "symbol" ? key + "" : key, value);
  return value;
};
class HttpResponse {
  constructor(url, status, statusText, body) {
    __publicField$3(this, "url");
    __publicField$3(this, "status");
    __publicField$3(this, "statusText");
    __publicField$3(this, "body");
    this.url = url;
    this.status = status;
    this.statusText = statusText;
    this.body = body;
  }
}

var __defProp$2 = Object.defineProperty;
var __defNormalProp$2 = (obj, key, value) => key in obj ? __defProp$2(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField$2 = (obj, key, value) => {
  __defNormalProp$2(obj, typeof key !== "symbol" ? key + "" : key, value);
  return value;
};
const invalidRFC8693PayloadError = (field, requirement, payload) => new InvalidPayloadError(
  `The field '${field}' ${requirement} per RFC8693. See https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1.`,
  { payload }
);
class OauthTokenExchangeResponse {
  constructor(payload) {
    __publicField$2(this, "access_token");
    __publicField$2(this, "issued_token_type");
    __publicField$2(this, "token_type");
    __publicField$2(this, "scope");
    __publicField$2(this, "expires_in");
    __publicField$2(this, "refresh_token");
    const { access_token, issued_token_type, token_type, scope, expires_in, refresh_token } = payload;
    if (!access_token || typeof access_token !== "string") {
      throw invalidRFC8693PayloadError(
        "access_token",
        "must be present and a valid value",
        payload
      );
    }
    this.access_token = access_token;
    if (!issued_token_type || typeof issued_token_type !== "string") {
      throw invalidRFC8693PayloadError(
        "issued_token_type",
        "must be present and a valid value",
        payload
      );
    }
    this.issued_token_type = issued_token_type;
    if (!token_type || typeof token_type !== "string") {
      throw invalidRFC8693PayloadError("token_type", "must be present and a valid value", payload);
    }
    this.token_type = token_type;
    if (scope && typeof scope === "string") {
      this.scope = scope;
    }
    if (typeof expires_in === "number" && expires_in > 0) {
      this.expires_in = expires_in;
    }
    if (refresh_token && typeof refresh_token === "string") {
      this.refresh_token = refresh_token;
    }
  }
}

var __defProp$1 = Object.defineProperty;
var __defNormalProp$1 = (obj, key, value) => key in obj ? __defProp$1(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField$1 = (obj, key, value) => {
  __defNormalProp$1(obj, typeof key !== "symbol" ? key + "" : key, value);
  return value;
};
const invalidOAuthErrorResponse = (field, requirement, payload) => new InvalidPayloadError(
  `The field '${field}' ${requirement} per RFC6749. See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.`,
  { payload }
);
class OAuthBadRequest {
  constructor(payload) {
    __publicField$1(this, "error");
    __publicField$1(this, "error_description");
    __publicField$1(this, "error_uri");
    const { error, error_description, error_uri } = payload;
    if (!error || !OAuthErrorTypes.includes(error)) {
      throw invalidOAuthErrorResponse("error", "must be present and a valid value", payload);
    }
    this.error = error;
    if (error_description) {
      if (typeof error_description !== "string") {
        throw invalidOAuthErrorResponse("error_description", "must be a valid string", payload);
      }
      this.error_description = error_description;
    }
    if (error_uri) {
      if (typeof error_uri !== "string") {
        throw invalidOAuthErrorResponse("error_uri", "must be a valid string", payload);
      }
      this.error_uri = error_uri;
    }
  }
}

const transformScopes = (scopes) => {
  if (scopes) {
    if (Array.isArray(scopes)) {
      return scopes.join(" ");
    }
    if (scopes instanceof Set) {
      return Array.from(scopes).join(" ");
    }
    if (typeof scopes === "string") {
      return scopes;
    }
    throw new InvalidArgumentError(
      "scopes",
      "Expected a valid string, array of strings, or Set of strings."
    );
  }
  return "";
};

const requestIdJwtAuthzGrant = async (opts) => {
  const { resource, subjectToken, subjectTokenType, audience, scopes, tokenUrl } = opts;
  if (!tokenUrl || typeof tokenUrl !== "string") {
    throw new InvalidArgumentError("opts.tokenUrl", "A valid url is required.");
  }
  if (!audience || typeof audience !== "string") {
    throw new InvalidArgumentError("opts.audience", "A valid string is required.");
  }
  if (!subjectToken || typeof subjectToken !== "string") {
    throw new InvalidArgumentError("opts.subjectToken");
  }
  let subjectTokenUrn;
  switch (subjectTokenType) {
    case "saml":
      subjectTokenUrn = OAuthTokenType.SAML2;
      break;
    case "oidc":
      subjectTokenUrn = OAuthTokenType.ID_TOKEN;
      break;
    case "access_token":
      subjectTokenUrn = OAuthTokenType.ACCESS_TOKEN;
      break;
    default:
      throw new InvalidArgumentError(
        "opts.subjectTokenType",
        "A valid SubjectTokenType constant is required."
      );
  }
  const scope = transformScopes(scopes);
  let clientAssertionData;
  if ("clientID" in opts) {
    clientAssertionData = {
      client_id: opts.clientID,
      ...opts.clientSecret ? { client_secret: opts.clientSecret } : null
    };
  } else if ("clientAssertion" in opts) {
    clientAssertionData = {
      client_assertion_type: OAuthClientAssertionType.JWT_BEARER,
      client_assertion: opts.clientAssertion
    };
  } else {
    throw new InvalidArgumentError(
      "opts.clientAssertion",
      "Expected a valid client assertion jwt or client id and secret."
    );
  }
  const requestData = {
    grant_type: OAuthGrantType.ID_JAG,
    requested_token_type: OAuthTokenType.JWT_ID_JAG,
    audience,
    resource,
    scope,
    subject_token: subjectToken,
    subject_token_type: subjectTokenUrn,
    ...clientAssertionData
  };
  const body = qs__default.stringify(requestData);
  console.error("[DEBUG requestIdJwtAuthzGrant] request body:", JSON.stringify(requestData, null, 2));
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const resStatus = response.status;
  if (resStatus === 400) {
    return {
      error: new OAuthBadRequest(await response.json())
    };
  }
  if (resStatus > 200 && resStatus < 600) {
    return {
      error: new HttpResponse(
        response.url,
        response.status,
        response.statusText,
        await response.text()
      )
    };
  }
  const payload = new OauthTokenExchangeResponse(await response.json());
  if (payload.issued_token_type !== OAuthTokenType.JWT_ID_JAG) {
    throw new InvalidPayloadError(
      `The field 'issued_token_type' must have the value '${OAuthTokenType.JWT_ID_JAG}' per the Identity Assertion Authorization Grant Draft Section 5.2.`
    );
  }
  if (payload.token_type.toLowerCase() !== "n_a") {
    throw new InvalidPayloadError(
      `The field 'token_type' must have the value 'n_a' per the Identity Assertion Authorization Grant Draft Section 5.2.`
    );
  }
  return { payload };
};

var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => {
  __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
  return value;
};
const invalidRFC6749PayloadError = (field, requirement, payload) => new InvalidPayloadError(
  `The field '${field}' ${requirement} per RFC8693. See https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.`,
  { payload }
);
const invalidRFC7523PayloadError = (field, requirement, payload) => new InvalidPayloadError(
  `The field '${field}' ${requirement} per RFC7523. See https://datatracker.ietf.org/doc/html/rfc7523#section-2.1.`,
  { payload }
);
class OauthJwtBearerAccessTokenResponse {
  constructor(payload) {
    __publicField(this, "access_token");
    __publicField(this, "token_type");
    __publicField(this, "scope");
    __publicField(this, "expires_in");
    __publicField(this, "refresh_token");
    const { access_token, token_type, scope, expires_in, refresh_token } = payload;
    if (!access_token || typeof access_token !== "string") {
      throw invalidRFC6749PayloadError(
        "access_token",
        "must be present and a valid value",
        payload
      );
    }
    this.access_token = access_token;
    if (!token_type || typeof token_type !== "string" || token_type.toLowerCase() !== "bearer") {
      throw invalidRFC7523PayloadError("token_type", "must have the value 'bearer'", payload);
    }
    this.token_type = token_type;
    if (scope && typeof scope === "string") {
      this.scope = scope;
    }
    if (typeof expires_in === "number" && expires_in > 0) {
      this.expires_in = expires_in;
    }
    if (refresh_token && typeof refresh_token === "string") {
      this.refresh_token = refresh_token;
    }
  }
}

const exchangeIdJwtAuthzGrant = async (opts) => {
  const { tokenUrl, authorizationGrant, scopes, audience } = opts;
  if (!tokenUrl || typeof tokenUrl !== "string") {
    throw new InvalidArgumentError("opts.tokenUrl", "A valid url is required.");
  }
  if (!authorizationGrant || typeof authorizationGrant !== "string") {
    throw new InvalidArgumentError(
      "opts.authorizationGrant",
      "A valid authorization grant is required."
    );
  }
  const scope = transformScopes(scopes);
  let clientAssertionData;
  if ("clientID" in opts) {
    clientAssertionData = {
      client_id: opts.clientID,
      ...opts.clientSecret ? { client_secret: opts.clientSecret } : null
    };
  } else if ("clientAssertion" in opts) {
    clientAssertionData = {
      client_assertion_type: OAuthClientAssertionType.JWT_BEARER,
      client_assertion: opts.clientAssertion
    };
  } else {
    throw new InvalidArgumentError(
      "opts.clientAssertion",
      "Expected a valid client assertion jwt or client id and secret."
    );
  }
  const requestData = {
    grant_type: OAuthGrantType.JWT_BEARER,
    assertion: authorizationGrant,
    scope,
    ...audience ? { audience } : null,
    ...clientAssertionData
  };
  const body = qs__default.stringify(requestData);
  console.error("[DEBUG exchangeIdJwtAuthzGrant] request body:", JSON.stringify(requestData, null, 2));
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const resStatus = response.status;
  if (resStatus === 400) {
    return {
      error: new OAuthBadRequest(await response.json())
    };
  }
  if (resStatus > 200 && resStatus < 600) {
    return {
      error: new HttpResponse(
        response.url,
        response.status,
        response.statusText,
        await response.text()
      )
    };
  }
  const payload = new OauthJwtBearerAccessTokenResponse(
    await response.json()
  );
  return { payload };
};

exports.HttpResponse = HttpResponse;
exports.InvalidArgumentError = InvalidArgumentError;
exports.InvalidPayloadError = InvalidPayloadError;
exports.JwtAuthGrantResponse = OauthTokenExchangeResponse;
exports.OAuthBadRequest = OAuthBadRequest;
exports.OAuthClientAssertionType = OAuthClientAssertionType;
exports.OAuthErrorTypes = OAuthErrorTypes;
exports.OAuthGrantType = OAuthGrantType;
exports.OAuthTokenType = OAuthTokenType;
exports.exchangeIdJwtAuthzGrant = exchangeIdJwtAuthzGrant;
exports.requestIdJwtAuthzGrant = requestIdJwtAuthzGrant;
