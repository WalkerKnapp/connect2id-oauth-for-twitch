/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.oauth2.sdk.ciba;


import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * CIBA error push delivery to the client notification endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0, section 12.
 * </ul>
 */
@Immutable
public class CIBAErrorDelivery extends CIBAPushCallback {
	
	
	/**
	 * The standard OAuth 2.0 errors for a CIBA error delivery.
	 */
	private static final Set<ErrorObject> STANDARD_ERRORS;
	
	static {
		Set<ErrorObject> errors = new HashSet<>();
		errors.add(OAuth2Error.ACCESS_DENIED);
		errors.add(CIBAError.EXPIRED_TOKEN);
		errors.add(CIBAError.TRANSACTION_FAILED);
		STANDARD_ERRORS = Collections.unmodifiableSet(errors);
	}
	
	
	/**
	 * Gets the standard OAuth 2.0 errors for a CIBA error delivery.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
		
		return STANDARD_ERRORS;
	}
	
	
	/**
	 * The error object.
	 */
	private final ErrorObject errorObject;
	
	
	/**
	 * Creates a new CIBA error push delivery.
	 *
	 * @param endpoint      The client notification endpoint. Must not be
	 *                      {@code null}.
	 * @param accessToken   The client notification token. Must not be
	 *                      {@code null}.
	 * @param authRequestID The CIBA request ID. Must not be {@code null}.
	 * @param errorObject   The error object. Must not be {@code null}.
	 */
	public CIBAErrorDelivery(final URI endpoint,
				 final BearerAccessToken accessToken,
				 final AuthRequestID authRequestID,
				 final ErrorObject errorObject) {
		
		super(endpoint, accessToken, authRequestID);
		
		if (endpoint == null) {
			throw new IllegalArgumentException("The error object must not be null");
		}
		this.errorObject = errorObject;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		
		return false;
	}
	
	
	/**
	 * Returns the error object.
	 *
	 * @return The error object.
	 */
	public ErrorObject getErrorObject() {
		
		return errorObject;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("auth_req_id", getAuthRequestID().getValue());
		jsonObject.putAll(getErrorObject().toJSONObject());
		httpRequest.setBody(jsonObject.toJSONString());
		return httpRequest;
	}
	
	
	/**
	 * Parses a CIBA error push delivery from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The CIBA error push delivery.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBAErrorDelivery parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		URI uri = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_JSON);
		
		BearerAccessToken clientNotificationToken = BearerAccessToken.parse(httpRequest);
		
		AuthRequestID authRequestID = new AuthRequestID(
			JSONObjectUtils.getString(
				httpRequest.getQueryAsJSONObject(),
				"auth_req_id")
		);
		
		ErrorObject errorObject = ErrorObject.parse(httpRequest.getQueryAsJSONObject());
		
		return new CIBAErrorDelivery(uri, clientNotificationToken, authRequestID, errorObject);
	}
}
