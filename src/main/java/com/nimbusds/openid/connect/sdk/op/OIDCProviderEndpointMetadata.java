/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Provider (OP) endpoint metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
 *     <li>OAuth 2.0 Device Flow for Browserless and Input Constrained Devices
 *         (draft-ietf-oauth-device-flow-14)
 *     <li>OpenID Connect Discovery 1.0, section 3.
 *     <li>OpenID Connect Session Management 1.0, section 2.1 (draft 28).
 *     <li>OpenID Connect Front-Channel Logout 1.0, section 3 (draft 02).
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.1 (draft 07).
 *     <li>OpenID Connect Federation 1.0 (draft 22).
 * </ul>
 */
public class OIDCProviderEndpointMetadata extends AuthorizationServerEndpointMetadata implements ReadOnlyOIDCProviderEndpointMetadata {
	
	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;
	
	
	static {
		Set<String> p = new HashSet<>(AuthorizationServerEndpointMetadata.getRegisteredParameterNames());
		p.add("userinfo_endpoint");
		p.add("check_session_iframe");
		p.add("end_session_endpoint");
		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * Gets the registered provider metadata parameter names for endpoints.
	 *
	 * @return The registered provider metadata parameter names for the
	 *         endpoints, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {
		
		return REGISTERED_PARAMETER_NAMES;
	}
	
	
	/**
	 * The UserInfo endpoint.
	 */
	private URI userInfoEndpoint;
	
	
	/**
	 * The cross-origin check session iframe.
	 */
	private URI checkSessionIframe;
	
	
	/**
	 * The logout endpoint.
	 */
	private URI endSessionEndpoint;
	
	
	/**
	 * Creates a new OpenID Connect provider endpoint metadata instance.
	 */
	public OIDCProviderEndpointMetadata() {
	}
	
	
	/**
	 * Converts an authorization server endpoint metadata to an OpenID
	 * Connect provider endpoint metadata instance.
	 */
	public OIDCProviderEndpointMetadata(final AuthorizationServerEndpointMetadata endpointMetadata) {

		setAuthorizationEndpointURI(endpointMetadata.getAuthorizationEndpointURI());
		setTokenEndpointURI(endpointMetadata.getTokenEndpointURI());
		setRegistrationEndpointURI(endpointMetadata.getRegistrationEndpointURI());
		setIntrospectionEndpointURI(endpointMetadata.getIntrospectionEndpointURI());
		setRevocationEndpointURI(endpointMetadata.getRevocationEndpointURI());
		setDeviceAuthorizationEndpointURI(endpointMetadata.getDeviceAuthorizationEndpointURI());
		setBackChannelAuthenticationEndpointURI(endpointMetadata.getBackChannelAuthenticationEndpointURI());
		setPushedAuthorizationRequestEndpointURI(endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		setRequestObjectEndpoint(endpointMetadata.getRequestObjectEndpoint());
		setFederationRegistrationEndpointURI(endpointMetadata.getFederationRegistrationEndpointURI());
	}


	@Override
	public URI getUserInfoEndpointURI() {
		return userInfoEndpoint;
	}


	/**
	 * Sets the UserInfo endpoint URI. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @param userInfoEndpoint The UserInfo endpoint URI, {@code null} if
	 *                         not specified.
	 */
	public void setUserInfoEndpointURI(final URI userInfoEndpoint) {
		this.userInfoEndpoint = userInfoEndpoint;
	}
	
	
	@Override
	public URI getCheckSessionIframeURI() {
		return checkSessionIframe;
	}
	
	
	/**
	 * Sets the cross-origin check session iframe URI. Corresponds to the
	 * {@code check_session_iframe} metadata field.
	 *
	 * @param checkSessionIframe The check session iframe URI, {@code null}
	 *                           if not specified.
	 */
	public void setCheckSessionIframeURI(final URI checkSessionIframe) {
		this.checkSessionIframe = checkSessionIframe;
	}
	
	
	@Override
	public URI getEndSessionEndpointURI() {
		return endSessionEndpoint;
	}
	
	
	/**
	 * Sets the logout endpoint URI. Corresponds to the
	 * {@code end_session_endpoint} metadata field.
	 *
	 * @param endSessionEndpoint The logoout endpoint URI, {@code null} if
	 *                           not specified.
	 */
	public void setEndSessionEndpointURI(final URI endSessionEndpoint) {
		this.endSessionEndpoint = endSessionEndpoint;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = super.toJSONObject();
		
		if (getUserInfoEndpointURI() != null)
			o.put("userinfo_endpoint", getUserInfoEndpointURI().toString());
		
		if (getCheckSessionIframeURI() != null)
			o.put("check_session_iframe", getCheckSessionIframeURI().toString());
		
		if (getEndSessionEndpointURI() != null)
			o.put("end_session_endpoint", getEndSessionEndpointURI().toString());
		
		return o;
	}
	
	
	/**
	 * Parses an OAuth 2.0 Authorisation Server endpoint metadata from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The OAuth 2.0 Authorisation Server endpoint metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OAuth 2.0 Authorisation Server endpoint metadata.
	 */
	public static OIDCProviderEndpointMetadata parse(final JSONObject jsonObject)
		throws ParseException {

		AuthorizationServerEndpointMetadata as = AuthorizationServerEndpointMetadata.parse(jsonObject);

		OIDCProviderEndpointMetadata op = new OIDCProviderEndpointMetadata();
		
		op.setAuthorizationEndpointURI(as.getAuthorizationEndpointURI());
		op.setTokenEndpointURI(as.getTokenEndpointURI());
		op.setRegistrationEndpointURI(as.getRegistrationEndpointURI());
		op.setIntrospectionEndpointURI(as.getIntrospectionEndpointURI());
		op.setRevocationEndpointURI(as.getRevocationEndpointURI());
		op.setDeviceAuthorizationEndpointURI(as.getDeviceAuthorizationEndpointURI());
		op.setBackChannelAuthenticationEndpointURI(as.getBackChannelAuthenticationEndpointURI());
		op.setPushedAuthorizationRequestEndpointURI(as.getPushedAuthorizationRequestEndpointURI());
		op.setFederationRegistrationEndpointURI(as.getFederationRegistrationEndpointURI());
		op.setRequestObjectEndpoint(as.getRequestObjectEndpoint());
		op.userInfoEndpoint = JSONObjectUtils.getURI(jsonObject, "userinfo_endpoint", null);
		op.checkSessionIframe = JSONObjectUtils.getURI(jsonObject, "check_session_iframe", null);
		op.endSessionEndpoint = JSONObjectUtils.getURI(jsonObject, "end_session_endpoint", null);
		
		return op;
	}
}
