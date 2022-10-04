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

package com.nimbusds.oauth2.sdk.as;


import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.OrderedJSONObject;


/**
 * OAuth 2.0 Authorisation Server (AS) endpoint metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
 *     <li>OAuth 2.0 Pushed Authorization Requests (RFC 9126)
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 *     <li>OpenID Connect Client Initiated Backchannel Authentication Flow -
 * 	   Core 1.0
 *     <li>OpenID Connect Federation 1.0 (draft 22).
 * </ul>
 */
public class AuthorizationServerEndpointMetadata implements ReadOnlyAuthorizationServerEndpointMetadata {
	
	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;
	
	
	static {
		Set<String> p = new HashSet<>();
		p.add("authorization_endpoint");
		p.add("token_endpoint");
		p.add("registration_endpoint");
		p.add("introspection_endpoint");
		p.add("revocation_endpoint");
		p.add("request_object_endpoint");
		p.add("pushed_authorization_request_endpoint");
		p.add("device_authorization_endpoint");
		p.add("backchannel_authentication_endpoint");
		p.add("federation_registration_endpoint");
		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * Gets the registered provider metadata parameter names for endpoints.
	 *
	 * @return The registered provider metadata parameter names for
	 *         endpoints, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {
		
		return REGISTERED_PARAMETER_NAMES;
	}
	
	
	/**
	 * The authorisation endpoint.
	 */
	private URI authzEndpoint;
	
	
	/**
	 * The token endpoint.
	 */
	private URI tokenEndpoint;
	
	
	/**
	 * The registration endpoint.
	 */
	private URI regEndpoint;
	
	
	/**
	 * The token introspection endpoint.
	 */
	private URI introspectionEndpoint;
	
	
	/**
	 * The token revocation endpoint.
	 */
	private URI revocationEndpoint;
	
	
	/**
	 * The request object endpoint.
	 */
	private URI requestObjectEndpoint;
	
	
	/**
	 * The pushed request object endpoint.
	 */
	private URI parEndpoint;
	
	
	/**
	 * The device authorization endpoint.
	 */
	private URI deviceAuthzEndpoint;
	
	
	/**
	 * The back-channel authentication endpoint.
	 */
	private URI backChannelAuthEndpoint;
	
	
	/**
	 * The federation registration endpoint.
	 */
	private URI federationRegistrationEndpoint;
	
	
	/**
	 * Creates a new OAuth 2.0 Authorisation Server (AS) endpoint metadata
	 * instance.
	 */
	public AuthorizationServerEndpointMetadata() {
	}
	
	
	@Override
	public URI getAuthorizationEndpointURI() {
		return authzEndpoint;
	}
	
	
	/**
	 * Sets the authorisation endpoint URI. Corresponds the
	 * {@code authorization_endpoint} metadata field.
	 *
	 * @param authzEndpoint The authorisation endpoint URI, {@code null} if
	 *                      not specified.
	 */
	public void setAuthorizationEndpointURI(final URI authzEndpoint) {
		this.authzEndpoint = authzEndpoint;
	}
	
	
	@Override
	public URI getTokenEndpointURI() {
		return tokenEndpoint;
	}

	
	/**
	 * Sts the token endpoint URI. Corresponds the {@code token_endpoint}
	 * metadata field.
	 *
	 * @param tokenEndpoint The token endpoint URI, {@code null} if not
	 *                      specified.
	 */
	public void setTokenEndpointURI(final URI tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}
	
	
	@Override
	public URI getRegistrationEndpointURI() {
		return regEndpoint;
	}
	
	
	/**
	 * Sets the client registration endpoint URI. Corresponds to the
	 * {@code registration_endpoint} metadata field.
	 *
	 * @param regEndpoint The client registration endpoint URI,
	 *                    {@code null} if not specified.
	 */
	public void setRegistrationEndpointURI(final URI regEndpoint) {
		this.regEndpoint = regEndpoint;
	}
	
	
	@Override
	public URI getIntrospectionEndpointURI() {
		return introspectionEndpoint;
	}
	
	
	/**
	 * Sets the token introspection endpoint URI. Corresponds to the
	 * {@code introspection_endpoint} metadata field.
	 *
	 * @param introspectionEndpoint  The token introspection endpoint URI,
	 *                               {@code null} if not specified.
	 */
	public void setIntrospectionEndpointURI(final URI introspectionEndpoint) {
		this.introspectionEndpoint = introspectionEndpoint;
	}
	
	
	@Override
	public URI getRevocationEndpointURI() {
		return revocationEndpoint;
	}
	
	
	/**
	 * Sets the token revocation endpoint URI. Corresponds to the
	 * {@code revocation_endpoint} metadata field.
	 *
	 * @param revocationEndpoint The token revocation endpoint URI,
	 *                           {@code null} if not specified.
	 */
	public void setRevocationEndpointURI(final URI revocationEndpoint) {
		this.revocationEndpoint = revocationEndpoint;
	}
	
	
	@Override
	@Deprecated
	public URI getRequestObjectEndpoint() {
		return requestObjectEndpoint;
	}
	
	
	/**
	 * Sets the request object endpoint. Corresponds to the
	 * {@code request_object_endpoint} metadata field.
	 *
	 * @param requestObjectEndpoint The request object endpoint,
	 *                              {@code null} if not specified.
	 */
	@Deprecated
	public void setRequestObjectEndpoint(final URI requestObjectEndpoint) {
		this.requestObjectEndpoint = requestObjectEndpoint;
	}
	
	
	@Override
	public URI getPushedAuthorizationRequestEndpointURI() {
		return parEndpoint;
	}
	
	
	/**
	 * Gets the pushed authorisation request endpoint. Corresponds to the
	 * {@code pushed_authorization_request_endpoint} metadata field.
	 *
	 * @param parEndpoint The pushed authorisation request endpoint,
	 *                    {@code null} if not specified.
	 */
	public void setPushedAuthorizationRequestEndpointURI(final URI parEndpoint) {
		this.parEndpoint = parEndpoint;
	}
	
	
	@Override
	public URI getDeviceAuthorizationEndpointURI() {
		return deviceAuthzEndpoint;
	}
	
	
	/**
	 * Sets the device authorization endpoint URI. Corresponds the
	 * {@code device_authorization_endpoint} metadata field.
	 *
	 * @param deviceAuthzEndpoint The device authorization endpoint URI,
	 *                            {@code null} if not specified.
	 */
	public void setDeviceAuthorizationEndpointURI(final URI deviceAuthzEndpoint) {
		this.deviceAuthzEndpoint = deviceAuthzEndpoint;
	}
	
	
	@Override
	public URI getBackChannelAuthenticationEndpointURI() {
		return backChannelAuthEndpoint;
	}
	
	
	@Deprecated
	@Override
	public URI getBackChannelAuthenticationEndpoint() {
		return getBackChannelAuthenticationEndpointURI();
	}
	
	
	/**
	 * Sets the back-channel authentication endpoint URI. Corresponds the
	 * {@code backchannel_authentication_endpoint} metadata field.
	 *
	 * @param backChannelAuthEndpoint The back-channel authentication e
	 *                                endpoint URI, {@code null} if not
	 *                                specified.
	 */
	public void setBackChannelAuthenticationEndpointURI(final URI backChannelAuthEndpoint) {
		this.backChannelAuthEndpoint = backChannelAuthEndpoint;
	}
	
	
	/**
	 * Sets the back-channel authentication endpoint URI. Corresponds the
	 * {@code backchannel_authentication_endpoint} metadata field.
	 *
	 * @deprecated Use {@link #setBackChannelAuthenticationEndpointURI}
	 * instead.
	 *
	 * @param backChannelAuthEndpoint The back-channel authentication e
	 *                                endpoint URI, {@code null} if not
	 *                                specified.
	 */
	@Deprecated
	public void setBackChannelAuthenticationEndpoint(final URI backChannelAuthEndpoint) {
		setBackChannelAuthenticationEndpointURI(backChannelAuthEndpoint);
	}
	
	
	@Override
	public URI getFederationRegistrationEndpointURI() {
		return federationRegistrationEndpoint;
	}
	
	
	/**
	 * Sets the federation registration endpoint URI. Corresponds to the
	 * {@code federation_registration_endpoint} metadata field.
	 *
	 * @param federationRegistrationEndpoint The federation registration
	 *                                       endpoint URI, {@code null} if
	 *                                       not specified.
	 */
	public void setFederationRegistrationEndpointURI(final URI federationRegistrationEndpoint) {
		this.federationRegistrationEndpoint = federationRegistrationEndpoint;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = new OrderedJSONObject();
		
		if (getAuthorizationEndpointURI() != null)
			o.put("authorization_endpoint", getAuthorizationEndpointURI().toString());
		
		if (getTokenEndpointURI() != null)
			o.put("token_endpoint", getTokenEndpointURI().toString());
		
		if (getRegistrationEndpointURI() != null)
			o.put("registration_endpoint", getRegistrationEndpointURI().toString());
		
		if (getIntrospectionEndpointURI() != null)
			o.put("introspection_endpoint", getIntrospectionEndpointURI().toString());
		
		if (getRevocationEndpointURI() != null)
			o.put("revocation_endpoint", getRevocationEndpointURI().toString());
		
		if (getRequestObjectEndpoint() != null)
			o.put("request_object_endpoint", getRequestObjectEndpoint().toString());
		
		if (getPushedAuthorizationRequestEndpointURI() != null)
			o.put("pushed_authorization_request_endpoint", getPushedAuthorizationRequestEndpointURI().toString());
		
		if (getDeviceAuthorizationEndpointURI() != null)
			o.put("device_authorization_endpoint", getDeviceAuthorizationEndpointURI().toString());
		
		if (getBackChannelAuthenticationEndpointURI() != null)
			o.put("backchannel_authentication_endpoint", getBackChannelAuthenticationEndpointURI().toString());
		
		if (getFederationRegistrationEndpointURI() != null)
			o.put("federation_registration_endpoint", getFederationRegistrationEndpointURI().toString());
		
		return o;
	}
	
	
	@Override
	public String toString() {
		return toJSONObject().toJSONString();
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
	public static AuthorizationServerEndpointMetadata parse(final JSONObject jsonObject)
		throws ParseException {
		
		AuthorizationServerEndpointMetadata as = new AuthorizationServerEndpointMetadata();
		as.authzEndpoint = JSONObjectUtils.getURI(jsonObject, "authorization_endpoint", null);
		as.tokenEndpoint = JSONObjectUtils.getURI(jsonObject, "token_endpoint", null);
		as.regEndpoint = JSONObjectUtils.getURI(jsonObject, "registration_endpoint", null);
		as.introspectionEndpoint = JSONObjectUtils.getURI(jsonObject, "introspection_endpoint", null);
		as.revocationEndpoint = JSONObjectUtils.getURI(jsonObject, "revocation_endpoint", null);
		as.requestObjectEndpoint = JSONObjectUtils.getURI(jsonObject, "request_object_endpoint", null);
		as.parEndpoint = JSONObjectUtils.getURI(jsonObject, "pushed_authorization_request_endpoint", null);
		as.deviceAuthzEndpoint = JSONObjectUtils.getURI(jsonObject, "device_authorization_endpoint", null);
		as.backChannelAuthEndpoint = JSONObjectUtils.getURI(jsonObject, "backchannel_authentication_endpoint", null);
		as.federationRegistrationEndpoint = JSONObjectUtils.getURI(jsonObject, "federation_registration_endpoint", null);
		return as;
	}
}
