/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.*;
import com.nimbusds.openid.connect.sdk.nativesso.DeviceSecret;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;


/**
 * Token request. Used to obtain an {@link AccessToken access token} and an
 * optional {@link RefreshToken refresh token} at the tokens endpoint of an
 * authorisation server. Supports custom request parameters.
 *
 * <p>Example token request with an authorisation code grant:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * grant_type=authorization_code
 * &amp;code=SplxlOBeZQQYbYS6WxSbIA
 * &amp;redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396)
 *     <li>Resource Indicators for OAuth 2.0 (RFC 8707)
 *     <li>OAuth 2.0 Incremental Authorization (draft-ietf-oauth-incremental-authz-04)
 *     <li>OpenID Connect Native SSO for Mobile Apps 1.0
 * </ul>
 */
@Immutable
public class TokenRequest extends AbstractOptionallyIdentifiedRequest {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;

	static {
		Set<String> p = new HashSet<>();

		p.add("grant_type");
		p.add("client_id");
		p.add("client_secret");
		p.add("client_assertion_type");
		p.add("client_assertion");
		p.add("scope");
		p.add("authorization_details");
		p.add("resource");
		p.add("existing_grant");
		p.add("device_secret");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The authorisation grant.
	 */
	private final AuthorizationGrant authzGrant;


	/**
	 * The scope (optional).
	 */
	private final Scope scope;


	/**
	 * The RAR details (optional).
	 */
	private final List<AuthorizationDetail> authorizationDetails;
	
	
	/**
	 * The resource URI(s) (optional).
	 */
	private final List<URI> resources;
	
	
	/**
	 * Existing refresh token for incremental authorisation of a public
	 * client (optional).
	 */
	private final RefreshToken existingGrant;


	/**
	 * Device secret for native SSO (optional).
	 */
	private final DeviceSecret deviceSecret;


	/**
	 * Custom request parameters.
	 */
	private final Map<String,List<String>> customParams;


	private static final Set<String> ALLOWED_REPEATED_PARAMS = new HashSet<>(Arrays.asList(
		"resource", // https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2
		"audience" // https://www.rfc-editor.org/rfc/rfc8693.html#name-relationship-between-resour
	));


	/**
	 * Builder for constructing token requests.
	 */
	public static class Builder {


		/**
		 * The endpoint URI (optional).
		 */
		private final URI endpoint;


		/**
		 * The client authentication, {@code null} if none.
		 */
		private final ClientAuthentication clientAuth;


		/**
		 * The client identifier, {@code null} if not specified.
		 */
		private final ClientID clientID;


		/**
		 * The authorisation grant.
		 */
		private final AuthorizationGrant authzGrant;


		/**
		 * The scope (optional).
		 */
		private Scope scope;


		/**
		 * The RAR details (optional).
		 */
		private List<AuthorizationDetail> authorizationDetails;


		/**
		 * The resource URI(s) (optional).
		 */
		private List<URI> resources;


		/**
		 * Existing refresh token for incremental authorisation of a
		 * public client (optional).
		 */
		private RefreshToken existingGrant;


		/**
		 * Device secret for native SSO (optional).
		 */
		private DeviceSecret deviceSecret;


		/**
		 * Custom parameters.
		 */
		private final Map<String,List<String>> customParams = new HashMap<>();


		/**
		 * Creates a new builder for a token request with client
		 * authentication.
		 *
		 * @param endpoint   The URI of the token endpoint. May be
		 *                   {@code null} if the {@link #toHTTPRequest}
		 *                   method is not going to be used.
		 * @param clientAuth The client authentication. Must not be
		 *                   {@code null}.
		 * @param authzGrant The authorisation grant. Must not be
		 *                   {@code null}.
		 */
		public Builder(final URI endpoint,
			       final ClientAuthentication clientAuth,
			       final AuthorizationGrant authzGrant) {
			this.endpoint = endpoint;
			this.clientAuth = Objects.requireNonNull(clientAuth);
			clientID = null;
			this.authzGrant = Objects.requireNonNull(authzGrant);
		}


		/**
		 * Creates a new builder for a token request with no (explicit)
		 * client authentication. The grant itself may be used to
		 * authenticate the client.
		 *
		 * @param endpoint   The URI of the token endpoint. May be
		 *                   {@code null} if the {@link #toHTTPRequest}
		 *                   method is not going to be used.
		 * @param clientID   The client identifier. Must not be
		 *                   {@code null}.
		 * @param authzGrant The authorisation grant. Must not be
		 *                   {@code null}.
		 */
		public Builder(final URI endpoint,
			       final ClientID clientID,
			       final AuthorizationGrant authzGrant) {
			this.endpoint = endpoint;
			clientAuth = null;
			this.clientID = Objects.requireNonNull(clientID);
			this.authzGrant = Objects.requireNonNull(authzGrant);
		}


		/**
		 * Creates a new builder for a token request with no (explicit)
		 * client authentication, the client identifier is inferred
		 * from the authorisation grant.
		 *
		 * @param endpoint   The URI of the token endpoint. May be
		 *                   {@code null} if the {@link #toHTTPRequest}
		 *                   method is not going to be used.
		 * @param authzGrant The authorisation grant. Must not be
		 *                   {@code null}.
		 */
		public Builder(final URI endpoint,
			       final AuthorizationGrant authzGrant) {
			this.endpoint = endpoint;
			clientAuth = null;
			clientID = null;
			this.authzGrant = Objects.requireNonNull(authzGrant);
		}


		/**
		 * Sets the scope. Corresponds to the optional {@code scope}
		 * parameter.
		 *
		 * @param scope The scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder scope(final Scope scope) {
			this.scope = scope;
			return this;
		}


		/**
		 * Sets the Rich Authorisation Request (RAR) details.
		 * Corresponds to the optional {@code authorization_details}
		 * parameter.
		 *
		 * @param authorizationDetails The authorisation details,
		 *                             {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder authorizationDetails(final List<AuthorizationDetail> authorizationDetails) {
			this.authorizationDetails = authorizationDetails;
			return this;
		}


		/**
		 * Sets the resource server URI. Corresponds to the optional
		 * {@code resource} parameter.
		 *
		 * @param resource The resource URI, {@code null} if not
		 *                 specified.
		 *
		 * @return This builder.
		 */
		public Builder resource(final URI resource) {
			if (resource != null) {
				this.resources = Collections.singletonList(resource);
			} else {
				this.resources = null;
			}
			return this;
		}


		/**
		 * Sets the resource server URI(s). Corresponds to the optional
		 * {@code resource} parameter.
		 *
		 * @param resources The resource URI(s), {@code null} if not
		 *                  specified.
		 *
		 * @return This builder.
		 */
		public Builder resources(final URI ... resources) {
			if (resources != null) {
				this.resources = Arrays.asList(resources);
			} else {
				this.resources = null;
			}
			return this;
		}


		/**
		 * Sets the existing refresh token for incremental
		 * authorisation of a public client. Corresponds to the
		 * optional {@code existing_grant} parameter.
		 *
		 * @param existingGrant Existing refresh token for incremental
		 *                      authorisation of a public client,
		 *                      {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder existingGrant(final RefreshToken existingGrant) {
			this.existingGrant = existingGrant;
			return this;
		}


		/**
		 * Sets the device secret for native SSO. Corresponds to the
		 * optional {@code device_secret} parameter.
		 *
		 * @param deviceSecret The device secret, {@code null} if not
		 *                     specified.
		 *
		 * @return This builder.
		 */
		public Builder deviceSecret(final DeviceSecret deviceSecret) {
			this.deviceSecret = deviceSecret;
			return this;
		}


		/**
		 * Sets a custom parameter.
		 *
		 * @param name   The parameter name. Must not be {@code null}.
		 * @param values The parameter values, {@code null} if not
		 *               specified.
		 *
		 * @return This builder.
		 */
		public Builder customParameter(final String name, final String ... values) {
			if (values == null || values.length == 0) {
				customParams.remove(name);
			} else {
				customParams.put(name, Arrays.asList(values));
			}
			return this;
		}


		/**
		 * Builds a new token request.
		 *
		 * @return The token request.
		 */
		public TokenRequest build() {

			try {
				if (clientAuth != null) {
					return new TokenRequest(
						endpoint,
						clientAuth,
						authzGrant,
						scope,
						authorizationDetails,
						resources,
						deviceSecret,
						customParams);
				}

				return new TokenRequest(
					endpoint,
					clientID,
					authzGrant,
					scope,
					authorizationDetails,
					resources,
					existingGrant,
					deviceSecret,
					customParams);
			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}


	/**
	 * Creates a new token request with client authentication.
	 *
	 * @param endpoint   The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   is not going to be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI endpoint,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		this(endpoint, clientAuth, authzGrant, scope, null, null);
	}


	/**
	 * Creates a new token request with client authentication and extension
	 * and custom parameters.
	 *
	 * @param endpoint     The URI of the token endpoint. May be
	 *                     {@code null} if the {@link #toHTTPRequest}
	 *                     method is not going to be used.
	 * @param clientAuth   The client authentication. Must not be
	 *                     {@code null}.
	 * @param authzGrant   The authorisation grant. Must not be
	 *                     {@code null}.
	 * @param scope        The requested scope, {@code null} if not
	 *                     specified.
	 * @param resources    The resource URI(s), {@code null} if not
	 *                     specified.
	 * @param customParams Custom parameters to be included in the request
	 *                     body, empty map or {@code null} if none.
	 */
	@Deprecated
	public TokenRequest(final URI endpoint,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<URI> resources,
			    final Map<String,List<String>> customParams) {

		this(endpoint, clientAuth, authzGrant, scope, null, resources, customParams);
	}


	/**
	 * Creates a new token request with client authentication and extension
	 * and custom parameters.
	 *
	 * @param endpoint             The URI of the token endpoint. May be
	 *                             {@code null} if the
	 *                             {@link #toHTTPRequest} method is not
	 *                             going be used.
	 * @param clientAuth           The client authentication. Must not be
	 *                             {@code null}.
	 * @param authzGrant           The authorisation grant. Must not be
	 *                             {@code null}.
	 * @param scope                The requested scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The Rich Authorisation Request (RAR)
	 *                             details, {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param customParams         Custom parameters to be included in the
	 *                             request body, empty map or {@code null}
	 *                             if none.
	 */
	@Deprecated
	public TokenRequest(final URI endpoint,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<AuthorizationDetail> authorizationDetails,
			    final List<URI> resources,
			    final Map<String,List<String>> customParams) {

		this(endpoint, clientAuth, authzGrant, scope, authorizationDetails, resources, null, customParams);
	}


	/**
	 * Creates a new token request with client authentication.
	 *
	 * @param endpoint   The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   is not going to be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	@Deprecated
	public TokenRequest(final URI endpoint,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant) {

		this(endpoint, clientAuth, authzGrant, null);
	}


	/**
	 * Creates a new token request with no (explicit) client
	 * authentication. The grant itself may be used to authenticate the
	 * client.
	 *
	 * @param endpoint   The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   is not going to be used.
	 * @param clientID   The client identifier, {@code null} if not
	 *                   specified.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI endpoint,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		this(endpoint, clientID, authzGrant, scope, null, null,null);
	}


	/**
	 * Creates a new token request, with no (explicit) client
	 * authentication and extension and custom parameters. The grant itself
	 * may be used to authenticate the client.
	 *
	 * @param endpoint      The URI of the token endpoint. May be
	 *                      {@code null} if the {@link #toHTTPRequest}
	 *                      method is not going to be used.
	 * @param clientID      The client identifier, {@code null} if not
	 *                      specified.
	 * @param authzGrant    The authorisation grant. Must not be
	 *                      {@code null}.
	 * @param scope         The requested scope, {@code null} if not
	 *                      specified.
	 * @param resources     The resource URI(s), {@code null} if not
	 *                      specified.
	 * @param existingGrant Existing refresh token for incremental
	 *                      authorisation of a public client, {@code null}
	 *                      if not specified.
	 * @param customParams  Custom parameters to be included in the request
	 *                      body, empty map or {@code null} if none.
	 */
	@Deprecated
	public TokenRequest(final URI endpoint,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<URI> resources,
			    final RefreshToken existingGrant,
			    final Map<String,List<String>> customParams) {

		this(endpoint, clientID, authzGrant, scope, null, resources, existingGrant, customParams);
	}


	/**
	 * Creates a new token request, with no (explicit) client
	 * authentication and extension and custom parameters. The grant itself
	 * may be used to authenticate the client.
	 *
	 * @param endpoint             The URI of the token endpoint. May be
	 *                             {@code null} if the
	 *                             {@link #toHTTPRequest}
	 *                             method is not going to be used.
	 * @param clientID             The client identifier, {@code null} if
	 *                             not specified.
	 * @param authzGrant           The authorisation grant. Must not be
	 *                             {@code null}.
	 * @param scope                The requested scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The Rich Authorisation Request (RAR)
	 *                             details, {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param existingGrant        Existing refresh token for incremental
	 *                             authorisation of a public client,
	 *                             {@code null} if not specified.
	 * @param customParams         Custom parameters to be included in the
	 *                             request body, empty map or {@code null}
	 *                             if none.
	 */
	@Deprecated
	public TokenRequest(final URI endpoint,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<AuthorizationDetail> authorizationDetails,
			    final List<URI> resources,
			    final RefreshToken existingGrant,
			    final Map<String,List<String>> customParams) {

		this(endpoint, clientID, authzGrant, scope, authorizationDetails, resources, existingGrant, null, customParams);
	}


	/**
	 * Creates a new token request, with no (explicit) client
	 * authentication. The grant itself may be used to authenticate the
	 * client.
	 *
	 * @param endpoint   The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   is not going to be used.
	 * @param clientID   The client identifier, {@code null} if not
	 *                   specified.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	@Deprecated
	public TokenRequest(final URI endpoint,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant) {

		this(endpoint, clientID, authzGrant, null);
	}


	/**
	 * Creates a new token request with no (explicit) client
	 * authentication, the client identifier is inferred from the
	 * authorisation grant.
	 *
	 * @param endpoint   The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   is not going to be used.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI endpoint,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		this(endpoint, (ClientID)null, authzGrant, scope);
	}


	/**
	 * Creates a new token request with no (explicit) client
	 * authentication, the client identifier is inferred from the
	 * authorisation grant.
	 *
	 * @param endpoint   The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   is not going to be used.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	@Deprecated
	public TokenRequest(final URI endpoint,
			    final AuthorizationGrant authzGrant) {

		this(endpoint, (ClientID)null, authzGrant, null);
	}


	/**
	 * Creates a new token request with client authentication and extension
	 * and custom parameters.
	 *
	 * @param endpoint             The URI of the token endpoint. May be
	 *                             {@code null} if the
	 *                             {@link #toHTTPRequest} method is not
	 *                             going be used.
	 * @param clientAuth           The client authentication. Must not be
	 *                             {@code null}.
	 * @param authzGrant           The authorisation grant. Must not be
	 *                             {@code null}.
	 * @param scope                The requested scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The Rich Authorisation Request (RAR)
	 *                             details, {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param deviceSecret         The device secret, {@code null} if not
	 *                             specified.
	 * @param customParams         Custom parameters to be included in the
	 *                             request body, empty map or {@code null}
	 *                             if none.
	 */
	public TokenRequest(final URI endpoint,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<AuthorizationDetail> authorizationDetails,
			    final List<URI> resources,
			    final DeviceSecret deviceSecret,
			    final Map<String,List<String>> customParams) {

		super(endpoint, Objects.requireNonNull(clientAuth));

		this.authzGrant = Objects.requireNonNull(authzGrant);

		this.scope = scope;

		if (resources != null) {
			for (URI resourceURI: resources) {
				if (! ResourceUtils.isLegalResourceURI(resourceURI))
					throw new IllegalArgumentException("Resource URI must be absolute and with no query or fragment: " + resourceURI);
			}
		}

		this.authorizationDetails = authorizationDetails;

		this.resources = resources;

		this.existingGrant = null; // only for public client

		this.deviceSecret = deviceSecret;

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = customParams;
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Creates a new token request, with no (explicit) client
	 * authentication and extension and custom parameters. The grant itself
	 * may be used to authenticate the client.
	 *
	 * @param endpoint             The URI of the token endpoint. May be
	 *                             {@code null} if the
	 *                             {@link #toHTTPRequest}
	 *                             method is not going to be used.
	 * @param clientID             The client identifier, {@code null} if
	 *                             not specified.
	 * @param authzGrant           The authorisation grant. Must not be
	 *                             {@code null}.
	 * @param scope                The requested scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The Rich Authorisation Request (RAR)
	 *                             details, {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param existingGrant        Existing refresh token for incremental
	 *                             authorisation of a public client,
	 *                             {@code null} if not specified.
	 * @param deviceSecret         The device secret, {@code null} if not
	 *                             specified.
	 * @param customParams         Custom parameters to be included in the
	 *                             request body, empty map or {@code null}
	 *                             if none.
	 */
	public TokenRequest(final URI endpoint,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<AuthorizationDetail> authorizationDetails,
			    final List<URI> resources,
			    final RefreshToken existingGrant,
			    final DeviceSecret deviceSecret,
			    final Map<String,List<String>> customParams) {

		super(endpoint, clientID);

		if (authzGrant.getType().requiresClientAuthentication()) {
			throw new IllegalArgumentException("The \"" + authzGrant.getType() + "\" grant type requires client authentication");
		}

		if (authzGrant.getType().requiresClientID() && clientID == null) {
			throw new IllegalArgumentException("The \"" + authzGrant.getType() + "\" grant type requires a \"client_id\" parameter");
		}

		this.authzGrant = authzGrant;

		this.scope = scope;

		if (resources != null) {
			for (URI resourceURI: resources) {
				if (! ResourceUtils.isLegalResourceURI(resourceURI))
					throw new IllegalArgumentException("Resource URI must be absolute and with no query or fragment: " + resourceURI);
			}
		}

		this.authorizationDetails = authorizationDetails;

		this.resources = resources;

		this.existingGrant = existingGrant;

		this.deviceSecret = deviceSecret;

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = customParams;
		} else {
			this.customParams = Collections.emptyMap();
		}
        }


	/**
	 * Returns the authorisation grant.
	 *
	 * @return The authorisation grant.
	 */
	public AuthorizationGrant getAuthorizationGrant() {

		return authzGrant;
	}


	/**
	 * Returns the requested scope. Corresponds to the {@code scope}
	 * parameter.
	 *
	 * @return The requested scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}


	/**
	 * Returns the Rich Authorisation Request (RAR) details. Corresponds to
	 * the {@code authorization_details} parameter.
	 *
	 * @return The authorisation details, {@code null} if not specified.
	 */
	public List<AuthorizationDetail> getAuthorizationDetails() {

		return authorizationDetails;
	}
	
	
	/**
	 * Returns the resource server URI. Corresponds to the {@code resource}
	 * parameter.
	 *
	 * @return The resource URI(s), {@code null} if not specified.
	 */
	public List<URI> getResources() {
		
		return resources;
	}
	
	
	/**
	 * Returns the existing refresh token for incremental authorisation of
	 * a public client. Corresponds to the {@code existing_grant}
	 * parameter.
	 *
	 * @return The existing grant, {@code null} if not specified.
	 */
	public RefreshToken getExistingGrant() {
		
		return existingGrant;
	}


	/**
	 * Returns the device secret for native SSO. Corresponds to the
	 * {@code device_secret} parameter.
	 *
	 * @return The device secret, {@code null} if not specified.
	 */
	public DeviceSecret getDeviceSecret() {

		return deviceSecret;
	}


	/**
	 * Returns the additional custom parameters included in the request
	 * body.
	 *
	 * @return The additional custom parameters as an unmodifiable map,
	 *         empty map if none.
	 */
	public Map<String,List<String>> getCustomParameters () {

		return Collections.unmodifiableMap(customParams);
	}


	/**
	 * Returns the specified custom parameter included in the request body.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 *
	 * @return The parameter value(s), {@code null} if not specified.
	 */
	public List<String> getCustomParameter(final String name) {

		return customParams.get(name);
	}


	@Override
	public HTTPRequest toHTTPRequest() {

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		if (getClientAuthentication() != null) {
			getClientAuthentication().applyTo(httpRequest);
		}

		Map<String, List<String>> params;
		try {
			params = new LinkedHashMap<>(httpRequest.getBodyAsFormParameters());
		} catch (ParseException e) {
			throw new SerializeException(e.getMessage(), e);
		}
		params.putAll(getAuthorizationGrant().toParameters());

		switch (getAuthorizationGrant().getType().getScopeRequirementInTokenRequest()) {
			case REQUIRED:
				if (CollectionUtils.isEmpty(getScope())) {
					throw new SerializeException("Scope is required for the " + getAuthorizationGrant().getType() + " grant");
				}
				params.put("scope", Collections.singletonList(getScope().toString()));
				break;
			case OPTIONAL:
				if (CollectionUtils.isNotEmpty(getScope())) {
					params.put("scope", Collections.singletonList(getScope().toString()));
				}
				break;
			case NOT_ALLOWED:
			default:
				break;
		}

		if (getClientID() != null) {
			params.put("client_id", Collections.singletonList(getClientID().getValue()));
		}

		if (getAuthorizationDetails() != null) {
			params.put("authorization_details", Collections.singletonList(AuthorizationDetail.toJSONString(getAuthorizationDetails())));
		}
		
		if (getResources() != null) {
			List<String> values = new LinkedList<>();
			for (URI uri: getResources()) {
				if (uri == null)
					continue;
				values.add(uri.toString());
			}
			params.put("resource", values);
		}
		
		if (getExistingGrant() != null) {
			params.put("existing_grant", Collections.singletonList(getExistingGrant().getValue()));
		}

		if (getDeviceSecret() != null) {
			params.put("device_secret", Collections.singletonList(getDeviceSecret().getValue()));
		}

		if (! getCustomParameters().isEmpty()) {
			params.putAll(getCustomParameters());
		}

		httpRequest.setBody(URLUtils.serializeParameters(params));

		return httpRequest;
	}


	/**
	 * Parses a token request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        token request.
	 */
	public static TokenRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		// Only HTTP POST accepted
		URI endpoint = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);

		// Parse client authentication, if any
		ClientAuthentication clientAuth;
		try {
			clientAuth = ClientAuthentication.parse(httpRequest);
		} catch (ParseException e) {
			throw new ParseException(e.getMessage(), OAuth2Error.INVALID_REQUEST.appendDescription(": " + e.getMessage()));
		}

		// No fragment! May use query component!
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		
		Set<String> repeatParams = MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, ALLOWED_REPEATED_PARAMS);
		if (! repeatParams.isEmpty()) {
			String msg = "Parameter(s) present more than once: " + repeatParams;
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.setDescription(msg));
		}
		
		// Multiple conflicting client auth methods (issue #203)?
		if (clientAuth instanceof ClientSecretBasic) {
			if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion")) || StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {
				String msg = "Multiple conflicting client authentication methods found: Basic and JWT assertion";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
		}

		// Parse grant
		AuthorizationGrant grant = AuthorizationGrant.parse(params);

		if (clientAuth == null && grant.getType().requiresClientAuthentication()) {
			String msg = "Missing client authentication";
			throw new ParseException(msg, OAuth2Error.INVALID_CLIENT.appendDescription(": " + msg));
		}

		// Parse client id
		ClientID clientID = null;

		if (clientAuth == null) {

			// Parse optional client ID
			String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");

			if (StringUtils.isNotBlank(clientIDString))
				clientID = new ClientID(clientIDString);

			if (clientID == null && grant.getType().requiresClientID()) {
				String msg = "Missing required client_id parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
		}

		// Parse optional scope
		String scopeValue = MultivaluedMapUtils.getFirstValue(params, "scope");

		ParameterRequirement scopeRequirement = grant.getType().getScopeRequirementInTokenRequest();

		Scope scope = null;

		if (scopeValue != null && (ParameterRequirement.REQUIRED.equals(scopeRequirement) || ParameterRequirement.OPTIONAL.equals(scopeRequirement))) {
			scope = Scope.parse(scopeValue);
		}

		// Parse optional RAR
		String json = MultivaluedMapUtils.getFirstValue(params, "authorization_details");

		List<AuthorizationDetail> authorizationDetails = null;

		if (json != null) {
			authorizationDetails = AuthorizationDetail.parseList(json);
		}
		
		// Parse optional resource URIs
		List<URI> resources = null;
		
		List<String> vList = params.get("resource");
		
		if (vList != null) {
			
			resources = new LinkedList<>();
			
			for (String uriValue: vList) {
				
				if (uriValue == null)
					continue;
				
				String errMsg = "Illegal resource parameter: Must be an absolute URI without a fragment: " + uriValue;
				
				URI resourceURI;
				try {
					resourceURI = new URI(uriValue);
				} catch (URISyntaxException e) {
					throw new ParseException(errMsg, OAuth2Error.INVALID_TARGET.setDescription(errMsg));
				}
				
				if (! ResourceUtils.isLegalResourceURI(resourceURI)) {
					throw new ParseException(errMsg, OAuth2Error.INVALID_TARGET.setDescription(errMsg));
				}
				
				resources.add(resourceURI);
			}
		}
		
		String rt = MultivaluedMapUtils.getFirstValue(params, "existing_grant");
		RefreshToken existingGrant = StringUtils.isNotBlank(rt) ? new RefreshToken(rt) : null;

		DeviceSecret deviceSecret = DeviceSecret.parse(MultivaluedMapUtils.getFirstValue(params, "device_secret"));

		// Parse custom parameters
		Map<String,List<String>> customParams = new HashMap<>();

		for (Map.Entry<String,List<String>> p: params.entrySet()) {

			if (REGISTERED_PARAMETER_NAMES.contains(p.getKey().toLowerCase())) {
				continue; // skip
			}

			if (! grant.getType().getRequestParameterNames().contains(p.getKey())) {
				// We have a custom (non-registered) parameter
				customParams.put(p.getKey(), p.getValue());
			}
		}

		if (clientAuth != null) {
			return new TokenRequest(endpoint, clientAuth, grant, scope, authorizationDetails, resources, deviceSecret, customParams);
		} else {
			// public client
			return new TokenRequest(endpoint, clientID, grant, scope, authorizationDetails, resources, existingGrant, deviceSecret, customParams);
		}
	}
}
