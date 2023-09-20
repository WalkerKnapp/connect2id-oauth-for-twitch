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

package com.nimbusds.oauth2.sdk.auth;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;

import java.util.*;


/**
 * Client secret post authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_POST}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 * </ul>
 */
@Immutable
public final class ClientSecretPost extends PlainClientSecret {


	/**
	 * Creates a new client secret post authentication.
	 *
	 * @param clientID The client identifier. Must not be {@code null}.
	 * @param secret   The client secret. Must not be {@code null}.
	 */
	public ClientSecretPost(final ClientID clientID, final Secret secret) {
	
		super(ClientAuthenticationMethod.CLIENT_SECRET_POST, clientID, secret);
	}
	
	
	@Override
	public Set<String> getFormParameterNames() {
		
		return Collections.unmodifiableSet(new HashSet<String>(Arrays.asList("client_id", "client_secret")));
	}
	
	
	/**
	 * Returns the parameter representation of this client secret post
	 * authentication. Note that the parameters are not 
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * <p>Parameters map:
	 *
	 * <pre>
	 * "client_id" = [client-identifier]
	 * "client_secret" = [client-secret]
	 * </pre>
	 *
	 * @return The parameters map, with keys "client_id" and 
	 *         "client_secret".
	 */
	public Map<String,List<String>> toParameters() {
	
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList(getClientID().getValue()));
		params.put("client_secret", Collections.singletonList(getClientSecret().getValue()));
		return params;
	}
	
	
	@Override
	public void applyTo(final HTTPRequest httpRequest) {
	
		if (httpRequest.getMethod() != HTTPRequest.Method.POST)
			throw new SerializeException("The HTTP request method must be POST");
		
		ContentType ct = httpRequest.getEntityContentType();
		
		if (ct == null)
			throw new SerializeException("Missing HTTP Content-Type header");
		
		if (! ct.matches(ContentType.APPLICATION_URLENCODED))
			throw new SerializeException("The HTTP Content-Type header must be " + ContentType.APPLICATION_URLENCODED);

		Map<String, List<String>> params = new LinkedHashMap<>();
		try {
			params.putAll(httpRequest.getBodyAsFormParameters());
		} catch (ParseException e) {
			throw new SerializeException(e.getMessage(), e);
		}
		params.putAll(toParameters());
		
		String queryString = URLUtils.serializeParameters(params);
		
		httpRequest.setBody(queryString);
	}
	
	
	/**
	 * Parses a client secret post authentication from the specified 
	 * parameters map. Note that the parameters must not be
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @param params The parameters map to parse. The client secret post
	 *               parameters must be keyed under "client_id" and 
	 *               "client_secret". The map must not be {@code null}.
	 *
	 * @return The client secret post authentication.
	 *
	 * @throws ParseException If the parameters map couldn't be parsed to a 
	 *                        client secret post authentication.
	 */
	public static ClientSecretPost parse(final Map<String,List<String>> params)
		throws ParseException {
	
		String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");
		
		if (clientIDString == null)
			throw new ParseException("Malformed client secret post authentication: Missing client_id parameter");
		
		String secretValue = MultivaluedMapUtils.getFirstValue(params, "client_secret");
		
		if (secretValue == null)
			throw new ParseException("Malformed client secret post authentication: Missing client_secret parameter");
		
		return new ClientSecretPost(new ClientID(clientIDString), new Secret(secretValue));
	}
	
	
	/**
	 * Parses a client secret post authentication from the specified 
	 * {@code application/x-www-form-urlencoded} encoded parameters string.
	 *
	 * @param paramsString The parameters string to parse. The client secret
	 *                     post parameters must be keyed under "client_id" 
	 *                     and "client_secret". The string must not be 
	 *                     {@code null}.
	 *
	 * @return The client secret post authentication.
	 *
	 * @throws ParseException If the parameters string couldn't be parsed to
	 *                        a client secret post authentication.
	 */
	public static ClientSecretPost parse(final String paramsString)
		throws ParseException {
		
		Map<String,List<String>> params = URLUtils.parseParameters(paramsString);
		
		return parse(params);
	}
	
	
	/**
	 * Parses a client secret post authentication from the specified HTTP
	 * POST request.
	 *
	 * @param httpRequest The HTTP POST request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    {@code application/x-www-form-urlencoded} encoded 
	 *                    parameters string in the entity body. The client 
	 *                    secret post parameters must be keyed under 
	 *                    "client_id" and "client_secret".
	 *
	 * @return The client secret post authentication.
	 *
	 * @throws ParseException If the HTTP request header couldn't be parsed
	 *                        to a valid client secret post authentication.
	 */
	public static ClientSecretPost parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		return parse(httpRequest.getBodyAsFormParameters());
	}
}
