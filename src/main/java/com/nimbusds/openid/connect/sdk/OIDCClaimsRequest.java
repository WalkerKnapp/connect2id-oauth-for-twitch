/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk;


import java.util.*;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.request.VerifiedClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;


/**
 * Specifies individual OpenID claims to return from the UserInfo endpoint and
 * / or in the ID Token. Replaces the deprecated {@link ClaimsRequest} class.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "userinfo":
 *    {
 *     "given_name": {"essential": true},
 *     "nickname": null,
 *     "email": {"essential": true},
 *     "email_verified": {"essential": true},
 *     "picture": null,
 *     "http://example.info/claims/groups": null
 *    },
 *   "id_token":
 *    {
 *     "auth_time": {"essential": true},
 *     "acr": {"values": ["urn:mace:incommon:iap:silver"] }
 *    }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public class OIDCClaimsRequest implements JSONAware {
	
	
	/**
	 * Claims requested in the ID token, {@code null} if not specified.
	 */
	private final ClaimsSetRequest idToken;
	
	
	/**
	 * Claims requested at the UserInfo endpoint, {@code null} if not
	 * specified.
	 */
	private final ClaimsSetRequest userInfo;
	
	
	/**
	 * Verified claims requested in the ID token, empty list if none.
	 */
	private final List<VerifiedClaimsSetRequest> idTokenVerified;
	
	
	/**
	 * Verified claims requested at the UserInfo endpoint, empty list if
	 * none.
	 */
	private final List<VerifiedClaimsSetRequest> userInfoVerified;
	
	
	/**
	 * Creates a new empty OpenID claims request.
	 */
	public OIDCClaimsRequest() {
		this(null, null, Collections.<VerifiedClaimsSetRequest>emptyList(), Collections.<VerifiedClaimsSetRequest>emptyList());
	}
	
	
	private OIDCClaimsRequest(final ClaimsSetRequest idToken,
				  final ClaimsSetRequest userInfo,
				  final List<VerifiedClaimsSetRequest> idTokenVerified,
				  final List<VerifiedClaimsSetRequest> userInfoVerified) {
		
		this.idToken = idToken;
		this.userInfo = userInfo;
		this.idTokenVerified = Collections.unmodifiableList(idTokenVerified);
		this.userInfoVerified = Collections.unmodifiableList(userInfoVerified);
	}
	
	
	/**
	 * Adds the entries from the specified other OpenID claims request.
	 *
	 * @param other The other OpenID claims request. If {@code null} no
	 *              claims request entries will be added to this claims
	 *              request.
	 *
	 * @return The updated OpenID claims request.
	 */
	public OIDCClaimsRequest add(final OIDCClaimsRequest other) {
		
		if (other == null)
			return this;
		
		// Regular id_token
		Collection<ClaimsSetRequest.Entry> idTokenEntries = new LinkedList<>();
		if (idToken != null) {
			idTokenEntries.addAll(idToken.getEntries());
		}
		if (other.getIDTokenClaimsRequest() != null) {
			idTokenEntries.addAll(other.getIDTokenClaimsRequest().getEntries());
		}
		
		// Regular userinfo
		Collection<ClaimsSetRequest.Entry> userInfoEntries = new LinkedList<>();
		if (userInfo != null) {
			userInfoEntries.addAll(userInfo.getEntries());
		}
		if (other.getUserInfoClaimsRequest() != null) {
			userInfoEntries.addAll(other.getUserInfoClaimsRequest().getEntries());
		}
		
		// Verified id_token
		List<VerifiedClaimsSetRequest> idTokenVerifiedList = new LinkedList<>(idTokenVerified);
		idTokenVerifiedList.addAll(other.getIDTokenVerifiedClaimsRequests());
		
		// Verified userinfo
		List<VerifiedClaimsSetRequest> userInfoVerifiedList = new LinkedList<>(userInfoVerified);
		userInfoVerifiedList.addAll(other.getUserInfoVerifiedClaimsRequests());
		
		return new OIDCClaimsRequest(
			idTokenEntries.isEmpty() ? null : new ClaimsSetRequest(idTokenEntries),
			userInfoEntries.isEmpty() ? null : new ClaimsSetRequest(userInfoEntries),
			idTokenVerifiedList,
			userInfoVerifiedList
		);
	}
	
	
	/**
	 * Returns the claims requested in the ID token.
	 *
	 * @return The ID token claims request, {@code null} if not specified.
	 */
	public ClaimsSetRequest getIDTokenClaimsRequest() {
		return idToken;
	}
	
	
	/**
	 * Sets the claims requested in the ID token.
	 *
	 * @param idToken The ID token claims request, {@code null} if not
	 *                specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	public OIDCClaimsRequest withIDTokenClaimsRequest(final ClaimsSetRequest idToken) {
		return new OIDCClaimsRequest(
			idToken,
			getUserInfoClaimsRequest(),
			getIDTokenVerifiedClaimsRequests(),
			getUserInfoVerifiedClaimsRequests());
	}
	
	
	/**
	 * Returns the claims requested at the UserInfo endpoint.
	 *
	 * @return The UserInfo claims request, {@code null} if not specified.
	 */
	public ClaimsSetRequest getUserInfoClaimsRequest() {
		return userInfo;
	}
	
	
	/**
	 * Sets the claims requested at the UserInfo endpoint.
	 *
	 * @param userInfo The UserInfo claims request, {@code null} if not
	 *                 specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	public OIDCClaimsRequest withUserInfoClaimsRequest(final ClaimsSetRequest userInfo) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			userInfo,
			getIDTokenVerifiedClaimsRequests(),
			getUserInfoVerifiedClaimsRequests());
	}
	
	
	private static List<VerifiedClaimsSetRequest> toCurrent(final List<com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest> list) {
		
		if (CollectionUtils.isEmpty(list)) {
			return Collections.emptyList();
		}
		
		List<VerifiedClaimsSetRequest> out = new LinkedList<>();
		for (com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest r: list) {
			if (r == null) {
				continue;
			}
			try {
				out.add(VerifiedClaimsSetRequest.parse(r.toJSONObject()));
			} catch (ParseException e) {
				// should never happen
			}	
		}
		return out;
	}
	
	
	private static List<com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest> toDeprecated(final List<VerifiedClaimsSetRequest> list) {
		
		if (CollectionUtils.isEmpty(list)) {
			return Collections.emptyList();
		}
		
		List<com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest> out = new LinkedList<>();
		for (VerifiedClaimsSetRequest r: list) {
			if (r == null) {
				continue;
			}
			try {
				out.add(com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest.parse(r.toJSONObject()));
			} catch (ParseException e) {
				// should never happen
			}
		}
		return out;
	}
	
	
	/**
	 * Returns the list of verified claims sets requested in the ID token.
	 *
	 * @return The ID token verified claims request list, empty list if not
	 *         specified.
	 */
	public List<VerifiedClaimsSetRequest> getIDTokenVerifiedClaimsRequests() {
		return idTokenVerified;
	}
	
	
	/**
	 * Returns the list of verified claims sets requested in the ID token.
	 *
	 * @return The ID token verified claims request list, empty list if not
	 *         specified.
	 */
	@Deprecated
	public List<com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest> getIDTokenVerifiedClaimsRequestList() {
		return toDeprecated(idTokenVerified);
	}
	
	
	/**
	 * Sets the list of verified claims sets requested in the ID token.
	 *
	 * @param idTokenVerifiedList One or more ID token verified claims
	 *                            requests, empty list if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	public OIDCClaimsRequest withIDTokenVerifiedClaimsRequests(final List<VerifiedClaimsSetRequest> idTokenVerifiedList) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			idTokenVerifiedList != null ? idTokenVerifiedList : Collections.<VerifiedClaimsSetRequest>emptyList(),
			getUserInfoVerifiedClaimsRequests());
	}
	
	
	/**
	 * Sets the list of verified claims sets requested in the ID token.
	 *
	 * @param idTokenVerifiedList One or more ID token verified claims
	 *                            requests, empty list if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	@Deprecated
	public OIDCClaimsRequest withIDTokenVerifiedClaimsRequestList(final List<com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest> idTokenVerifiedList) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			idTokenVerifiedList != null ? toCurrent(idTokenVerifiedList) : Collections.<VerifiedClaimsSetRequest>emptyList(),
			getUserInfoVerifiedClaimsRequests());
	}
	
	
	/**
	 * Sets a single verified claims set requested in the ID token.
	 *
	 * @param idTokenVerified The ID token verified claims request,
	 *                        {@code null} if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	public OIDCClaimsRequest withIDTokenVerifiedClaimsRequest(final VerifiedClaimsSetRequest idTokenVerified) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			idTokenVerified != null ? Collections.singletonList(idTokenVerified) : Collections.<VerifiedClaimsSetRequest>emptyList(),
			getUserInfoVerifiedClaimsRequests());
	}
	
	
	/**
	 * Sets a single verified claims set requested in the ID token.
	 *
	 * @param idTokenVerified The ID token verified claims request,
	 *                        {@code null} if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	@Deprecated
	public OIDCClaimsRequest withIDTokenVerifiedClaimsRequest(final com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest idTokenVerified) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			idTokenVerified != null ? toCurrent(Collections.singletonList(idTokenVerified)) : Collections.<VerifiedClaimsSetRequest>emptyList(),
			getUserInfoVerifiedClaimsRequests());
	}
	
	
	/**
	 * Returns the list of verified claims sets requested at the UserInfo
	 * endpoint.
	 *
	 * @return The UserInfo verified claims request list, empty list if not
	 *         specified.
	 */
	public List<VerifiedClaimsSetRequest> getUserInfoVerifiedClaimsRequests() {
		return userInfoVerified;
	}
	
	
	/**
	 * Returns the list of verified claims sets requested at the UserInfo
	 * endpoint.
	 *
	 * @return The UserInfo verified claims request list, empty list if not
	 *         specified.
	 */
	@Deprecated
	public List<com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest> getUserInfoVerifiedClaimsRequestList() {
		return toDeprecated(userInfoVerified);
	}
	
	
	/**
	 * Sets the list of verified claims sets requested at the UserInfo
	 * endpoint.
	 *
	 * @param userInfoVerifiedList One or more UserInfo verified claims
	 *                             requests, empty list if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	public OIDCClaimsRequest withUserInfoVerifiedClaimsRequests(final List<VerifiedClaimsSetRequest> userInfoVerifiedList) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			getIDTokenVerifiedClaimsRequests(),
			userInfoVerifiedList != null ? userInfoVerifiedList : Collections.<VerifiedClaimsSetRequest>emptyList());
	}
	
	
	/**
	 * Sets the list of verified claims sets requested at the UserInfo
	 * endpoint.
	 *
	 * @param userInfoVerifiedList One or more UserInfo verified claims
	 *                             requests, empty list if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	@Deprecated
	public OIDCClaimsRequest withUserInfoVerifiedClaimsRequestList(final List<com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest> userInfoVerifiedList) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			getIDTokenVerifiedClaimsRequests(),
			userInfoVerifiedList != null ? toCurrent(userInfoVerifiedList) : Collections.<VerifiedClaimsSetRequest>emptyList());
	}
	
	
	/**
	 * Sets a single verified claims set requested at the UserInfo
	 * endpoint.
	 *
	 * @param userInfoVerified The UserInfo verified claims request,
	 *                         {@code null} if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	public OIDCClaimsRequest withUserInfoVerifiedClaimsRequest(final VerifiedClaimsSetRequest userInfoVerified) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			getIDTokenVerifiedClaimsRequests(),
			userInfoVerified != null ? Collections.singletonList(userInfoVerified) : Collections.<VerifiedClaimsSetRequest>emptyList());
	}
	
	
	/**
	 * Sets a single verified claims set requested at the UserInfo
	 * endpoint.
	 *
	 * @param userInfoVerified The UserInfo verified claims request,
	 *                         {@code null} if not specified.
	 *
	 * @return The updated OpenID claims request.
	 */
	@Deprecated
	public OIDCClaimsRequest withUserInfoVerifiedClaimsRequest(final com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest userInfoVerified) {
		return new OIDCClaimsRequest(
			getIDTokenClaimsRequest(),
			getUserInfoClaimsRequest(),
			getIDTokenVerifiedClaimsRequests(),
			userInfoVerified != null ? toCurrent(Collections.singletonList(userInfoVerified)) : Collections.<VerifiedClaimsSetRequest>emptyList());
	}
	
	
	private static JSONObject addVerified(final List<VerifiedClaimsSetRequest> verified,
					      final JSONObject containingJSONObject) {
		
		if (verified != null) {
			
			if (verified.size() == 1 && verified.get(0) != null) {
				JSONObject out = new JSONObject();
				if (containingJSONObject != null) {
					out.putAll(containingJSONObject);
				}
				out.put("verified_claims", verified.get(0).toJSONObject());
				return out;
			} else if (verified.size() > 1) {
				JSONObject out = new JSONObject();
				if (containingJSONObject != null) {
					out.putAll(containingJSONObject);
				}
				JSONArray jsonArray = new JSONArray();
				for (VerifiedClaimsSetRequest verifiedClaims: verified) {
					jsonArray.add(verifiedClaims.toJSONObject());
				}
				out.put("verified_claims", jsonArray);
				return out;
			}
		}
		return containingJSONObject;
	}
	
	
	/**
	 * Returns the JSON object representation of this OpenID claims
	 * request.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "userinfo":
	 *    {
	 *     "given_name": {"essential": true},
	 *     "nickname": null,
	 *     "email": {"essential": true},
	 *     "email_verified": {"essential": true},
	 *     "picture": null,
	 *     "http://example.info/claims/groups": null
	 *    },
	 *   "id_token":
	 *    {
	 *     "auth_time": {"essential": true},
	 *     "acr": {"values": ["urn:mace:incommon:iap:silver"] }
	 *    }
	 * }
	 * </pre>
	 *
	 * @return The JSON object, empty if no ID token and UserInfo claims
	 *         are specified.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		
		// id_token
		JSONObject idTokenJSONObject = null;
		if (idToken != null) {
			 idTokenJSONObject = idToken.toJSONObject();
		}
		idTokenJSONObject = addVerified(idTokenVerified, idTokenJSONObject);
		if (idTokenJSONObject != null && ! idTokenJSONObject.isEmpty()) {
			o.put("id_token", idTokenJSONObject);
		}
		
		// userinfo
		JSONObject userInfoJSONObject = null;
		if (userInfo != null) {
			 userInfoJSONObject = userInfo.toJSONObject();
		}
		userInfoJSONObject = addVerified(userInfoVerified, userInfoJSONObject);
		if (userInfoJSONObject != null && ! userInfoJSONObject.isEmpty()) {
			o.put("userinfo", userInfoJSONObject);
		}
		
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	@Override
	public String toString() {
		
		return toJSONString();
	}
	
	
	/**
	 * Resolves the OpenID claims request for the specified response type
	 * and scope. The scope values that are {@link OIDCScopeValue standard
	 * OpenID scope values} are resolved to their respective individual
	 * claims requests, any other scope values are ignored.
	 *
	 * @param responseType The response type. Must not be {@code null}.
	 * @param scope        The scope, {@code null} if not specified (for a
	 *                     plain OAuth 2.0 authorisation request with no
	 *                     scope explicitly specified).
	 *
	 * @return The OpenID claims request.
	 */
	public static OIDCClaimsRequest resolve(final ResponseType responseType, final Scope scope) {
		
		return resolve(responseType, scope, Collections.<Scope.Value, Set<String>>emptyMap());
	}
	
	
	/**
	 * Resolves the OpenID claims request for the specified response type
	 * and scope. The scope values that are {@link OIDCScopeValue standard
	 * OpenID scope values} are resolved to their respective individual
	 * claims requests, any other scope values are checked in the specified
	 * custom claims map and resolved accordingly.
	 *
	 * @param responseType The response type. Must not be {@code null}.
	 * @param scope        The scope, {@code null} if not specified (for a
	 *                     plain OAuth 2.0 authorisation request with no
	 *                     scope explicitly specified).
	 * @param customClaims Custom scope value to set of claim names map,
	 *                     {@code null} if not specified.
	 *
	 * @return The OpenID claims request.
	 */
	public static OIDCClaimsRequest resolve(final ResponseType responseType,
					        final Scope scope,
					        final Map<Scope.Value, Set<String>> customClaims) {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest();
		
		if (scope == null) {
			// Plain OAuth 2.0 mode
			return claimsRequest;
		}
		
		List<ClaimsSetRequest.Entry> entries = new LinkedList<>();
		for (Scope.Value value : scope) {
			
			if (value.equals(OIDCScopeValue.PROFILE)) {
				
				entries.addAll(OIDCScopeValue.PROFILE.toClaimsSetRequestEntries());
				
			} else if (value.equals(OIDCScopeValue.EMAIL)) {
				
				entries.addAll(OIDCScopeValue.EMAIL.toClaimsSetRequestEntries());
				
			} else if (value.equals(OIDCScopeValue.PHONE)) {
				
				entries.addAll(OIDCScopeValue.PHONE.toClaimsSetRequestEntries());
				
			} else if (value.equals(OIDCScopeValue.ADDRESS)) {
				
				entries.addAll(OIDCScopeValue.ADDRESS.toClaimsSetRequestEntries());
				
			} else if (customClaims != null && customClaims.containsKey(value)) {
				
				// Process custom scope value -> claim names expansion, e.g.
				// "corp_profile" -> ["employeeNumber", "dept", "ext"]
				Set<String> claimNames = customClaims.get(value);
				
				if (claimNames == null || claimNames.isEmpty()) {
					continue; // skip
				}
				
				for (String claimName : claimNames) {
					entries.add(new ClaimsSetRequest.Entry(claimName).withClaimRequirement(ClaimRequirement.VOLUNTARY));
				}
				
			}
		}
		
		if (entries.isEmpty()) {
			return claimsRequest;
		}
			
		ClaimsSetRequest claimsSetRequest = new ClaimsSetRequest(entries);
		
		// Determine the claims target (ID token or UserInfo)
		final boolean switchToIDToken =
			responseType.contains(OIDCResponseTypeValue.ID_TOKEN) &&
				!responseType.contains(ResponseType.Value.CODE) &&
				!responseType.contains(ResponseType.Value.TOKEN);
			
		if (switchToIDToken) {
			return claimsRequest.withIDTokenClaimsRequest(claimsSetRequest);
		} else {
			return claimsRequest.withUserInfoClaimsRequest(claimsSetRequest);
		}
	}
	
	
	/**
	 * Resolves the merged OpenID claims request from the specified OpenID
	 * authentication request parameters. The scope values that are {@link
	 * OIDCScopeValue standard OpenID scope values} are resolved to their
	 * respective individual claims requests, any other scope values are
	 * ignored.
	 *
	 * @param responseType  The response type. Must not be {@code null}.
	 * @param scope         The scope, {@code null} if not specified (for a
	 *                      plain OAuth 2.0 authorisation request with no
	 *                      scope explicitly specified).
	 * @param claimsRequest The OpenID claims request, corresponding to the
	 *                      optional {@code claims} OpenID authentication
	 *                      request parameter, {@code null} if not
	 *                      specified.
	 *
	 * @return The merged OpenID claims request.
	 */
	public static OIDCClaimsRequest resolve(final ResponseType responseType,
						final Scope scope,
						final OIDCClaimsRequest claimsRequest) {
		
		return resolve(responseType, scope, claimsRequest, Collections.<Scope.Value, Set<String>>emptyMap());
	}
	
	
	/**
	 * Resolves the merged OpenID claims request from the specified OpenID
	 * authentication request parameters. The scope values that are {@link
	 * OIDCScopeValue standard OpenID scope values} are resolved to their
	 * respective individual claims requests, any other scope values are
	 * checked in the specified custom claims map and resolved accordingly.
	 *
	 * @param responseType  The response type. Must not be {@code null}.
	 * @param scope         The scope, {@code null} if not specified (for a
	 *                      plain OAuth 2.0 authorisation request with no
	 *                      scope explicitly specified).
	 * @param claimsRequest The OpenID claims request, corresponding to the
	 *                      optional {@code claims} OpenID authentication
	 *                      request parameter, {@code null} if not
	 *                      specified.
	 * @param customClaims  Custom scope value to set of claim names map,
	 *                      {@code null} if not specified.
	 *
	 * @return The merged OpenID claims request.
	 */
	public static OIDCClaimsRequest resolve(final ResponseType responseType,
						final Scope scope,
						final OIDCClaimsRequest claimsRequest,
						final Map<Scope.Value, Set<String>> customClaims) {
		
		return resolve(responseType, scope, customClaims).add(claimsRequest);
	}
	
	
	/**
	 * Resolves the merged OpenID claims request for the specified OpenID
	 * authentication request. The scope values that are {@link
	 * OIDCScopeValue standard OpenID scope values} are resolved to their
	 * respective individual claims requests, any other scope values are
	 * ignored.
	 *
	 * @param authRequest The OpenID authentication request. Must not be
	 *                    {@code null}.
	 *
	 * @return The merged OpenID claims request.
	 */
	public static OIDCClaimsRequest resolve(final AuthenticationRequest authRequest) {
		
		return resolve(authRequest.getResponseType(), authRequest.getScope(), authRequest.getOIDCClaims());
	}
	
	
	private static VerifiedClaimsSetRequest parseVerifiedClaimsSetRequest(final JSONObject jsonObject,
									      final int position)
		throws ParseException {
		
		try {
			return VerifiedClaimsSetRequest.parse(jsonObject);
		} catch (ParseException e) {
			throw new ParseException("Invalid verified claims request" +
				(position > -1 ? " at position " + position : "") +
				": " + e.getMessage(),
				e);
		}
	}
	
	
	private static List<VerifiedClaimsSetRequest> parseVerified(final JSONObject containingJSONObject)
		throws ParseException {
		
		if (! containingJSONObject.containsKey("verified_claims")) {
			// No verified claims
			return Collections.emptyList();
		}
		
		if (containingJSONObject.get("verified_claims") instanceof JSONObject) {
			// Single verified claims element
			JSONObject vo = JSONObjectUtils.getJSONObject(containingJSONObject, "verified_claims");
			return Collections.singletonList(parseVerifiedClaimsSetRequest(vo, -1));
			
		} else {
			// Array of one or more verified claims elements
			JSONArray va = JSONObjectUtils.getJSONArray(containingJSONObject, "verified_claims");
			List<VerifiedClaimsSetRequest> out = new LinkedList<>();
			int pos = 0;
			for (JSONObject vo: JSONArrayUtils.toJSONObjectList(va)) {
				out.add(parseVerifiedClaimsSetRequest(vo, pos++));
			}
			return out;
		}
	}
	
	
	/**
	 * Parses an OpenID claims request from the specified JSON object
	 * representation.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "userinfo":
	 *    {
	 *     "given_name": {"essential": true},
	 *     "nickname": null,
	 *     "email": {"essential": true},
	 *     "email_verified": {"essential": true},
	 *     "picture": null,
	 *     "http://example.info/claims/groups": null
	 *    },
	 *   "id_token":
	 *    {
	 *     "auth_time": {"essential": true},
	 *     "acr": {"values": ["urn:mace:incommon:iap:silver"] }
	 *    }
	 * }
	 * </pre>
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The OpenID claims request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static OIDCClaimsRequest parse(final JSONObject jsonObject)
		throws ParseException {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest();
		
		JSONObject idTokenObject = JSONObjectUtils.getJSONObject(jsonObject, "id_token", null);
		
		if (idTokenObject != null) {
			ClaimsSetRequest csr = ClaimsSetRequest.parse(idTokenObject);
			if (! csr.getEntries().isEmpty()) {
				claimsRequest = claimsRequest.withIDTokenClaimsRequest(csr);
			}
			claimsRequest = claimsRequest.withIDTokenVerifiedClaimsRequests(parseVerified(idTokenObject));
		}
		
		JSONObject userInfoObject = JSONObjectUtils.getJSONObject(jsonObject, "userinfo", null);
		
		if (userInfoObject != null) {
			ClaimsSetRequest csr = ClaimsSetRequest.parse(userInfoObject);
			if (! csr.getEntries().isEmpty()) {
				claimsRequest = claimsRequest.withUserInfoClaimsRequest(ClaimsSetRequest.parse(userInfoObject));
			}
			claimsRequest = claimsRequest.withUserInfoVerifiedClaimsRequests(parseVerified(userInfoObject));
		}
		
		return claimsRequest;
	}
	
	
	/**
	 * Parses an OpenID claims request from the specified JSON object
	 * string representation.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "userinfo":
	 *    {
	 *     "given_name": {"essential": true},
	 *     "nickname": null,
	 *     "email": {"essential": true},
	 *     "email_verified": {"essential": true},
	 *     "picture": null,
	 *     "http://example.info/claims/groups": null
	 *    },
	 *   "id_token":
	 *    {
	 *     "auth_time": {"essential": true},
	 *     "acr": {"values": ["urn:mace:incommon:iap:silver"] }
	 *    }
	 * }
	 * </pre>
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The OpenID claims request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static OIDCClaimsRequest parse(final String json)
		throws ParseException {

		JSONObject jsonObject;
		try {
			jsonObject = JSONObjectUtils.parse(json);
		} catch (ParseException e) {
			throw new ParseException("Invalid JSON");
		}
		return parse(jsonObject);
	}
}
