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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;


/**
 * External attachment. Provides a {@link #retrieveContent method} to retrieve
 * the remote content and verify its digest.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public class ExternalAttachment extends Attachment {
	
	
	/**
	 * The attachment URL.
	 */
	private final URI url;
	
	
	/**
	 * Optional access token of type Bearer for retrieving the attachment.
	 */
	private final BearerAccessToken accessToken;
	
	
	/**
	 * Number of seconds until the attachment becomes unavailable and / or
	 * the access token becomes invalid. Zero or negative is not specified.
	 */
	private final long expiresIn;
	
	
	/**
	 * The cryptographic digest.
	 */
	private final Digest digest;
	
	
	/**
	 * Creates a new external attachment.
	 *
	 * @param url         The attachment URL. Must not be {@code null}.
	 * @param accessToken Optional access token of type Bearer for
	 *                    retrieving the attachment, {@code null} if none.
	 * @param expiresIn   Number of seconds until the attachment becomes
	 *                    unavailable and / or the access token becomes
	 *                    invalid. Zero or negative if not specified.
	 * @param digest      The cryptographic digest for the document
	 *                    content. Must not be {@code null}.
	 * @param description The description, {@code null} if not specified.
	 */
	public ExternalAttachment(final URI url,
				  final BearerAccessToken accessToken,
				  final long expiresIn,
				  final Digest digest,
				  final String description) {
		super(AttachmentType.EXTERNAL, description);
		
		Objects.requireNonNull(url);
		this.url = url;
		
		this.accessToken = accessToken;
		
		this.expiresIn = expiresIn;
		
		Objects.requireNonNull(digest);
		this.digest = digest;
	}
	
	
	/**
	 * Returns the attachment URL.
	 *
	 * @return The attachment URL.
	 */
	public URI getURL() {
		return url;
	}
	
	
	/**
	 * Returns the optional access token of type Bearer for retrieving the
	 * attachment.
	 *
	 * @return The bearer access token, {@code null} if not specified.
	 */
	public BearerAccessToken getBearerAccessToken() {
		return accessToken;
	}
	
	
	/**
	 * Returns the number of seconds until the attachment becomes
	 * unavailable and / or the access token becomes invalid.
	 *
	 * @return The number of seconds until the attachment becomes
	 *         unavailable and / or the access token becomes invalid. Zero
	 *         or negative if not specified.
	 */
	public long getExpiresIn() {
		return expiresIn;
	}
	
	
	/**
	 * Returns the cryptographic digest for the document content.
	 *
	 * @return The cryptographic digest.
	 */
	public Digest getDigest() {
		return digest;
	}
	
	
	/**
	 * Retrieves the external attachment content and verifies its digest.
	 *
	 * @param httpConnectTimeout The HTTP connect timeout, in milliseconds.
	 *                           Zero implies no timeout. Must not be
	 *                           negative.
	 * @param httpReadTimeout    The HTTP response read timeout, in
	 *                           milliseconds. Zero implies no timeout.
	 *                           Must not be negative.
	 *
	 * @return The retrieved content.
	 *
	 * @throws IOException              If retrieval of the content failed.
	 * @throws NoSuchAlgorithmException If the hash algorithm for the
	 *                                  digest isn't supported.
	 * @throws DigestMismatchException  If the computed digest for the
	 *                                  retrieved document doesn't match
	 *                                  the expected.
	 */
	public Content retrieveContent(final int httpConnectTimeout, final int httpReadTimeout)
		throws IOException, NoSuchAlgorithmException, DigestMismatchException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, getURL());
		if (getBearerAccessToken() != null) {
			httpRequest.setAuthorization(getBearerAccessToken().toAuthorizationHeader());
		}
		httpRequest.setConnectTimeout(httpConnectTimeout);
		httpRequest.setReadTimeout(httpReadTimeout);
		
		HTTPResponse httpResponse = httpRequest.send();
		try {
			httpResponse.ensureStatusCode(200);
		} catch (ParseException e) {
			throw new IOException(e.getMessage(), e);
		}
		
		if (httpResponse.getEntityContentType() == null) {
			throw new IOException("Missing Content-Type header in HTTP response: " + url);
		}
		
		if (StringUtils.isBlank(httpResponse.getContent())) {
			throw new IOException("The HTTP response has no content: " + url);
		}
		
		// Trim whitespace to ensure digest gets computed over base64 text only
		Base64 contentBase64 = new Base64(httpResponse.getContent().trim());
		
		if (! getDigest().matches(contentBase64)) {
			throw new DigestMismatchException("The computed " + digest.getHashAlgorithm() + " digest for the retrieved content doesn't match the expected: " + getURL());
		}
		
		return new Content(httpResponse.getEntityContentType(), contentBase64, getDescriptionString());
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject jsonObject = super.toJSONObject();
		
		jsonObject.put("url", getURL().toString());
		if (getBearerAccessToken() != null) {
			jsonObject.put("access_token", getBearerAccessToken().getValue());
		}
		if (expiresIn > 0) {
			jsonObject.put("expires_in", getExpiresIn());
		}
		jsonObject.put("digest", getDigest().toJSONObject());
		return jsonObject;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ExternalAttachment)) return false;
		if (!super.equals(o)) return false;
		ExternalAttachment that = (ExternalAttachment) o;
		return getExpiresIn() == that.getExpiresIn() &&
			url.equals(that.url) &&
			Objects.equals(accessToken, that.accessToken) &&
			getDigest().equals(that.getDigest());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), url, accessToken, getExpiresIn(), getDigest());
	}
	
	
	/**
	 * Parses an external attachment from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The external attachment.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ExternalAttachment parse(final JSONObject jsonObject)
		throws ParseException {
		
		URI url = JSONObjectUtils.getURI(jsonObject, "url");
		
		long expiresIn = 0;
		if (jsonObject.get("expires_in") != null) {
			
			expiresIn = JSONObjectUtils.getLong(jsonObject, "expires_in");
			
			if (expiresIn < 1) {
				throw new ParseException("The expires_in parameter must be a positive integer");
			}
		}
		
		BearerAccessToken accessToken = null;
		if (jsonObject.get("access_token") != null) {
			
			String tokenValue = JSONObjectUtils.getNonBlankString(jsonObject, "access_token");
			
			if (expiresIn > 0) {
				accessToken = new BearerAccessToken(tokenValue, expiresIn, null);
			} else {
				accessToken = new BearerAccessToken(tokenValue);
			}
		}
		
		String description = JSONObjectUtils.getString(jsonObject, "desc", null);
		
		Digest digest = Digest.parse(JSONObjectUtils.getJSONObject(jsonObject, "digest"));
		
		return new ExternalAttachment(url, accessToken, expiresIn, digest, description);
	}
}
