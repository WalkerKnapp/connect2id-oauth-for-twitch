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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.Objects;


/**
 * Embedded attachment.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public class EmbeddedAttachment extends Attachment {
	
	
	/**
	 * The content.
	 */
	private final Content content;
	
	
	/**
	 * Creates a new embedded attachment.
	 *
	 * @param content The content. Must not be {@code null}.
	 */
	public EmbeddedAttachment(final Content content) {
		
		super(AttachmentType.EMBEDDED, content.getDescription());
		this.content = content;
	}
	
	
	/**
	 * Returns the content.
	 *
	 * @return The content.
	 */
	public Content getContent() {
		return content;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		JSONObject o = super.toJSONObject();
		o.put("content_type", getContent().getType().toString());
		o.put("content", getContent().getBase64().toString());
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof EmbeddedAttachment)) return false;
		if (!super.equals(o)) return false;
		EmbeddedAttachment that = (EmbeddedAttachment) o;
		return getContent().equals(that.getContent());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), getContent());
	}
	
	
	/**
	 * Parses an embedded attachment from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The embedded attachment.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EmbeddedAttachment parse(final JSONObject jsonObject)
		throws ParseException {
		
		ContentType type;
		try {
			type = ContentType.parse(JSONObjectUtils.getString(jsonObject, "content_type"));
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid content_type: " + e.getMessage(), e);
		}
		
		Base64 base64 = Base64.from(JSONObjectUtils.getNonBlankString(jsonObject, "content"));
		
		String description = JSONObjectUtils.getString(jsonObject, "desc", null);
		
		return new EmbeddedAttachment(new Content(type, base64, description));
	}
}
