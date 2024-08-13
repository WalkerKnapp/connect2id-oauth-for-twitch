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


import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;


/**
 * Identity evidence attachment.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public abstract class Attachment {
	
	
	/**
	 * The attachment type.
	 */
	private final AttachmentType type;
	
	
	/**
	 * The optional description.
	 */
	private final String description;
	
	
	/**
	 * Creates a new attachment with the specified description.
	 *
	 * @param type        The type. Must not be {@code null}.
	 * @param description The description, {@code null} if not specified.
	 */
	protected Attachment(final AttachmentType type, final String description) {
		Objects.requireNonNull(type);
		this.type = type;
		this.description = description;
	}
	
	
	/**
	 * Returns the type of this attachment.
	 *
	 * @return The type.
	 */
	public AttachmentType getType() {
		return type;
	}
	
	
	/**
	 * Returns the description.
	 *
	 * @return The description string.
	 */
	public String getDescriptionString() {
		return description;
	}
	
	
	/**
	 * Returns a JSON object representation of this attachment.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getDescriptionString() != null) {
			o.put("desc", getDescriptionString());
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Attachment)) return false;
		Attachment that = (Attachment) o;
		return Objects.equals(description, that.description);
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(description);
	}
	
	
	/**
	 * Casts this attachment to an embedded attachment.
	 *
	 * @return The embedded attachment.
	 *
	 * @throws ClassCastException If the cast failed.
	 */
	public EmbeddedAttachment toEmbeddedAttachment() {
		
		return (EmbeddedAttachment) this;
	}
	
	
	/**
	 * Casts this attachment to an external attachment.
	 *
	 * @return The external attachment.
	 *
	 * @throws ClassCastException If the cast failed.
	 */
	public ExternalAttachment toExternalAttachment() {
		
		return (ExternalAttachment) this;
	}
	
	
	/**
	 * Parses an identity evidence attachment from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The identity evidence attachment.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Attachment parse(final JSONObject jsonObject)
		throws ParseException {
		
		if (jsonObject.get("content") != null) {
			return EmbeddedAttachment.parse(jsonObject);
		} else if (jsonObject.get("url") != null) {
			return ExternalAttachment.parse(jsonObject);
		} else {
			throw new ParseException("Missing required attachment parameter(s)");
		}
	}
	
	
	/**
	 * Parses a list of identity evidence attachments from the specified
	 * JSON array.
	 *
	 * @param jsonArray The JSON array, {@code null} if not specified.
	 *
	 * @return The list of identity evidence attachments, {@code null} if
	 *         not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static List<Attachment> parseList(final JSONArray jsonArray)
		throws ParseException {
		
		if (jsonArray == null) {
			return null;
		}
		
		List<Attachment> attachments = new LinkedList<>();
		for (JSONObject attachmentObject: JSONArrayUtils.toJSONObjectList(jsonArray)) {
			attachments.add(Attachment.parse(attachmentObject));
		}
		return attachments;
	}
}
