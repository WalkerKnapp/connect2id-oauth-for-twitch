package com.nimbusds.oauth2.sdk.token;


import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.Set;


/**
 * Typeless (generic) token.
 */
@Immutable
public class TypelessToken extends Token {
	
	
	private static final long serialVersionUID = 1477117093355749547L;
	
	
	/**
	 * Creates a new typeless token with the specified value.
	 *
	 * @param value The token value. Must not be {@code null} or empty
	 *              string.
	 */
	public TypelessToken(final String value) {
		super(value);
	}
	
	
	@Override
	public Set<String> getParameterNames() {
		return getCustomParameters().keySet();
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		JSONObject jsonObject = new JSONObject();
		jsonObject.putAll(getCustomParameters());
		return jsonObject;
	}
}
