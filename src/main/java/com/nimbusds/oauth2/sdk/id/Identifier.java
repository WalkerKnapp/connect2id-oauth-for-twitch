package com.nimbusds.oauth2.sdk.id;


import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONValue;


/**
 * The base abstract class for representing identifiers and identities. 
 * Provides constructors that generate random identifier values made up of
 * mixed-case alphanumeric ASCII characters.
 *
 * <p>Extending classes must override the {@link #equals} method.
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class Identifier implements JSONAware {


	/**
	 * The identifier value.
	 */
	private final String value;


	/**
	 * Creates a new identifier with the specified value.
	 *
	 * @param value The identifier value. Must not be {@code null} or empty
	 *              string.
	 */
	public Identifier(final String value) {

		if (StringUtils.isBlank(value))
			throw new IllegalArgumentException("The value must not be null or empty string");

		this.value = value;
	}


	/**
	 * Creates a new identifier with a randomly generated value of the 
	 * specified length. The value will be made up of mixed-case 
	 * alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public Identifier(final int length) {
	
		this(RandomStringUtils.randomAlphanumeric(length));
	}
	
	
	/**
	 * Creates a new identifier with a randomly generated value. The value 
	 * will be made up of 32 mixed-case alphanumeric ASCII characters.
	 */
	public Identifier() {

		this(32);
	}


	/**
	 * Gets the value of this identifier.
	 *
	 * @return The value.
	 */
	public String getValue() {

		return value;
	}


	/**
	 * Returns the JSON string representation of this identifier.
	 *
	 * @return The JSON string.
	 */
	@Override
	public String toJSONString() {

		StringBuilder sb = new StringBuilder("\"");
		sb.append(JSONValue.escape(value));
		sb.append('"');
		return sb.toString();
	}
	
	
	/**
	 * @see #getValue
	 */
	@Override
	public String toString() {
	
		return getValue();
	}


	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public int hashCode() {
	
		return value.hashCode();
	}
	
	
	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value, otherwise
	 *         {@code false}.
	 */
	@Override
	public abstract boolean equals(final Object object);
}