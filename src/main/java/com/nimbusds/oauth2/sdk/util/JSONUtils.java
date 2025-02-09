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

package com.nimbusds.oauth2.sdk.util;


import java.util.LinkedList;
import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;

import net.minidev.json.parser.JSONParser;
import net.minidev.json.writer.JsonReader;


/**
 * JSON helper methods.
 */
public final class JSONUtils {


	/**
	 * Parses a JSON value.
	 *
	 * @param s The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The JSON value.
	 *
	 * @throws ParseException If the string cannot be parsed to a JSON
	 *                        value.
	 */
	public static Object parseJSON(final String s)
		throws ParseException {

		try {
			return new JSONParser(
				JSONParser.USE_HI_PRECISION_FLOAT |
				JSONParser.ACCEPT_TAILLING_SPACE |
				JSONParser.LIMIT_JSON_DEPTH
			).parse(s);
		} catch (net.minidev.json.parser.ParseException e) {
			throw new ParseException("Invalid JSON", e);
		} catch (NullPointerException e) {
			throw new ParseException("The JSON string must not be null", e);
		} catch (Exception e) {
			throw new ParseException("Unexpected exception: " + e.getMessage(), e);
		} catch (Error e) {
			// Guard against unexpected java.lang.Error instances
			throw new ParseException("Unexpected error: " + e.getMessage(), e);
		}
	}


	/**
	 * Parses a JSON value while keeping the order of JSON object members.
	 *
	 * @param s The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The JSON value.
	 *
	 * @throws ParseException If the string cannot be parsed to a JSON
	 *                        value.
	 */
	public static Object parseJSONKeepingOrder(final String s)
		throws ParseException {

		try {
			return new JSONParser(
				JSONParser.USE_HI_PRECISION_FLOAT |
				JSONParser.ACCEPT_TAILLING_SPACE |
				JSONParser.LIMIT_JSON_DEPTH
			).parse(s, new JsonReader().DEFAULT_ORDERED);

		} catch (net.minidev.json.parser.ParseException e) {
			throw new ParseException("Invalid JSON", e);
		} catch (NullPointerException e) {
			throw new ParseException("The JSON string must not be null", e);
		} catch (Exception e) {
			throw new ParseException("Unexpected exception: " + e.getMessage(), e);
		} catch (Error e) {
			// Guard against unexpected java.lang.Error instances
			throw new ParseException("Unexpected error: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Casts an object.
	 *
	 * @param o     The object. Must not be {@code null}.
	 * @param clazz The expected class of the object. Must not be
	 *              {@code null}.
	 *
	 * @return The cast object.
	 *
	 * @throws ParseException If the object is not of the expected type.
	 */
	@SuppressWarnings("unchecked")
	public static <T> T to(final Object o, final Class<T> clazz)
		throws ParseException {
		
		if (! clazz.isAssignableFrom(o.getClass()))
			throw new ParseException("Unexpected type: " + o.getClass());
		
		return (T)o;
	}
	
	
	/**
	 * Casts an object to a boolean.
	 *
	 * @param o The object. Must not be {@code null}.
	 *
	 * @return The boolean value.
	 *
	 * @throws ParseException If the object is not of the expected type.
	 */
	public static boolean toBoolean(final Object o)
		throws ParseException {
		
		return to(o, Boolean.class);
	}
	
	
	/**
	 * Casts an object to a number.
	 *
	 * @param o The object. Must not be {@code null}.
	 *
	 * @return The number.
	 *
	 * @throws ParseException If the object is not of the expected type.
	 */
	public static Number toNumber(final Object o)
		throws ParseException {
		
		return to(o, Number.class);
	}
	
	
	/**
	 * Casts an object to a string.
	 *
	 * @param o The object. Must not be {@code null}.
	 *
	 * @return The string.
	 *
	 * @throws ParseException If the object is not of the expected type.
	 */
	public static String toString(final Object o)
		throws ParseException {
		
		return to(o, String.class);
	}
	
	
	/**
	 * Casts an object to a list.
	 *
	 * @param o The object. Must not be {@code null}.
	 *
	 * @return The list.
	 *
	 * @throws ParseException If the object is not of the expected type.
	 */
	public static List<?> toList(final Object o)
		throws ParseException {
		
		return to(o, List.class);
	}
	
	
	/**
	 * Casts an object to a list then returns a string list copy of it
	 * casting each item to a string.
	 *
	 * @param o The object. Must not be {@code null}.
	 *
	 * @return The string list.
	 *
	 * @throws ParseException If the object is not of the expected type.
	 */
	public static List<String> toStringList(final Object o)
		throws ParseException {
		
		List<String> stringList = new LinkedList<>();
		try {
			for (Object item: toList(o)) {
				stringList.add((String)item);
			}
		} catch (ClassCastException e) {
			throw new ParseException("Item not a string");
		}
		return stringList;
	}
	
	
	/**
	 * Prevents instantiation.
	 */
	private JSONUtils() {}
}
