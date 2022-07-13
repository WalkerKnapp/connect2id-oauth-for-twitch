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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * ISO 3166-1 alpha-2 (two-letter) country code.
 *
 * <p>Includes constants for all 249 current officially assigned ISO 3166-1
 * alpha-2 codes.
 */
@Immutable
public final class ISO3166_1Alpha2CountryCode extends ISO3166_1AlphaCountryCode {
	
	
	private static final long serialVersionUID = -7659886425656766569L;
	
	
	// Codes extracted from Markdown at https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements
	
	/** Andorra */
	public static final ISO3166_1Alpha2CountryCode AD = new ISO3166_1Alpha2CountryCode("AD");
	
	/** United Arab Emirates */
	public static final ISO3166_1Alpha2CountryCode AE = new ISO3166_1Alpha2CountryCode("AE");
	
	/** Afghanistan */
	public static final ISO3166_1Alpha2CountryCode AF = new ISO3166_1Alpha2CountryCode("AF");
	
	/** Antigua and Barbuda */
	public static final ISO3166_1Alpha2CountryCode AG = new ISO3166_1Alpha2CountryCode("AG");
	
	/** Anguilla */
	public static final ISO3166_1Alpha2CountryCode AI = new ISO3166_1Alpha2CountryCode("AI");
	
	/** Albania */
	public static final ISO3166_1Alpha2CountryCode AL = new ISO3166_1Alpha2CountryCode("AL");
	
	/** Armenia */
	public static final ISO3166_1Alpha2CountryCode AM = new ISO3166_1Alpha2CountryCode("AM");
	
	/** Angola */
	public static final ISO3166_1Alpha2CountryCode AO = new ISO3166_1Alpha2CountryCode("AO");
	
	/** Antarctica */
	public static final ISO3166_1Alpha2CountryCode AQ = new ISO3166_1Alpha2CountryCode("AQ");
	
	/** Argentina */
	public static final ISO3166_1Alpha2CountryCode AR = new ISO3166_1Alpha2CountryCode("AR");
	
	/** American Samoa */
	public static final ISO3166_1Alpha2CountryCode AS = new ISO3166_1Alpha2CountryCode("AS");
	
	/** Austria */
	public static final ISO3166_1Alpha2CountryCode AT = new ISO3166_1Alpha2CountryCode("AT");
	
	/** Australia */
	public static final ISO3166_1Alpha2CountryCode AU = new ISO3166_1Alpha2CountryCode("AU");
	
	/** Aruba */
	public static final ISO3166_1Alpha2CountryCode AW = new ISO3166_1Alpha2CountryCode("AW");
	
	/** Aland Islands */
	public static final ISO3166_1Alpha2CountryCode AX = new ISO3166_1Alpha2CountryCode("AX");
	
	/** Azerbaijan */
	public static final ISO3166_1Alpha2CountryCode AZ = new ISO3166_1Alpha2CountryCode("AZ");
	
	/** Bosnia and Herzegovina */
	public static final ISO3166_1Alpha2CountryCode BA = new ISO3166_1Alpha2CountryCode("BA");
	
	/** Barbados */
	public static final ISO3166_1Alpha2CountryCode BB = new ISO3166_1Alpha2CountryCode("BB");
	
	/** Bangladesh */
	public static final ISO3166_1Alpha2CountryCode BD = new ISO3166_1Alpha2CountryCode("BD");
	
	/** Belgium */
	public static final ISO3166_1Alpha2CountryCode BE = new ISO3166_1Alpha2CountryCode("BE");
	
	/** Burkina Faso */
	public static final ISO3166_1Alpha2CountryCode BF = new ISO3166_1Alpha2CountryCode("BF");
	
	/** Bulgaria */
	public static final ISO3166_1Alpha2CountryCode BG = new ISO3166_1Alpha2CountryCode("BG");
	
	/** Bahrain */
	public static final ISO3166_1Alpha2CountryCode BH = new ISO3166_1Alpha2CountryCode("BH");
	
	/** Burundi */
	public static final ISO3166_1Alpha2CountryCode BI = new ISO3166_1Alpha2CountryCode("BI");
	
	/** Benin */
	public static final ISO3166_1Alpha2CountryCode BJ = new ISO3166_1Alpha2CountryCode("BJ");
	
	/** Saint Barthélemy */
	public static final ISO3166_1Alpha2CountryCode BL = new ISO3166_1Alpha2CountryCode("BL");
	
	/** Bermuda */
	public static final ISO3166_1Alpha2CountryCode BM = new ISO3166_1Alpha2CountryCode("BM");
	
	/** Brunei Darussalam */
	public static final ISO3166_1Alpha2CountryCode BN = new ISO3166_1Alpha2CountryCode("BN");
	
	/** Bolivia (Plurinational State of) */
	public static final ISO3166_1Alpha2CountryCode BO = new ISO3166_1Alpha2CountryCode("BO");
	
	/** Bonaire, Sint Eustatius and Saba */
	public static final ISO3166_1Alpha2CountryCode BQ = new ISO3166_1Alpha2CountryCode("BQ");
	
	/** Brazil */
	public static final ISO3166_1Alpha2CountryCode BR = new ISO3166_1Alpha2CountryCode("BR");
	
	/** Bahamas */
	public static final ISO3166_1Alpha2CountryCode BS = new ISO3166_1Alpha2CountryCode("BS");
	
	/** Bhutan */
	public static final ISO3166_1Alpha2CountryCode BT = new ISO3166_1Alpha2CountryCode("BT");
	
	/** Bouvet Island */
	public static final ISO3166_1Alpha2CountryCode BV = new ISO3166_1Alpha2CountryCode("BV");
	
	/** Botswana */
	public static final ISO3166_1Alpha2CountryCode BW = new ISO3166_1Alpha2CountryCode("BW");
	
	/** Belarus */
	public static final ISO3166_1Alpha2CountryCode BY = new ISO3166_1Alpha2CountryCode("BY");
	
	/** Belize */
	public static final ISO3166_1Alpha2CountryCode BZ = new ISO3166_1Alpha2CountryCode("BZ");
	
	/** Canada */
	public static final ISO3166_1Alpha2CountryCode CA = new ISO3166_1Alpha2CountryCode("CA");
	
	/** Cocos (Keeling) Islands */
	public static final ISO3166_1Alpha2CountryCode CC = new ISO3166_1Alpha2CountryCode("CC");
	
	/** Congo, Democratic Republic of the */
	public static final ISO3166_1Alpha2CountryCode CD = new ISO3166_1Alpha2CountryCode("CD");
	
	/** Central African Republic */
	public static final ISO3166_1Alpha2CountryCode CF = new ISO3166_1Alpha2CountryCode("CF");
	
	/** Congo */
	public static final ISO3166_1Alpha2CountryCode CG = new ISO3166_1Alpha2CountryCode("CG");
	
	/** Switzerland */
	public static final ISO3166_1Alpha2CountryCode CH = new ISO3166_1Alpha2CountryCode("CH");
	
	/** Côte d'Ivoire */
	public static final ISO3166_1Alpha2CountryCode CI = new ISO3166_1Alpha2CountryCode("CI");
	
	/** Cook Islands */
	public static final ISO3166_1Alpha2CountryCode CK = new ISO3166_1Alpha2CountryCode("CK");
	
	/** Chile */
	public static final ISO3166_1Alpha2CountryCode CL = new ISO3166_1Alpha2CountryCode("CL");
	
	/** Cameroon */
	public static final ISO3166_1Alpha2CountryCode CM = new ISO3166_1Alpha2CountryCode("CM");
	
	/** China */
	public static final ISO3166_1Alpha2CountryCode CN = new ISO3166_1Alpha2CountryCode("CN");
	
	/** Colombia */
	public static final ISO3166_1Alpha2CountryCode CO = new ISO3166_1Alpha2CountryCode("CO");
	
	/** Costa Rica */
	public static final ISO3166_1Alpha2CountryCode CR = new ISO3166_1Alpha2CountryCode("CR");
	
	/** Cuba */
	public static final ISO3166_1Alpha2CountryCode CU = new ISO3166_1Alpha2CountryCode("CU");
	
	/** Cabo Verde */
	public static final ISO3166_1Alpha2CountryCode CV = new ISO3166_1Alpha2CountryCode("CV");
	
	/** Curaçao */
	public static final ISO3166_1Alpha2CountryCode CW = new ISO3166_1Alpha2CountryCode("CW");
	
	/** Christmas Island */
	public static final ISO3166_1Alpha2CountryCode CX = new ISO3166_1Alpha2CountryCode("CX");
	
	/** Cyprus */
	public static final ISO3166_1Alpha2CountryCode CY = new ISO3166_1Alpha2CountryCode("CY");
	
	/** Czechia */
	public static final ISO3166_1Alpha2CountryCode CZ = new ISO3166_1Alpha2CountryCode("CZ");
	
	/** Germany */
	public static final ISO3166_1Alpha2CountryCode DE = new ISO3166_1Alpha2CountryCode("DE");
	
	/** Djibouti */
	public static final ISO3166_1Alpha2CountryCode DJ = new ISO3166_1Alpha2CountryCode("DJ");
	
	/** Denmark */
	public static final ISO3166_1Alpha2CountryCode DK = new ISO3166_1Alpha2CountryCode("DK");
	
	/** Dominica */
	public static final ISO3166_1Alpha2CountryCode DM = new ISO3166_1Alpha2CountryCode("DM");
	
	/** Dominican Republic */
	public static final ISO3166_1Alpha2CountryCode DO = new ISO3166_1Alpha2CountryCode("DO");
	
	/** Algeria */
	public static final ISO3166_1Alpha2CountryCode DZ = new ISO3166_1Alpha2CountryCode("DZ");
	
	/** Ecuador */
	public static final ISO3166_1Alpha2CountryCode EC = new ISO3166_1Alpha2CountryCode("EC");
	
	/** Estonia */
	public static final ISO3166_1Alpha2CountryCode EE = new ISO3166_1Alpha2CountryCode("EE");
	
	/** Egypt */
	public static final ISO3166_1Alpha2CountryCode EG = new ISO3166_1Alpha2CountryCode("EG");
	
	/** Western Sahara */
	public static final ISO3166_1Alpha2CountryCode EH = new ISO3166_1Alpha2CountryCode("EH");
	
	/** Eritrea */
	public static final ISO3166_1Alpha2CountryCode ER = new ISO3166_1Alpha2CountryCode("ER");
	
	/** Spain */
	public static final ISO3166_1Alpha2CountryCode ES = new ISO3166_1Alpha2CountryCode("ES");
	
	/** Ethiopia */
	public static final ISO3166_1Alpha2CountryCode ET = new ISO3166_1Alpha2CountryCode("ET");
	
	/** Finland */
	public static final ISO3166_1Alpha2CountryCode FI = new ISO3166_1Alpha2CountryCode("FI");
	
	/** Fiji */
	public static final ISO3166_1Alpha2CountryCode FJ = new ISO3166_1Alpha2CountryCode("FJ");
	
	/** Falkland Islands (Malvinas) */
	public static final ISO3166_1Alpha2CountryCode FK = new ISO3166_1Alpha2CountryCode("FK");
	
	/** Micronesia (Federated States of) */
	public static final ISO3166_1Alpha2CountryCode FM = new ISO3166_1Alpha2CountryCode("FM");
	
	/** Faroe Islands */
	public static final ISO3166_1Alpha2CountryCode FO = new ISO3166_1Alpha2CountryCode("FO");
	
	/** France */
	public static final ISO3166_1Alpha2CountryCode FR = new ISO3166_1Alpha2CountryCode("FR");
	
	/** Gabon */
	public static final ISO3166_1Alpha2CountryCode GA = new ISO3166_1Alpha2CountryCode("GA");
	
	/** United Kingdom of Great Britain and Northern Ireland */
	public static final ISO3166_1Alpha2CountryCode GB = new ISO3166_1Alpha2CountryCode("GB");
	
	/** Grenada */
	public static final ISO3166_1Alpha2CountryCode GD = new ISO3166_1Alpha2CountryCode("GD");
	
	/** Georgia */
	public static final ISO3166_1Alpha2CountryCode GE = new ISO3166_1Alpha2CountryCode("GE");
	
	/** French Guiana */
	public static final ISO3166_1Alpha2CountryCode GF = new ISO3166_1Alpha2CountryCode("GF");
	
	/** Guernsey */
	public static final ISO3166_1Alpha2CountryCode GG = new ISO3166_1Alpha2CountryCode("GG");
	
	/** Ghana */
	public static final ISO3166_1Alpha2CountryCode GH = new ISO3166_1Alpha2CountryCode("GH");
	
	/** Gibraltar */
	public static final ISO3166_1Alpha2CountryCode GI = new ISO3166_1Alpha2CountryCode("GI");
	
	/** Greenland */
	public static final ISO3166_1Alpha2CountryCode GL = new ISO3166_1Alpha2CountryCode("GL");
	
	/** Gambia */
	public static final ISO3166_1Alpha2CountryCode GM = new ISO3166_1Alpha2CountryCode("GM");
	
	/** Guinea */
	public static final ISO3166_1Alpha2CountryCode GN = new ISO3166_1Alpha2CountryCode("GN");
	
	/** Guadeloupe */
	public static final ISO3166_1Alpha2CountryCode GP = new ISO3166_1Alpha2CountryCode("GP");
	
	/** Equatorial Guinea */
	public static final ISO3166_1Alpha2CountryCode GQ = new ISO3166_1Alpha2CountryCode("GQ");
	
	/** Greece */
	public static final ISO3166_1Alpha2CountryCode GR = new ISO3166_1Alpha2CountryCode("GR");
	
	/** South Georgia and the South Sandwich Islands */
	public static final ISO3166_1Alpha2CountryCode GS = new ISO3166_1Alpha2CountryCode("GS");
	
	/** Guatemala */
	public static final ISO3166_1Alpha2CountryCode GT = new ISO3166_1Alpha2CountryCode("GT");
	
	/** Guam */
	public static final ISO3166_1Alpha2CountryCode GU = new ISO3166_1Alpha2CountryCode("GU");
	
	/** Guinea-Bissau */
	public static final ISO3166_1Alpha2CountryCode GW = new ISO3166_1Alpha2CountryCode("GW");
	
	/** Guyana */
	public static final ISO3166_1Alpha2CountryCode GY = new ISO3166_1Alpha2CountryCode("GY");
	
	/** Hong Kong */
	public static final ISO3166_1Alpha2CountryCode HK = new ISO3166_1Alpha2CountryCode("HK");
	
	/** Heard Island and McDonald Islands */
	public static final ISO3166_1Alpha2CountryCode HM = new ISO3166_1Alpha2CountryCode("HM");
	
	/** Honduras */
	public static final ISO3166_1Alpha2CountryCode HN = new ISO3166_1Alpha2CountryCode("HN");
	
	/** Croatia */
	public static final ISO3166_1Alpha2CountryCode HR = new ISO3166_1Alpha2CountryCode("HR");
	
	/** Haiti */
	public static final ISO3166_1Alpha2CountryCode HT = new ISO3166_1Alpha2CountryCode("HT");
	
	/** Hungary */
	public static final ISO3166_1Alpha2CountryCode HU = new ISO3166_1Alpha2CountryCode("HU");
	
	/** Indonesia */
	public static final ISO3166_1Alpha2CountryCode ID = new ISO3166_1Alpha2CountryCode("ID");
	
	/** Ireland */
	public static final ISO3166_1Alpha2CountryCode IE = new ISO3166_1Alpha2CountryCode("IE");
	
	/** Israel */
	public static final ISO3166_1Alpha2CountryCode IL = new ISO3166_1Alpha2CountryCode("IL");
	
	/** Isle of Man */
	public static final ISO3166_1Alpha2CountryCode IM = new ISO3166_1Alpha2CountryCode("IM");
	
	/** India */
	public static final ISO3166_1Alpha2CountryCode IN = new ISO3166_1Alpha2CountryCode("IN");
	
	/** British Indian Ocean Territory */
	public static final ISO3166_1Alpha2CountryCode IO = new ISO3166_1Alpha2CountryCode("IO");
	
	/** Iraq */
	public static final ISO3166_1Alpha2CountryCode IQ = new ISO3166_1Alpha2CountryCode("IQ");
	
	/** Iran (Islamic Republic of) */
	public static final ISO3166_1Alpha2CountryCode IR = new ISO3166_1Alpha2CountryCode("IR");
	
	/** Iceland */
	public static final ISO3166_1Alpha2CountryCode IS = new ISO3166_1Alpha2CountryCode("IS");
	
	/** Italy */
	public static final ISO3166_1Alpha2CountryCode IT = new ISO3166_1Alpha2CountryCode("IT");
	
	/** Jersey */
	public static final ISO3166_1Alpha2CountryCode JE = new ISO3166_1Alpha2CountryCode("JE");
	
	/** Jamaica */
	public static final ISO3166_1Alpha2CountryCode JM = new ISO3166_1Alpha2CountryCode("JM");
	
	/** Jordan */
	public static final ISO3166_1Alpha2CountryCode JO = new ISO3166_1Alpha2CountryCode("JO");
	
	/** Japan */
	public static final ISO3166_1Alpha2CountryCode JP = new ISO3166_1Alpha2CountryCode("JP");
	
	/** Kenya */
	public static final ISO3166_1Alpha2CountryCode KE = new ISO3166_1Alpha2CountryCode("KE");
	
	/** Kyrgyzstan */
	public static final ISO3166_1Alpha2CountryCode KG = new ISO3166_1Alpha2CountryCode("KG");
	
	/** Cambodia */
	public static final ISO3166_1Alpha2CountryCode KH = new ISO3166_1Alpha2CountryCode("KH");
	
	/** Kiribati */
	public static final ISO3166_1Alpha2CountryCode KI = new ISO3166_1Alpha2CountryCode("KI");
	
	/** Comoros */
	public static final ISO3166_1Alpha2CountryCode KM = new ISO3166_1Alpha2CountryCode("KM");
	
	/** Saint Kitts and Nevis */
	public static final ISO3166_1Alpha2CountryCode KN = new ISO3166_1Alpha2CountryCode("KN");
	
	/** Korea (Democratic People's Republic of) */
	public static final ISO3166_1Alpha2CountryCode KP = new ISO3166_1Alpha2CountryCode("KP");
	
	/** Korea, Republic of */
	public static final ISO3166_1Alpha2CountryCode KR = new ISO3166_1Alpha2CountryCode("KR");
	
	/** Kuwait */
	public static final ISO3166_1Alpha2CountryCode KW = new ISO3166_1Alpha2CountryCode("KW");
	
	/** Cayman Islands */
	public static final ISO3166_1Alpha2CountryCode KY = new ISO3166_1Alpha2CountryCode("KY");
	
	/** Kazakhstan */
	public static final ISO3166_1Alpha2CountryCode KZ = new ISO3166_1Alpha2CountryCode("KZ");
	
	/** Lao People's Democratic Republic */
	public static final ISO3166_1Alpha2CountryCode LA = new ISO3166_1Alpha2CountryCode("LA");
	
	/** Lebanon */
	public static final ISO3166_1Alpha2CountryCode LB = new ISO3166_1Alpha2CountryCode("LB");
	
	/** Saint Lucia */
	public static final ISO3166_1Alpha2CountryCode LC = new ISO3166_1Alpha2CountryCode("LC");
	
	/** Liechtenstein */
	public static final ISO3166_1Alpha2CountryCode LI = new ISO3166_1Alpha2CountryCode("LI");
	
	/** Sri Lanka */
	public static final ISO3166_1Alpha2CountryCode LK = new ISO3166_1Alpha2CountryCode("LK");
	
	/** Liberia */
	public static final ISO3166_1Alpha2CountryCode LR = new ISO3166_1Alpha2CountryCode("LR");
	
	/** Lesotho */
	public static final ISO3166_1Alpha2CountryCode LS = new ISO3166_1Alpha2CountryCode("LS");
	
	/** Lithuania */
	public static final ISO3166_1Alpha2CountryCode LT = new ISO3166_1Alpha2CountryCode("LT");
	
	/** Luxembourg */
	public static final ISO3166_1Alpha2CountryCode LU = new ISO3166_1Alpha2CountryCode("LU");
	
	/** Latvia */
	public static final ISO3166_1Alpha2CountryCode LV = new ISO3166_1Alpha2CountryCode("LV");
	
	/** Libya */
	public static final ISO3166_1Alpha2CountryCode LY = new ISO3166_1Alpha2CountryCode("LY");
	
	/** Morocco */
	public static final ISO3166_1Alpha2CountryCode MA = new ISO3166_1Alpha2CountryCode("MA");
	
	/** Monaco */
	public static final ISO3166_1Alpha2CountryCode MC = new ISO3166_1Alpha2CountryCode("MC");
	
	/** Moldova, Republic of */
	public static final ISO3166_1Alpha2CountryCode MD = new ISO3166_1Alpha2CountryCode("MD");
	
	/** Montenegro */
	public static final ISO3166_1Alpha2CountryCode ME = new ISO3166_1Alpha2CountryCode("ME");
	
	/** Saint Martin (French part) */
	public static final ISO3166_1Alpha2CountryCode MF = new ISO3166_1Alpha2CountryCode("MF");
	
	/** Madagascar */
	public static final ISO3166_1Alpha2CountryCode MG = new ISO3166_1Alpha2CountryCode("MG");
	
	/** Marshall Islands */
	public static final ISO3166_1Alpha2CountryCode MH = new ISO3166_1Alpha2CountryCode("MH");
	
	/** North Macedonia */
	public static final ISO3166_1Alpha2CountryCode MK = new ISO3166_1Alpha2CountryCode("MK");
	
	/** Mali */
	public static final ISO3166_1Alpha2CountryCode ML = new ISO3166_1Alpha2CountryCode("ML");
	
	/** Myanmar */
	public static final ISO3166_1Alpha2CountryCode MM = new ISO3166_1Alpha2CountryCode("MM");
	
	/** Mongolia */
	public static final ISO3166_1Alpha2CountryCode MN = new ISO3166_1Alpha2CountryCode("MN");
	
	/** Macao */
	public static final ISO3166_1Alpha2CountryCode MO = new ISO3166_1Alpha2CountryCode("MO");
	
	/** Northern Mariana Islands */
	public static final ISO3166_1Alpha2CountryCode MP = new ISO3166_1Alpha2CountryCode("MP");
	
	/** Martinique */
	public static final ISO3166_1Alpha2CountryCode MQ = new ISO3166_1Alpha2CountryCode("MQ");
	
	/** Mauritania */
	public static final ISO3166_1Alpha2CountryCode MR = new ISO3166_1Alpha2CountryCode("MR");
	
	/** Montserrat */
	public static final ISO3166_1Alpha2CountryCode MS = new ISO3166_1Alpha2CountryCode("MS");
	
	/** Malta */
	public static final ISO3166_1Alpha2CountryCode MT = new ISO3166_1Alpha2CountryCode("MT");
	
	/** Mauritius */
	public static final ISO3166_1Alpha2CountryCode MU = new ISO3166_1Alpha2CountryCode("MU");
	
	/** Maldives */
	public static final ISO3166_1Alpha2CountryCode MV = new ISO3166_1Alpha2CountryCode("MV");
	
	/** Malawi */
	public static final ISO3166_1Alpha2CountryCode MW = new ISO3166_1Alpha2CountryCode("MW");
	
	/** Mexico */
	public static final ISO3166_1Alpha2CountryCode MX = new ISO3166_1Alpha2CountryCode("MX");
	
	/** Malaysia */
	public static final ISO3166_1Alpha2CountryCode MY = new ISO3166_1Alpha2CountryCode("MY");
	
	/** Mozambique */
	public static final ISO3166_1Alpha2CountryCode MZ = new ISO3166_1Alpha2CountryCode("MZ");
	
	/** Namibia */
	public static final ISO3166_1Alpha2CountryCode NA = new ISO3166_1Alpha2CountryCode("NA");
	
	/** New Caledonia */
	public static final ISO3166_1Alpha2CountryCode NC = new ISO3166_1Alpha2CountryCode("NC");
	
	/** Niger */
	public static final ISO3166_1Alpha2CountryCode NE = new ISO3166_1Alpha2CountryCode("NE");
	
	/** Norfolk Island */
	public static final ISO3166_1Alpha2CountryCode NF = new ISO3166_1Alpha2CountryCode("NF");
	
	/** Nigeria */
	public static final ISO3166_1Alpha2CountryCode NG = new ISO3166_1Alpha2CountryCode("NG");
	
	/** Nicaragua */
	public static final ISO3166_1Alpha2CountryCode NI = new ISO3166_1Alpha2CountryCode("NI");
	
	/** Netherlands */
	public static final ISO3166_1Alpha2CountryCode NL = new ISO3166_1Alpha2CountryCode("NL");
	
	/** Norway */
	public static final ISO3166_1Alpha2CountryCode NO = new ISO3166_1Alpha2CountryCode("NO");
	
	/** Nepal */
	public static final ISO3166_1Alpha2CountryCode NP = new ISO3166_1Alpha2CountryCode("NP");
	
	/** Nauru */
	public static final ISO3166_1Alpha2CountryCode NR = new ISO3166_1Alpha2CountryCode("NR");
	
	/** Niue */
	public static final ISO3166_1Alpha2CountryCode NU = new ISO3166_1Alpha2CountryCode("NU");
	
	/** New Zealand */
	public static final ISO3166_1Alpha2CountryCode NZ = new ISO3166_1Alpha2CountryCode("NZ");
	
	/** Oman */
	public static final ISO3166_1Alpha2CountryCode OM = new ISO3166_1Alpha2CountryCode("OM");
	
	/** Panama */
	public static final ISO3166_1Alpha2CountryCode PA = new ISO3166_1Alpha2CountryCode("PA");
	
	/** Peru */
	public static final ISO3166_1Alpha2CountryCode PE = new ISO3166_1Alpha2CountryCode("PE");
	
	/** French Polynesia */
	public static final ISO3166_1Alpha2CountryCode PF = new ISO3166_1Alpha2CountryCode("PF");
	
	/** Papua New Guinea */
	public static final ISO3166_1Alpha2CountryCode PG = new ISO3166_1Alpha2CountryCode("PG");
	
	/** Philippines */
	public static final ISO3166_1Alpha2CountryCode PH = new ISO3166_1Alpha2CountryCode("PH");
	
	/** Pakistan */
	public static final ISO3166_1Alpha2CountryCode PK = new ISO3166_1Alpha2CountryCode("PK");
	
	/** Poland */
	public static final ISO3166_1Alpha2CountryCode PL = new ISO3166_1Alpha2CountryCode("PL");
	
	/** Saint Pierre and Miquelon */
	public static final ISO3166_1Alpha2CountryCode PM = new ISO3166_1Alpha2CountryCode("PM");
	
	/** Pitcairn */
	public static final ISO3166_1Alpha2CountryCode PN = new ISO3166_1Alpha2CountryCode("PN");
	
	/** Puerto Rico */
	public static final ISO3166_1Alpha2CountryCode PR = new ISO3166_1Alpha2CountryCode("PR");
	
	/** Palestine, State of */
	public static final ISO3166_1Alpha2CountryCode PS = new ISO3166_1Alpha2CountryCode("PS");
	
	/** Portugal */
	public static final ISO3166_1Alpha2CountryCode PT = new ISO3166_1Alpha2CountryCode("PT");
	
	/** Palau */
	public static final ISO3166_1Alpha2CountryCode PW = new ISO3166_1Alpha2CountryCode("PW");
	
	/** Paraguay */
	public static final ISO3166_1Alpha2CountryCode PY = new ISO3166_1Alpha2CountryCode("PY");
	
	/** Qatar */
	public static final ISO3166_1Alpha2CountryCode QA = new ISO3166_1Alpha2CountryCode("QA");
	
	/** Réunion */
	public static final ISO3166_1Alpha2CountryCode RE = new ISO3166_1Alpha2CountryCode("RE");
	
	/** Romania */
	public static final ISO3166_1Alpha2CountryCode RO = new ISO3166_1Alpha2CountryCode("RO");
	
	/** Serbia */
	public static final ISO3166_1Alpha2CountryCode RS = new ISO3166_1Alpha2CountryCode("RS");
	
	/** Russian Federation */
	public static final ISO3166_1Alpha2CountryCode RU = new ISO3166_1Alpha2CountryCode("RU");
	
	/** Rwanda */
	public static final ISO3166_1Alpha2CountryCode RW = new ISO3166_1Alpha2CountryCode("RW");
	
	/** Saudi Arabia */
	public static final ISO3166_1Alpha2CountryCode SA = new ISO3166_1Alpha2CountryCode("SA");
	
	/** Solomon Islands */
	public static final ISO3166_1Alpha2CountryCode SB = new ISO3166_1Alpha2CountryCode("SB");
	
	/** Seychelles */
	public static final ISO3166_1Alpha2CountryCode SC = new ISO3166_1Alpha2CountryCode("SC");
	
	/** Sudan */
	public static final ISO3166_1Alpha2CountryCode SD = new ISO3166_1Alpha2CountryCode("SD");
	
	/** Sweden */
	public static final ISO3166_1Alpha2CountryCode SE = new ISO3166_1Alpha2CountryCode("SE");
	
	/** Singapore */
	public static final ISO3166_1Alpha2CountryCode SG = new ISO3166_1Alpha2CountryCode("SG");
	
	/** Saint Helena, Ascension and Tristan da Cunha */
	public static final ISO3166_1Alpha2CountryCode SH = new ISO3166_1Alpha2CountryCode("SH");
	
	/** Slovenia */
	public static final ISO3166_1Alpha2CountryCode SI = new ISO3166_1Alpha2CountryCode("SI");
	
	/** Svalbard and Jan Mayen */
	public static final ISO3166_1Alpha2CountryCode SJ = new ISO3166_1Alpha2CountryCode("SJ");
	
	/** Slovakia */
	public static final ISO3166_1Alpha2CountryCode SK = new ISO3166_1Alpha2CountryCode("SK");
	
	/** Sierra Leone */
	public static final ISO3166_1Alpha2CountryCode SL = new ISO3166_1Alpha2CountryCode("SL");
	
	/** San Marino */
	public static final ISO3166_1Alpha2CountryCode SM = new ISO3166_1Alpha2CountryCode("SM");
	
	/** Senegal */
	public static final ISO3166_1Alpha2CountryCode SN = new ISO3166_1Alpha2CountryCode("SN");
	
	/** Somalia */
	public static final ISO3166_1Alpha2CountryCode SO = new ISO3166_1Alpha2CountryCode("SO");
	
	/** Suriname */
	public static final ISO3166_1Alpha2CountryCode SR = new ISO3166_1Alpha2CountryCode("SR");
	
	/** South Sudan */
	public static final ISO3166_1Alpha2CountryCode SS = new ISO3166_1Alpha2CountryCode("SS");
	
	/** Sao Tome and Principe */
	public static final ISO3166_1Alpha2CountryCode ST = new ISO3166_1Alpha2CountryCode("ST");
	
	/** El Salvador */
	public static final ISO3166_1Alpha2CountryCode SV = new ISO3166_1Alpha2CountryCode("SV");
	
	/** Sint Maarten (Dutch part) */
	public static final ISO3166_1Alpha2CountryCode SX = new ISO3166_1Alpha2CountryCode("SX");
	
	/** Syrian Arab Republic */
	public static final ISO3166_1Alpha2CountryCode SY = new ISO3166_1Alpha2CountryCode("SY");
	
	/** Eswatini */
	public static final ISO3166_1Alpha2CountryCode SZ = new ISO3166_1Alpha2CountryCode("SZ");
	
	/** Turks and Caicos Islands */
	public static final ISO3166_1Alpha2CountryCode TC = new ISO3166_1Alpha2CountryCode("TC");
	
	/** Chad */
	public static final ISO3166_1Alpha2CountryCode TD = new ISO3166_1Alpha2CountryCode("TD");
	
	/** French Southern Territories */
	public static final ISO3166_1Alpha2CountryCode TF = new ISO3166_1Alpha2CountryCode("TF");
	
	/** Togo */
	public static final ISO3166_1Alpha2CountryCode TG = new ISO3166_1Alpha2CountryCode("TG");
	
	/** Thailand */
	public static final ISO3166_1Alpha2CountryCode TH = new ISO3166_1Alpha2CountryCode("TH");
	
	/** Tajikistan */
	public static final ISO3166_1Alpha2CountryCode TJ = new ISO3166_1Alpha2CountryCode("TJ");
	
	/** Tokelau */
	public static final ISO3166_1Alpha2CountryCode TK = new ISO3166_1Alpha2CountryCode("TK");
	
	/** Timor-Leste */
	public static final ISO3166_1Alpha2CountryCode TL = new ISO3166_1Alpha2CountryCode("TL");
	
	/** Turkmenistan */
	public static final ISO3166_1Alpha2CountryCode TM = new ISO3166_1Alpha2CountryCode("TM");
	
	/** Tunisia */
	public static final ISO3166_1Alpha2CountryCode TN = new ISO3166_1Alpha2CountryCode("TN");
	
	/** Tonga */
	public static final ISO3166_1Alpha2CountryCode TO = new ISO3166_1Alpha2CountryCode("TO");
	
	/** Turkey */
	public static final ISO3166_1Alpha2CountryCode TR = new ISO3166_1Alpha2CountryCode("TR");
	
	/** Trinidad and Tobago */
	public static final ISO3166_1Alpha2CountryCode TT = new ISO3166_1Alpha2CountryCode("TT");
	
	/** Tuvalu */
	public static final ISO3166_1Alpha2CountryCode TV = new ISO3166_1Alpha2CountryCode("TV");
	
	/** Taiwan, Province of China */
	public static final ISO3166_1Alpha2CountryCode TW = new ISO3166_1Alpha2CountryCode("TW");
	
	/** Tanzania, United Republic of */
	public static final ISO3166_1Alpha2CountryCode TZ = new ISO3166_1Alpha2CountryCode("TZ");
	
	/** Ukraine */
	public static final ISO3166_1Alpha2CountryCode UA = new ISO3166_1Alpha2CountryCode("UA");
	
	/** Uganda */
	public static final ISO3166_1Alpha2CountryCode UG = new ISO3166_1Alpha2CountryCode("UG");
	
	/** United States Minor Outlying Islands */
	public static final ISO3166_1Alpha2CountryCode UM = new ISO3166_1Alpha2CountryCode("UM");
	
	/** United States of America */
	public static final ISO3166_1Alpha2CountryCode US = new ISO3166_1Alpha2CountryCode("US");
	
	/** Uruguay */
	public static final ISO3166_1Alpha2CountryCode UY = new ISO3166_1Alpha2CountryCode("UY");
	
	/** Uzbekistan */
	public static final ISO3166_1Alpha2CountryCode UZ = new ISO3166_1Alpha2CountryCode("UZ");
	
	/** Holy See */
	public static final ISO3166_1Alpha2CountryCode VA = new ISO3166_1Alpha2CountryCode("VA");
	
	/** Saint Vincent and the Grenadines */
	public static final ISO3166_1Alpha2CountryCode VC = new ISO3166_1Alpha2CountryCode("VC");
	
	/** Venezuela (Bolivarian Republic of) */
	public static final ISO3166_1Alpha2CountryCode VE = new ISO3166_1Alpha2CountryCode("VE");
	
	/** Virgin Islands (British) */
	public static final ISO3166_1Alpha2CountryCode VG = new ISO3166_1Alpha2CountryCode("VG");
	
	/** Virgin Islands (U.S.) */
	public static final ISO3166_1Alpha2CountryCode VI = new ISO3166_1Alpha2CountryCode("VI");
	
	/** Viet Nam */
	public static final ISO3166_1Alpha2CountryCode VN = new ISO3166_1Alpha2CountryCode("VN");
	
	/** Vanuatu */
	public static final ISO3166_1Alpha2CountryCode VU = new ISO3166_1Alpha2CountryCode("VU");
	
	/** Wallis and Futuna */
	public static final ISO3166_1Alpha2CountryCode WF = new ISO3166_1Alpha2CountryCode("WF");
	
	/** Samoa */
	public static final ISO3166_1Alpha2CountryCode WS = new ISO3166_1Alpha2CountryCode("WS");
	
	/** Yemen */
	public static final ISO3166_1Alpha2CountryCode YE = new ISO3166_1Alpha2CountryCode("YE");
	
	/** Mayotte */
	public static final ISO3166_1Alpha2CountryCode YT = new ISO3166_1Alpha2CountryCode("YT");
	
	/** South Africa */
	public static final ISO3166_1Alpha2CountryCode ZA = new ISO3166_1Alpha2CountryCode("ZA");
	
	/** Zambia */
	public static final ISO3166_1Alpha2CountryCode ZM = new ISO3166_1Alpha2CountryCode("ZM");
	
	/** Zimbabwe */
	public static final ISO3166_1Alpha2CountryCode ZW = new ISO3166_1Alpha2CountryCode("ZW");
	
	
	/**
	 * The {@code iso3166_1alpha2-codes.properties} resource.
	 */
	private static final Properties CODES_RESOURCE = new Properties();
	
	
	/**
	 * Creates a new ISO 3166-1 alpha-2 country code. Normalises the code
	 * to upper case.
	 *
	 * @param value The country code value, must be two-letter.
	 */
	public ISO3166_1Alpha2CountryCode(final String value) {
		super(value);
		if (value.length() != 2) {
			throw new IllegalArgumentException("The ISO 3166-1 alpha-2 country code must be 2 letters");
		}
	}
	
	
	/**
	 * Returns the matching alpha-3 country code. See
	 * {@link ISO3166_1AlphaCountryCodeMapper}.
	 *
	 * @return The matching alpha-3 country code, {@code null} if none.
	 */
	public ISO3166_1Alpha3CountryCode toAlpha3CountryCode() {
	
		return ISO3166_1AlphaCountryCodeMapper.toAlpha3CountryCode(this);
	}
	
	
	/**
	 * Returns the country name if available in the
	 * {@code iso3166_1alpha2-codes.properties} resource.
	 *
	 * @return The country name, {@code null} if not available.
	 */
	@Override
	public String getCountryName() {
		
		if (CODES_RESOURCE.isEmpty()) {
			try (InputStream is = getClass().getClassLoader().getResourceAsStream("iso3166_1alpha2-codes.properties")) {
				CODES_RESOURCE.load(is);
			} catch (IOException e) {
				return null;
			}
		}
		
		return CODES_RESOURCE.getProperty(getValue());
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ISO3166_1Alpha2CountryCode &&
			this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an ISO 3166-1 alpha-2 (two-letter) country code.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The ISO 3166-1 alpha-2 (two-letter) country code.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ISO3166_1Alpha2CountryCode parse(final String s)
		throws ParseException {
		
		try {
			return new ISO3166_1Alpha2CountryCode(s);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}
