/*
 * Copyright 2019 EPAM Systems
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.epam.reportportal.properties;

import com.epam.ta.reportportal.entity.integration.IntegrationParams;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * @author <a href="mailto:ivan_budayeu@epam.com">Ivan Budayeu</a>
 */
public enum SamlIntegrationProperties {

	/**
	 * Name of IDP displayed on login page
	 */
	IDP_NAME("idpName"),

	/**
	 * URL for getting IDP metadata information
	 */
	IDP_METADATA("idpMetadata"),

	/**
	 * Attribute Name Format Id associated with IDP for user identification and extracted from metadata
	 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
	 * Page 82, Line 3528
	 */
	IDP_NAME_ID("idpNameId"),

	/**
	 * Alias associated with IDP extracted from metadata
	 */
	IDP_ALIAS("idpAlias"),

	/**
	 * URL of IDP extracted from metadata
	 */
	IDP_URL("idpUrl"),

	/**
	 * Name of attribute used for extracting full name from SAML response
	 */
	FULL_NAME_ATTRIBUTE_ID("fullNameAttributeId"),

	/**
	 * Name of attribute used for extracting first name from SAML response
	 */
	FIRST_NAME_ATTRIBUTE_ID("firstNameAttributeId"),

	/**
	 * Name of attribute used for extracting last name from SAML response
	 */
	LAST_NAME_ATTRIBUTE_ID("firstNameAttributeId"),

	/**
	 * Name of attribute used for extracting email from SAML response
	 */
	EMAIL_ATTRIBUTE_ID("firstNameAttributeId");

	private String name;

	SamlIntegrationProperties(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public Optional<String> getParam(Map<String, Object> params) {
		return Optional.ofNullable(params.get(this.name)).map(String::valueOf);
	}

	public void setParam(IntegrationParams params, String value) {
		if (null == params.getParams()) {
			params.setParams(new HashMap<>());
		}
		params.getParams().put(this.name, value);
	}
}
