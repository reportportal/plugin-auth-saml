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
public enum SamlPluginProperties {

	BASE_PATH("basePath"),
	KEY_ALIAS("keyAlias"),
	KEY_PASSWORD("keyPassword"),
	KEY_STORE("keyStore"),
	KEY_STORE_PASSWORD("keyStorePassword"),
	ACTIVE_KEY_NAME("activeKeyName"),
	NETWORK_CONNECTION_TIMEOUT("networkConnectionTimeout"),
	NETWORK_READ_TIMEOUT("networkReadTimeout"),
	SIGNED_REQUESTS("signedRequests");

	private String name;

	SamlPluginProperties(String name) {
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
