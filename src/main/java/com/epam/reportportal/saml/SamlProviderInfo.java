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

package com.epam.reportportal.saml;

import com.epam.reportportal.extension.auth.info.AuthProviderInfo;

import java.util.Map;

/**
 * @author <a href="mailto:ivan_budayeu@epam.com">Ivan Budayeu</a>
 */
public class SamlProviderInfo extends AuthProviderInfo {
	private Map<String, String> providers;

	public SamlProviderInfo(String button, Map<String, String> providers) {
		super(button);
		this.providers = providers;
	}

	public Map<String, String> getProviders() {
		return providers;
	}

	public void setProviders(Map<String, String> providers) {
		this.providers = providers;
	}
}