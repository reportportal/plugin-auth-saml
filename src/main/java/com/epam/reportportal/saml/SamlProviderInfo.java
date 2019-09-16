package com.epam.reportportal.saml;

import com.epam.reportportal.extension.auth.AuthProviderInfo;

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