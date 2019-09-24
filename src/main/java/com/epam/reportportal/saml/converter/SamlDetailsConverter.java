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
package com.epam.reportportal.saml.converter;

import com.epam.reportportal.properties.SamlIntegrationProperties;
import com.epam.ta.reportportal.entity.integration.Integration;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.NameId;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.Optional.ofNullable;

/**
 * Used for mapping between SAML resource model and entity
 *
 * @author Yevgeniy Svalukhin
 */
public class SamlDetailsConverter {

	public final static Function<List<Integration>, List<ExternalIdentityProviderConfiguration>> TO_EXTERNAL_PROVIDER_CONFIG = providers -> {
		List<ExternalIdentityProviderConfiguration> externalProviders = providers.stream()
				.map(integration -> ofNullable(integration.getParams()).flatMap(integrationParams -> ofNullable(integrationParams.getParams())
						.map(params -> {
							ExternalIdentityProviderConfiguration externalIdentityProviderConfiguration = new ExternalIdentityProviderConfiguration();
							SamlIntegrationProperties.IDP_ALIAS.getParam(params).ifPresent(externalIdentityProviderConfiguration::setAlias);
							SamlIntegrationProperties.IDP_METADATA.getParam(params)
									.ifPresent(externalIdentityProviderConfiguration::setMetadata);
							SamlIntegrationProperties.IDP_NAME.getParam(params)
									.ifPresent(externalIdentityProviderConfiguration::setLinktext);
							SamlIntegrationProperties.IDP_NAME_ID.getParam(params)
									.ifPresent(idpNameId -> externalIdentityProviderConfiguration.setNameId(NameId.fromUrn(idpNameId)));
							return externalIdentityProviderConfiguration;
						})))
				.filter(Optional::isPresent)
				.map(Optional::get)
				.collect(Collectors.toList());
		IntStream.range(0, externalProviders.size()).forEach(index -> externalProviders.get(index).setAssertionConsumerServiceIndex(index));
		return externalProviders;
	};
}
