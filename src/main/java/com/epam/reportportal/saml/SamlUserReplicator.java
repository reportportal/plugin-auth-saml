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

import com.epam.reportportal.extension.auth.AbstractUserReplicator;
import com.epam.reportportal.properties.SamlIntegrationProperties;
import com.epam.ta.reportportal.binary.UserDataStoreService;
import com.epam.ta.reportportal.dao.IntegrationRepository;
import com.epam.ta.reportportal.dao.IntegrationTypeRepository;
import com.epam.ta.reportportal.dao.ProjectRepository;
import com.epam.ta.reportportal.dao.UserRepository;
import com.epam.ta.reportportal.entity.integration.Integration;
import com.epam.ta.reportportal.entity.integration.IntegrationParams;
import com.epam.ta.reportportal.entity.integration.IntegrationType;
import com.epam.ta.reportportal.entity.project.Project;
import com.epam.ta.reportportal.entity.user.User;
import com.epam.ta.reportportal.entity.user.UserRole;
import com.epam.ta.reportportal.entity.user.UserType;
import com.epam.ta.reportportal.exception.ReportPortalException;
import com.epam.ta.reportportal.util.PersonalProjectService;
import com.epam.ta.reportportal.ws.model.ErrorType;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.epam.reportportal.config.SamlPlugin.SamlExtension.EMPTY_STRING;
import static com.epam.reportportal.config.SamlPlugin.SamlExtension.SAML_PLUGIN_NAME;
import static com.epam.ta.reportportal.commons.EntityUtils.normalizeId;
import static java.util.Optional.ofNullable;

/**
 * Replicates user from SAML response into database if it is not exist
 *
 * @author Yevgeniy Svalukhin
 */
@Component
public class SamlUserReplicator extends AbstractUserReplicator {

	private final IntegrationTypeRepository integrationTypeRepository;
	private final IntegrationRepository integrationRepository;
	private final TransactionTemplate transactionTemplate;

	public SamlUserReplicator(UserRepository userRepository, ProjectRepository projectRepository,
			PersonalProjectService personalProjectService, UserDataStoreService userDataStoreService,
			IntegrationTypeRepository integrationTypeRepository, IntegrationRepository integrationRepository,
			PlatformTransactionManager transactionManager) {
		super(userRepository, projectRepository, personalProjectService, userDataStoreService);
		this.integrationTypeRepository = integrationTypeRepository;
		this.integrationRepository = integrationRepository;
		this.transactionTemplate = new TransactionTemplate(transactionManager);
	}

	public User replicateUser(ReportPortalSamlAuthentication samlAuthentication) {
		return transactionTemplate.execute(status -> {
			String userName = normalizeId(StringUtils.substringBefore(samlAuthentication.getPrincipal(), "@"));
			Optional<User> userOptional = userRepository.findByLogin(userName);

			if (userOptional.isPresent()) {
				return userOptional.get();
			}

			IntegrationType integrationType = integrationTypeRepository.findByName(SAML_PLUGIN_NAME)
					.orElseThrow(() -> new ReportPortalException(ErrorType.UNABLE_INTERACT_WITH_INTEGRATION, "SAML plugin was not found"));
			List<Integration> integrations = integrationRepository.findAllGlobalByType(integrationType);

			Optional<Integration> samlProvider = integrations.stream()
					.filter(integration -> ofNullable(integration.getParams()).map(IntegrationParams::getParams)
							.map(params -> SamlIntegrationProperties.IDP_URL.getParam(params)
									.map(idpUrl -> idpUrl.equalsIgnoreCase(samlAuthentication.getIssuer()))
									.orElse(Boolean.FALSE))
							.orElse(Boolean.FALSE))
					.findFirst();

			User user = new User();
			user.setLogin(userName);

			List<Attribute> details = samlAuthentication.getDetails();

			if (samlProvider.isPresent()) {
				populateUserDetailsIfSettingsArePresent(user, samlProvider.get().getParams(), details);
			} else {
				populateUserDetails(user, details);
			}

			user.setUserType(UserType.SAML);
			user.setRole(UserRole.USER);
			user.setExpired(false);

			Project project = generatePersonalProject(user);
			user.getProjects().add(project.getUsers().iterator().next());

			user.setMetadata(defaultMetaData());

			userRepository.save(user);

			return user;
		});
	}

	private void populateUserDetails(User user, List<Attribute> details) {
		String email = findAttributeValue(details, UserAttribute.EMAIL.toString(), String.class);
		checkEmail(email);
		user.setEmail(email);

		String firstName = findAttributeValue(details, UserAttribute.FIRST_NAME.toString(), String.class);
		String lastName = findAttributeValue(details, UserAttribute.LAST_NAME.toString(), String.class);
		user.setFullName(String.join(" ", firstName, lastName));
	}

	private void populateUserDetailsIfSettingsArePresent(User user, IntegrationParams providerDetails, List<Attribute> details) {
		String email = findAttributeValue(details,
				SamlIntegrationProperties.EMAIL_ATTRIBUTE_ID.getParam(providerDetails.getParams()).orElse(EMPTY_STRING),
				String.class
		);
		checkEmail(email);
		user.setEmail(email);

		String fullNameAttributeId = SamlIntegrationProperties.FULL_NAME_ATTRIBUTE_ID.getParam(providerDetails.getParams())
				.orElse(EMPTY_STRING);
		if (StringUtils.isEmpty(fullNameAttributeId)) {
			String firstName = findAttributeValue(details,
					SamlIntegrationProperties.FIRST_NAME_ATTRIBUTE_ID.getParam(providerDetails.getParams()).orElse(EMPTY_STRING),
					String.class
			);
			String lastName = findAttributeValue(details,
					SamlIntegrationProperties.LAST_NAME_ATTRIBUTE_ID.getParam(providerDetails.getParams()).orElse(EMPTY_STRING),
					String.class
			);
			user.setFullName(String.join(" ", firstName, lastName));
		} else {
			String fullName = findAttributeValue(details, fullNameAttributeId, String.class);
			user.setFullName(fullName);
		}
	}

	private <T> T findAttributeValue(List<Attribute> attributes, String lookingFor, Class<T> castTo) {
		if (CollectionUtils.isEmpty(attributes)) {
			return null;
		}

		Optional<Attribute> attribute = attributes.stream().filter(it -> it.getName().equalsIgnoreCase(lookingFor)).findFirst();

		if (attribute.isPresent()) {
			List<Object> values = attribute.get().getValues();
			if (!CollectionUtils.isEmpty(values)) {
				List<T> resultList = values.stream().filter(castTo::isInstance).map(castTo::cast).collect(Collectors.toList());
				if (!resultList.isEmpty()) {
					return resultList.get(0);
				}
			}
		}
		return null;
	}
}
