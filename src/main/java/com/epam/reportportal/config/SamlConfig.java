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
package com.epam.reportportal.config;

import com.epam.reportportal.config.handler.SamlAuthFailureHandler;
import com.epam.reportportal.config.handler.SamlAuthSuccessHandler;
import com.epam.reportportal.extension.auth.TokenServicesFacade;
import com.epam.reportportal.extension.auth.data.BeanData;
import com.epam.reportportal.extension.auth.provider.BeanProvider;
import com.epam.reportportal.saml.SamlUserReplicator;
import com.epam.ta.reportportal.binary.UserDataStoreService;
import com.epam.ta.reportportal.dao.IntegrationRepository;
import com.epam.ta.reportportal.dao.IntegrationTypeRepository;
import com.epam.ta.reportportal.dao.ProjectRepository;
import com.epam.ta.reportportal.dao.UserRepository;
import com.epam.ta.reportportal.util.PersonalProjectService;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.transaction.PlatformTransactionManager;

import javax.servlet.Filter;
import java.util.List;

/**
 * @author <a href="mailto:ivan_budayeu@epam.com">Ivan Budayeu</a>
 */
@Configuration
@ComponentScan("com")
public class SamlConfig implements BeanProvider {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private ProjectRepository projectRepository;

	@Autowired
	private PersonalProjectService personalProjectService;

	@Autowired
	private UserDataStoreService userDataStoreService;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@Autowired
	private IntegrationTypeRepository integrationTypeRepository;

	@Autowired
	private IntegrationRepository integrationRepository;

	@Autowired
	private TokenServicesFacade tokenServicesFacade;

	@Autowired
	private ApplicationEventPublisher eventPublisher;

	@Autowired
	private AuthorizationServerTokenServices tokenServices;

	@Override
	public List<BeanData> getBeansToInitialize() {
		return Lists.newArrayList(new BeanData("samlAuthenticationManager", samlAuthenticationManager()),
				new BeanData("samlCompositeFilter", samlCompositeFilter()),
				new BeanData("samlAuthSuccessHandler", samlAuthSuccessHandler()),
				new BeanData("samlAuthFailureHandler", samlAuthFailureHandler())
		);
	}

	@Bean
	public AuthenticationManager samlAuthenticationManager() {
		return new ReportPortalSamlAuthenticationManager(samlUserReplicator());
	}

	@Bean
	public SamlUserReplicator samlUserReplicator() {
		return new SamlUserReplicator(userRepository,
				projectRepository,
				personalProjectService,
				userDataStoreService,
				integrationTypeRepository,
				integrationRepository,
				transactionManager
		);
	}

	@Bean
	public Filter samlCompositeFilter() {
		return new SamlCompositeFilter();
	}

	@Bean
	public AuthenticationSuccessHandler samlAuthSuccessHandler() {
		return new SamlAuthSuccessHandler(() -> tokenServicesFacade, eventPublisher, tokenServices);
	}

	@Bean
	public AuthenticationFailureHandler samlAuthFailureHandler() {
		return new SamlAuthFailureHandler();
	}
}
