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

import com.epam.reportportal.extension.PluginCommand;
import com.epam.reportportal.extension.auth.AuthExtension;
import com.epam.reportportal.extension.auth.data.BeanProviderData;
import com.epam.reportportal.extension.auth.info.AuthProviderInfo;
import com.epam.reportportal.extension.auth.info.CompositeInfoContributor;
import com.epam.reportportal.extension.common.IntegrationTypeProperties;
import com.epam.reportportal.extension.event.IntegrationEvent;
import com.epam.reportportal.properties.SamlIntegrationProperties;
import com.epam.reportportal.properties.SamlPluginProperties;
import com.epam.reportportal.saml.SamlProviderInfo;
import com.epam.reportportal.saml.converter.SamlDetailsConverter;
import com.epam.reportportal.util.CertificationUtil;
import com.epam.ta.reportportal.dao.IntegrationRepository;
import com.epam.ta.reportportal.dao.IntegrationTypeRepository;
import com.epam.ta.reportportal.entity.integration.Integration;
import com.epam.ta.reportportal.entity.integration.IntegrationParams;
import com.epam.ta.reportportal.entity.integration.IntegrationType;
import com.epam.ta.reportportal.entity.integration.IntegrationTypeDetails;
import com.epam.ta.reportportal.exception.ReportPortalException;
import com.epam.ta.reportportal.ws.model.ErrorType;
import com.google.common.base.Suppliers;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.opensaml.saml.saml2.core.NameID;
import org.pf4j.Extension;
import org.pf4j.Plugin;
import org.pf4j.PluginWrapper;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.info.Info;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml.SamlKeyException;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.NetworkConfiguration;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.service.authentication.SamlAuthenticationResponseFilter;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;
import org.springframework.security.saml.spi.SamlKeyStoreProvider;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.security.saml.util.X509Utilities;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.annotation.PostConstruct;
import javax.inject.Provider;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getEncoder;
import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromContextPath;

/**
 * @author <a href="mailto:ivan_budayeu@epam.com">Ivan Budayeu</a>
 */
public class SamlPlugin extends Plugin {
	/**
	 * Constructor to be used by plugin manager for plugin instantiation.
	 * Your plugins have to provide constructor with this exact signature to
	 * be successfully loaded by manager.
	 *
	 * @param wrapper
	 */
	public SamlPlugin(PluginWrapper wrapper) {
		super(wrapper);
	}

	@Override
	public void start() {

	}

	@Override
	public void stop() {

	}

	@Extension(ordinal = 1)
	@Component
	public static class SamlExtension extends SamlServiceProviderServerBeanConfiguration implements AuthExtension, DisposableBean {

		public static final String SAML_PLUGIN_NAME = "saml";
		public static final String EMPTY_STRING = "";

		private static final String SAML_BUTTON = "<span>Login with SAML</span>";
		private static final Integer DEFAULT_NETWORK_CONNECT_TIMEOUT = 5000;
		private static final Integer DEFAULT_NETWORK_READ_TIMEOUT = 10000;

		@Override
		public List<BeanProviderData> getBeanProviders() {
			return Lists.newArrayList(new BeanProviderData("samlConfig", SamlConfig.class));
		}

		@Override
		public List<String> getCommandNames() {
			return Collections.emptyList();
		}

		@Override
		public PluginCommand getCommandToExecute(String commandName) {
			return (integration, params) -> EMPTY_STRING;
		}

		@Override
		public void destroy() {
			ApplicationEventMulticaster applicationEventMulticaster = applicationContext.getBean(AbstractApplicationContext.APPLICATION_EVENT_MULTICASTER_BEAN_NAME,
					ApplicationEventMulticaster.class
			);
			applicationEventMulticaster.removeApplicationListener(samlProviderReloadListener);

			FilterChainProxy filterChainProxy = (FilterChainProxy) springSecurityFilterChain;
			List<Filter> filters = filterChainProxy.getFilters("/");
			filters.removeIf(f -> SamlCompositeFilter.class.isAssignableFrom(f.getClass()));
			compositeInfoContributor.getReportPortalInfoContributors().remove(SAML_PLUGIN_NAME);
		}

		private String basePath = "http://localhost:9999";

		private String keyAlias = "report-portal-sp";

		private String keyPassword = "password";

		private String keyStore = "/saml/keystore.jks";

		private String keyStorePassword = "password";

		private String activeKeyName = "sp-signing-key";

		private Integer networkConnectTimeout = DEFAULT_NETWORK_CONNECT_TIMEOUT;

		private Integer networkReadTimeout = DEFAULT_NETWORK_READ_TIMEOUT;

		private Boolean signedRequests = true;

		public SamlExtension(Map<String, Object> initParams) {
			keyStore = "file://" + IntegrationTypeProperties.RESOURCES_DIRECTORY.getValue(initParams).orElse(EMPTY_STRING) + keyStore;
			SamlPluginProperties.BASE_PATH.getParam(initParams).ifPresent(basePath -> this.basePath = basePath);
			SamlPluginProperties.KEY_ALIAS.getParam(initParams).ifPresent(keyAlias -> this.keyAlias = keyAlias);
			SamlPluginProperties.KEY_PASSWORD.getParam(initParams).ifPresent(keyPassword -> this.keyPassword = keyPassword);
			SamlPluginProperties.KEY_STORE.getParam(initParams).ifPresent(keyStore -> this.keyStore = keyPassword);
			SamlPluginProperties.KEY_STORE_PASSWORD.getParam(initParams)
					.ifPresent(keyStorePassword -> this.keyStorePassword = keyStorePassword);
			SamlPluginProperties.ACTIVE_KEY_NAME.getParam(initParams).ifPresent(activeKeyName -> this.activeKeyName = activeKeyName);
			SamlPluginProperties.NETWORK_CONNECTION_TIMEOUT.getParam(initParams)
					.ifPresent(networkConnectTimeout -> this.networkConnectTimeout = NumberUtils.toInt(networkConnectTimeout,
							DEFAULT_NETWORK_CONNECT_TIMEOUT
					));
			SamlPluginProperties.NETWORK_READ_TIMEOUT.getParam(initParams)
					.ifPresent(networkReadTimeout -> this.networkReadTimeout = NumberUtils.toInt(networkReadTimeout,
							DEFAULT_NETWORK_READ_TIMEOUT
					));
			SamlPluginProperties.SIGNED_REQUESTS.getParam(initParams)
					.ifPresent(signedRequests -> this.signedRequests = BooleanUtils.toBoolean(signedRequests));

		}

		@Autowired
		private ApplicationContext applicationContext;

		@Autowired
		private Provider<HttpServletRequest> httpServletRequest;

		@Autowired
		private IntegrationRepository integrationRepository;

		@Autowired
		private IntegrationTypeRepository integrationTypeRepository;

		@Autowired
		private AuthenticationManager samlAuthenticationManager;

		@Autowired
		private AuthenticationSuccessHandler samlAuthSuccessHandler;

		@Autowired
		private AuthenticationFailureHandler samlAuthFailureHandler;

		@Autowired
		@Qualifier("springSecurityFilterChain")
		private Filter springSecurityFilterChain;

		@Autowired
		@Qualifier("samlCompositeFilter")
		private Filter samlCompositeFilter;

		@Autowired
		private CompositeInfoContributor compositeInfoContributor;

		private final ApplicationListener<IntegrationEvent> samlProviderReloadListener = new SamlProvidersReloadEventHandler();

		private final Supplier<SamlServerConfiguration> samlServerConfigurationSupplier = Suppliers.memoize(() -> new SamlServerConfiguration()
				.setServiceProvider(serviceProviderConfiguration())
				.setNetwork(networkConfiguration()));

		private final Supplier<Filter> spAuthenticationResponseFilterSupplier = Suppliers.memoize(() -> {
			SamlAuthenticationResponseFilter authenticationFilter = new SamlAuthenticationResponseFilter(getSamlProvisioning());
			authenticationFilter.setAuthenticationManager(samlAuthenticationManager);
			authenticationFilter.setAuthenticationSuccessHandler(samlAuthSuccessHandler);
			authenticationFilter.setAuthenticationFailureHandler(samlAuthFailureHandler);
			return authenticationFilter;
		});

		private final Supplier<SpringSecuritySaml> springSecuritySamlSupplier = Suppliers.memoize(() -> {
			OpenSamlImplementation implementation = new OpenSamlImplementation(samlTime()).init();
			implementation.setSamlKeyStoreProvider(samlKeyStoreProvider());
			return implementation;
		});

		private class SamlProvidersReloadEventHandler implements ApplicationListener<IntegrationEvent> {

			@Override
			public void onApplicationEvent(IntegrationEvent event) {
				if (supports(event)) {
					LocalServiceProviderConfiguration serviceProvider = samlServerConfigurationSupplier.get().getServiceProvider();
					serviceProvider.getProviders().clear();

					integrationTypeRepository.findByName(SAML_PLUGIN_NAME).ifPresent(integrationType -> {
						List<Integration> integrations = integrationRepository.findAllGlobalByType(integrationType);
						serviceProvider.getProviders().addAll(SamlDetailsConverter.TO_EXTERNAL_PROVIDER_CONFIG.apply(integrations));
					});
				}
			}

			private boolean supports(IntegrationEvent event) {
				return SAML_PLUGIN_NAME.equals(event.getIntegrationTypeName());
			}
		}

		@Override
		protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
			return samlServerConfigurationSupplier.get();
		}

		@Override
		public Filter spAuthenticationResponseFilter() {
			return spAuthenticationResponseFilterSupplier.get();
		}

		@Override
		public SpringSecuritySaml samlImplementation() {
			return springSecuritySamlSupplier.get();
		}

		private LocalServiceProviderConfiguration serviceProviderConfiguration() {
			LocalServiceProviderConfiguration serviceProviderConfiguration = new LocalServiceProviderConfiguration();
			serviceProviderConfiguration.setSignRequests(signedRequests)
					.setWantAssertionsSigned(signedRequests)
					.setEntityId("report.portal.sp.id")
					.setAlias("report-portal-sp")
					.setSignMetadata(signedRequests)
					.setSingleLogoutEnabled(true)
					.setNameIds(Arrays.asList(NameID.EMAIL, NameID.PERSISTENT, NameID.UNSPECIFIED))
					.setKeys(rotatingKeys())
					.setProviders(providers())
					.setPrefix("saml/sp")
					.setBasePath(basePath);
			return serviceProviderConfiguration;
		}

		private NetworkConfiguration networkConfiguration() {
			return new NetworkConfiguration().setConnectTimeout(networkConnectTimeout).setReadTimeout(networkReadTimeout);
		}

		private List<ExternalIdentityProviderConfiguration> providers() {

			List<ExternalIdentityProviderConfiguration> providers = integrationTypeRepository.findByName(SAML_PLUGIN_NAME)
					.map(integrationType -> {
						List<Integration> samlIntegrations = integrationRepository.findAllGlobalByType(integrationType);
						return SamlDetailsConverter.TO_EXTERNAL_PROVIDER_CONFIG.apply(samlIntegrations);
					})
					.orElseGet(Collections::emptyList);

			if (CollectionUtils.isEmpty(providers)) {
				return new CopyOnWriteArrayList<>();
			}

			return new CopyOnWriteArrayList<>(providers);
		}

		private RotatingKeys rotatingKeys() {
			return new RotatingKeys().setActive(activeKey()).setStandBy(standbyKeys());
		}

		private List<SimpleKey> standbyKeys() {
			return Collections.emptyList();
		}

		private SimpleKey activeKey() {
			if (signedRequests) {
				X509Certificate certificate = CertificationUtil.getCertificateByName(keyAlias, keyStore, keyStorePassword);
				PrivateKey privateKey = CertificationUtil.getPrivateKey(keyAlias, keyPassword, keyStore, keyStorePassword);

				try {
					return new SimpleKey().setCertificate(getEncoder().encodeToString(certificate.getEncoded()))
							.setPassphrase(keyPassword)
							.setPrivateKey(getEncoder().encodeToString(privateKey.getEncoded()))
							.setName(activeKeyName);
				} catch (CertificateEncodingException e) {
					e.printStackTrace();
				}
			}
			return new SimpleKey();
		}

		private SamlKeyStoreProvider samlKeyStoreProvider() {
			return new SamlKeyStoreProvider() {
				@Override
				public KeyStore getKeyStore(SimpleKey key) {
					try {
						KeyStore ks = KeyStore.getInstance("JKS");
						ks.load(null, DEFAULT_KS_PASSWD);

						byte[] certbytes = X509Utilities.getDER(key.getCertificate());
						Certificate certificate = X509Utilities.getCertificate(certbytes);
						ks.setCertificateEntry(key.getName(), certificate);

						if (hasText(key.getPrivateKey())) {

							RSAPrivateKey privateKey = X509Utilities.getPrivateKey(Base64.getDecoder().decode(key.getPrivateKey()), "RSA");

							ks.setKeyEntry(key.getName(), privateKey, key.getPassphrase().toCharArray(), new Certificate[] { certificate });
						}

						return ks;
					} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException | IOException e) {
						throw new SamlKeyException(e);
					}
				}
			};
		}

		@PostConstruct
		public void init() {
			initBasePath();
			initIntegrationEventListener();
			initFilterChain();
			initInfoContributor();
		}

		private void initBasePath() {
			IntegrationType integrationType = integrationTypeRepository.findByName(SAML_PLUGIN_NAME)
					.orElseThrow(() -> new ReportPortalException(ErrorType.UNABLE_INTERACT_WITH_INTEGRATION, "SAML plugin was not found"));
			IntegrationTypeDetails integrationTypeDetails = ofNullable(integrationType.getDetails()).orElseGet(() -> {
				IntegrationTypeDetails details = new IntegrationTypeDetails();
				integrationType.setDetails(details);
				return details;
			});
			Map<String, Object> detailsMap = ofNullable(integrationTypeDetails.getDetails()).orElseGet(() -> {
				Map<String, Object> details = Maps.newHashMap();
				integrationTypeDetails.setDetails(details);
				return details;
			});

			basePath = SamlPluginProperties.BASE_PATH.getParam(detailsMap).orElseGet(() -> {
				UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(
						httpServletRequest.get())).replacePath(EMPTY_STRING);
				String[] urlPaths = StringUtils.substringAfter(httpServletRequest.get().getRequestURI(), "/").split("/");
				if (urlPaths.length > 1) {
					uriComponentsBuilder.replacePath(urlPaths[0]);
				}
				String basePath = uriComponentsBuilder.build().toUri().toString();
				detailsMap.put(SamlPluginProperties.BASE_PATH.getName(), basePath);
				return basePath;
			});
		}

		private void initIntegrationEventListener() {
			ApplicationEventMulticaster applicationEventMulticaster = applicationContext.getBean(AbstractApplicationContext.APPLICATION_EVENT_MULTICASTER_BEAN_NAME,
					ApplicationEventMulticaster.class
			);
			applicationEventMulticaster.addApplicationListener(samlProviderReloadListener);
		}

		private void initFilterChain() {
			FilterChainProxy filterChainProxy = (FilterChainProxy) springSecurityFilterChain;
			List<Filter> filters = filterChainProxy.getFilters("/");
			int samlFilterIndex = IntStream.range(0, filters.size()).filter(i -> {
				Filter filter = filters.get(i);
				return BasicAuthenticationFilter.class.equals(filter.getClass());
			}).map(i -> i + 1).findFirst().orElse(Math.min(4, filters.size()));
			((SamlCompositeFilter) samlCompositeFilter).setFilters(samlFilters());
			filters.add(samlFilterIndex, samlCompositeFilter);
		}

		private void initInfoContributor() {
			ofNullable(httpServletRequest.get()).ifPresent(request -> {
				compositeInfoContributor.addInfoContributor(SAML_PLUGIN_NAME, builder -> {

					Map<String, String> samlProviders = integrationTypeRepository.findByName(SAML_PLUGIN_NAME)
							.map(integrationType -> integrationRepository.findAllGlobalByType(integrationType)
									.stream()
									.filter(Integration::isEnabled)
									.map(Integration::getParams)
									.filter(Objects::nonNull)
									.map(IntegrationParams::getParams)
									.filter(Objects::nonNull)
									.collect((Supplier<HashMap<String, String>>) HashMap::new, (map, integrationParams) -> {
										String idpName = SamlIntegrationProperties.IDP_NAME.getParam(integrationParams)
												.orElse(EMPTY_STRING);
										String idpUrl = SamlIntegrationProperties.IDP_URL.getParam(integrationParams)
												.map(url -> fromContextPath(httpServletRequest.get()).path(String.format(
														"/saml/sp/discovery?idp=%s",
														UriUtils.encode(url, UTF_8.toString())
												)).build().getPath())
												.orElse(EMPTY_STRING);
										map.put(idpName, idpUrl);
									}, HashMap::putAll))
							.orElseGet(Maps::newHashMap);

					Info info = builder.build();
					Map<String, Object> infoDetails = Maps.newLinkedHashMap(info.getDetails());
					if (!CollectionUtils.isEmpty(samlProviders)) {
						Map<String, AuthProviderInfo> authExtensions = (Map<String, AuthProviderInfo>) ofNullable(infoDetails.get(
								"authExtensions")).orElseGet(() -> {
							Map<Object, Object> extensions = Maps.newHashMap();
							infoDetails.put("authExtensions", extensions);
							return extensions;
						});
						authExtensions.put("samlProviders", new SamlProviderInfo(SAML_BUTTON, samlProviders));
						builder.withDetails(infoDetails);
					}

				});
			});
		}

		private List<Filter> samlFilters() {
			return Lists.newArrayList(this.samlConfigurationFilter(),
					this.spMetadataFilter(),
					this.spAuthenticationRequestFilter(),
					this.spAuthenticationResponseFilter(),
					this.spSamlLogoutFilter(),
					this.spSelectIdentityProviderFilter()
			);
		}

	}
}
