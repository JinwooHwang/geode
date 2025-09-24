/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.apache.geode.management.api;

import static org.apache.geode.management.configuration.Links.URI_VERSION;
import static org.apache.geode.management.rest.internal.Constants.INCLUDE_CLASS_HEADER;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;

import org.apache.geode.annotations.Experimental;
import org.apache.geode.management.configuration.AbstractConfiguration;
import org.apache.geode.management.configuration.HasFile;
import org.apache.geode.management.rest.internal.exception.RestTemplateResponseErrorHandler;
import org.apache.geode.management.runtime.OperationResult;
import org.apache.geode.management.runtime.RuntimeInfo;
import org.apache.geode.util.internal.GeodeJsonMapper;

/**
 * Concrete implementation of {@link ClusterManagementServiceTransport} which uses Spring's
 * {@link RestTemplate} for communication between client and CMS endpoint.
 */
@Experimental
public class RestTemplateClusterManagementServiceTransport
    implements ClusterManagementServiceTransport {

  static final ResponseErrorHandler DEFAULT_ERROR_HANDLER =
      new RestTemplateResponseErrorHandler();

  private final RestTemplate restTemplate;

  private final ScheduledExecutorService longRunningStatusPollingThreadPool =
      Executors.newScheduledThreadPool(1);

  public RestTemplateClusterManagementServiceTransport(RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
    this.restTemplate.setErrorHandler(DEFAULT_ERROR_HANDLER);

    // configur the rest template to use a speciic jackson converter
    List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
    MappingJackson2HttpMessageConverter jackson2HttpMessageConverter = messageConverters.stream()
        .filter(MappingJackson2HttpMessageConverter.class::isInstance)
        .map(MappingJackson2HttpMessageConverter.class::cast)
        .findFirst().orElse(null);

    if (jackson2HttpMessageConverter == null) {
      jackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
      messageConverters.add(jackson2HttpMessageConverter);
    }

    jackson2HttpMessageConverter.setPrettyPrint(false);
    // the client should use a mapper that would ignore unknown properties in case the server
    // is a newer version than the client
    jackson2HttpMessageConverter
        .setObjectMapper(GeodeJsonMapper.getMapperIgnoringUnknownProperties());
    // if we don't set the default charset here, the request will use ServletRequest's default
    // charset which may not be UTF-8
    jackson2HttpMessageConverter.setDefaultCharset(StandardCharsets.UTF_8);
  }

  public RestTemplateClusterManagementServiceTransport(
      ConnectionConfig connectionConfig) {
    this(new RestTemplate(), connectionConfig);
  }

  public RestTemplateClusterManagementServiceTransport(RestTemplate restTemplate,
      ConnectionConfig connectionConfig) {
    this(restTemplate);
    configureConnection(connectionConfig);
  }

  public void configureConnection(ConnectionConfig connectionConfig) {
    if (connectionConfig == null) {
      throw new IllegalStateException(
          "ConnectionConfig cannot be null. Please use setConnectionConfig()");
    }

    if (connectionConfig.getHost() == null || connectionConfig.getPort() <= 0) {
      throw new IllegalArgumentException(
          "host and port needs to be specified in order to build the service.");
    }

    String schema = (connectionConfig.getSslContext() == null) ? "http" : "https";

    DefaultUriBuilderFactory uriBuilderFactory = new DefaultUriBuilderFactory(
        schema + "://" + connectionConfig.getHost() + ":" + connectionConfig.getPort()
            + "/management");

    restTemplate.setUriTemplateHandler(uriBuilderFactory);

    // HttpComponentsClientHttpRequestFactory allows us to preconfigure httpClient for
    // authentication and ssl context (migrated to HttpClient 5.x)
    // Migration from HttpClient 4.x to 5.x involved updating package names (org.apache.http.* to
    // org.apache.hc.*),
    // changing SSL and connection management API, and updating authentication configuration
    // patterns.
    HttpComponentsClientHttpRequestFactory requestFactory =
        new HttpComponentsClientHttpRequestFactory();

    HttpClientBuilder clientBuilder = HttpClientBuilder.create();

    // Note: LaxRedirectStrategy class was removed in HttpClient 5.x migration
    // Configure SSL context and connection manager
    // HttpClient 5.x replaced org.apache.http.conn.ssl.SSLConnectionSocketFactory
    // with org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory and updated the connection
    // manager API. Previously, SSL context and hostname verifier were set directly on the client
    // builder via setSSLContext() and setSSLHostnameVerifier(). Now they are configured together
    // through the SSLConnectionSocketFactory and connection manager pattern.
    if (connectionConfig.getSslContext() != null
        || connectionConfig.getHostnameVerifier() != null) {
      SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
          connectionConfig.getSslContext() != null ? connectionConfig.getSslContext()
              : org.apache.hc.core5.ssl.SSLContexts.createDefault(),
          connectionConfig.getHostnameVerifier() != null ? connectionConfig.getHostnameVerifier()
              : new DefaultHostnameVerifier());

      HttpClientConnectionManager connectionManager =
          PoolingHttpClientConnectionManagerBuilder.create()
              .setSSLSocketFactory(sslSocketFactory)
              .build();
      clientBuilder.setConnectionManager(connectionManager);
    }

    // Configure authentication
    // HttpClient 5.x updated authentication API from org.apache.http.auth.* to
    // org.apache.hc.client5.http.auth.*
    // UsernamePasswordCredentials now uses char[] for password instead of String for better
    // security
    if (connectionConfig.getAuthToken() != null) {
      Header authHeader =
          new BasicHeader(HttpHeaders.AUTHORIZATION, "Bearer " + connectionConfig.getAuthToken());
      clientBuilder.setDefaultHeaders(List.of(authHeader));
    } else if (connectionConfig.getUsername() != null) {
      BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
      credsProvider.setCredentials(
          new AuthScope(connectionConfig.getHost(), connectionConfig.getPort()),
          new UsernamePasswordCredentials(connectionConfig.getUsername(),
              connectionConfig.getPassword().toCharArray()));
      clientBuilder.setDefaultCredentialsProvider(credsProvider);
    }

    // Note: HttpClient 5.x handles redirects differently and follows them by default
    // In HttpClient 4.x, redirects were disabled by default and required explicit configuration:
    // if (connectionConfig.getFollowRedirects()) {
    // clientBuilder.setRedirectStrategy(new LaxRedirectStrategy());
    // }
    // LaxRedirectStrategy was removed in HttpClient 5.x as redirects are now enabled by default.
    // In HttpClient 5.x, redirects are enabled by default and LaxRedirectStrategy was removed.
    // The followRedirects configuration is now managed through the HttpClientBuilder
    if (!connectionConfig.getFollowRedirects()) {
      clientBuilder.disableRedirectHandling();
    }

    requestFactory.setHttpClient(clientBuilder.build());
    restTemplate.setRequestFactory(requestFactory);
  }

  @Override
  public <T extends AbstractConfiguration<?>> ClusterManagementRealizationResult submitMessage(
      T configMessage, CommandType command) {
    switch (command) {
      case CREATE:
        return create(configMessage, HttpMethod.POST);
      case CREATE_OR_UPDATE:
        return create(configMessage, HttpMethod.PUT);
      case DELETE:
        return delete(configMessage);
    }

    throw new IllegalArgumentException("Unable to process command " + command
        + ". Perhaps you need to use a different method in ClusterManagementServiceTransport.");
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T extends AbstractConfiguration<R>, R extends RuntimeInfo> ClusterManagementGetResult<T, R> submitMessageForGet(
      T config) {
    return restTemplate.exchange(getIdentityEndpoint(config), HttpMethod.GET, makeEntity(config),
        ClusterManagementGetResult.class).getBody();
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T extends AbstractConfiguration<R>, R extends RuntimeInfo> ClusterManagementListResult<T, R> submitMessageForList(
      T config) {
    String endPoint = URI_VERSION + config.getLinks().getList();
    return restTemplate
        .exchange(endPoint + "?id={id}&group={group}", HttpMethod.GET, makeEntity(config),
            ClusterManagementListResult.class, config.getId(), config.getGroup())
        .getBody();
  }

  @Override
  @SuppressWarnings("unchecked")
  public <A extends ClusterManagementOperation<V>, V extends OperationResult> ClusterManagementListOperationsResult<A, V> submitMessageForListOperation(
      A opType) {
    return restTemplate.exchange(URI_VERSION + opType.getEndpoint(), HttpMethod.GET,
        makeEntity(null), ClusterManagementListOperationsResult.class).getBody();
  }

  @Override
  @SuppressWarnings("unchecked")
  public <A extends ClusterManagementOperation<V>, V extends OperationResult> ClusterManagementOperationResult<A, V> submitMessageForGetOperation(
      A op, String operationId) {
    String uri = URI_VERSION + op.getEndpoint() + "/" + operationId;
    return restTemplate
        .exchange(uri, HttpMethod.GET, makeEntity(null), ClusterManagementOperationResult.class)
        .getBody();
  }

  @Override
  @SuppressWarnings("unchecked")
  public <A extends ClusterManagementOperation<V>, V extends OperationResult> ClusterManagementOperationResult<A, V> submitMessageForStart(
      A op) {
    return restTemplate.exchange(URI_VERSION + op.getEndpoint(), HttpMethod.POST, makeEntity(op),
        ClusterManagementOperationResult.class).getBody();
  }

  @Override
  public boolean isConnected() {
    try {
      return "pong"
          .equals(restTemplate.getForEntity(URI_VERSION + "/ping", String.class).getBody());
    } catch (RestClientException e) {
      return false;
    }
  }

  @Override
  public void close() {
    longRunningStatusPollingThreadPool.shutdownNow();
  }

  private <T extends AbstractConfiguration<?>> ClusterManagementRealizationResult create(T config,
      HttpMethod method) {
    String endPoint = URI_VERSION + config.getLinks().getList();
    // the response status code info is represented by the ClusterManagementResult.errorCode already
    return restTemplate.exchange(endPoint, method, makeEntity(config),
        ClusterManagementRealizationResult.class)
        .getBody();
  }

  private <T extends AbstractConfiguration<?>> ClusterManagementRealizationResult delete(T config) {
    String uri = getIdentityEndpoint(config);
    return restTemplate.exchange(uri + "?group={group}",
        HttpMethod.DELETE,
        makeEntity(null),
        ClusterManagementRealizationResult.class,
        config.getGroup())
        .getBody();
  }

  private static <T> HttpEntity<?> makeEntity(T config) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(INCLUDE_CLASS_HEADER, "true");
    if (config instanceof HasFile) {
      MultiValueMap<String, Object> content = new LinkedMultiValueMap<>();
      File file = ((HasFile) config).getFile();
      if (file != null) {
        content.add(HasFile.FILE_PARAM, new FileSystemResource(file));
        content.add(HasFile.CONFIG_PARAM, config);
        return new HttpEntity<>(content, headers);
      }
    }
    return new HttpEntity<>(config, headers);
  }

  private static String getIdentityEndpoint(AbstractConfiguration<?> config) {
    String uri = config.getLinks().getSelf();
    if (uri == null) {
      throw new IllegalArgumentException(
          "Unable to construct the URI with the current configuration.");
    }
    return URI_VERSION + uri;
  }
}
