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
 */
package org.apache.geode.management.internal.rest.security;


import java.io.IOException;
import java.util.Arrays;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;

import org.apache.geode.management.api.ClusterManagementResult;
import org.apache.geode.management.configuration.Links;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
// this package name needs to be different than the admin rest controller's package name
// otherwise this component scan will pick up the admin rest controllers as well.
@ComponentScan("org.apache.geode.management.internal.rest")
public class RestSecurityConfiguration {

  @Autowired
  private GeodeAuthenticationProvider authProvider;

  @Autowired
  private ObjectMapper objectMapper;

  /**
   * Spring Security 6.x requires explicit AuthenticationManager configuration using
   * ProviderManager.
   * This replaces the deprecated AuthenticationManagerBuilder pattern and provides direct control
   * over the authentication provider chain for REST API authentication.
   */
  @Bean
  public AuthenticationManager authenticationManager() {
    return new ProviderManager(authProvider);
  }

  @Bean
  public MultipartResolver multipartResolver() {
    return new StandardServletMultipartResolver() {
      @Override
      public boolean isMultipart(HttpServletRequest request) {
        String method = request.getMethod().toLowerCase();
        // By default, only POST is allowed. Since this is an 'update' we should accept PUT.
        if (!Arrays.asList("put", "post").contains(method)) {
          return false;
        }
        String contentType = request.getContentType();
        return (contentType != null && contentType.toLowerCase().startsWith("multipart/"));
      }
    };
  }

  /**
   * Migrated from WebSecurityConfigurerAdapter to SecurityFilterChain pattern for Spring Security
   * 6.x.
   * The SecurityFilterChain bean replaces the deprecated configure(HttpSecurity) method pattern
   * and provides REST API security configuration with modern lambda-based syntax.
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(
        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/docs/**", "/swagger-ui.html", "/swagger-ui/index.html",
                "/swagger-ui/**",
                "/", Links.URI_VERSION + "/api-docs/**", "/webjars/springdoc-openapi-ui/**",
                "/v3/api-docs/**", "/swagger-resources/**")
            .permitAll())
        .csrf(csrf -> csrf.disable());

    if (authProvider.getSecurityService().isIntegratedSecurity()) {
      http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
      // if auth token is enabled, add a filter to parse the request header. The filter still
      // saves the token in the form of UsernamePasswordAuthenticationToken
      if (authProvider.isAuthTokenEnabled()) {
        JwtAuthenticationFilter tokenEndpointFilter = new JwtAuthenticationFilter();
        tokenEndpointFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
        });
        tokenEndpointFilter.setAuthenticationFailureHandler((request, response, exception) -> {
        });
        http.addFilterBefore(tokenEndpointFilter, BasicAuthenticationFilter.class);
      }
      http.httpBasic(basic -> basic.authenticationEntryPoint(new AuthenticationFailedHandler()));
    }

    return http.build();
  }

  private class AuthenticationFailedHandler implements AuthenticationEntryPoint {
    private static final String CONTENT_TYPE = MediaType.APPLICATION_JSON_VALUE;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException)
        throws IOException, ServletException {
      response.addHeader("WWW-Authenticate", "Basic realm=\"GEODE\"");
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.setContentType(CONTENT_TYPE);
      ClusterManagementResult result =
          new ClusterManagementResult(ClusterManagementResult.StatusCode.UNAUTHENTICATED,
              authException.getMessage());
      objectMapper.writeValue(response.getWriter(), result);
    }
  }
}
