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
package org.apache.geode.rest.internal.web.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import org.apache.geode.management.configuration.Links;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ComponentScan("org.apache.geode.rest.internal.web")
public class RestSecurityConfiguration {

  @Autowired
  private GeodeAuthenticationProvider authProvider;

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
                Links.URI_VERSION + "/api-docs/**", "/webjars/springdoc-openapi-ui/**",
                "/v3/api-docs/**", "/swagger-resources/**")
            .permitAll())
        .csrf(csrf -> csrf.disable());

    if (authProvider.getSecurityService().isIntegratedSecurity()) {
      http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
          .httpBasic(httpBasic -> {
          });
    }

    return http.build();
  }
}
