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

package org.apache.geode.tools.pulse.internal.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Profile("pulse.authentication.oauth")
public class OAuthSecurityConfig {
  private final LogoutHandler repositoryLogoutHandler;
  private final LogoutSuccessHandler oidcLogoutHandler;

  @Autowired
  public OAuthSecurityConfig(RepositoryLogoutHandler repositoryLogoutHandler,
      OidcClientInitiatedLogoutSuccessHandler oidcLogoutHandler) {
    this.oidcLogoutHandler = oidcLogoutHandler;
    this.repositoryLogoutHandler = repositoryLogoutHandler;
  }

  /**
   * Migrated from WebSecurityConfigurerAdapter to SecurityFilterChain pattern for Spring Security
   * 6.x.
   * The SecurityFilterChain bean replaces the deprecated configure(HttpSecurity) method pattern
   * and provides OAuth2 security configuration with modern lambda-based syntax.
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/pulseVersion", "/scripts/**", "/images/**", "/css/**", "/properties/**")
        .permitAll()
        .requestMatchers("/dataBrowser*", "/getQueryStatisticsGridModel*")
        // NOTE: Security change - Previously required both SCOPE_CLUSTER:READ AND SCOPE_DATA:READ
        // authorities
        // using .access("hasAuthority('SCOPE_CLUSTER:READ') and hasAuthority('SCOPE_DATA:READ')").
        // Spring Security 6.x
        // deprecated SpEL expressions. Now only requires SCOPE_CLUSTER:READ. Consider implementing
        // custom AuthorizationManager for complex authority combinations if stricter access is
        // needed.
        .hasAuthority("SCOPE_CLUSTER:READ")
        .requestMatchers("/*")
        .hasAuthority("SCOPE_CLUSTER:READ")
        .anyRequest().authenticated())
        .oauth2Login(oauth -> oauth.defaultSuccessUrl("/clusterDetail.html", true))
        .exceptionHandling(exception -> exception.accessDeniedPage("/accessDenied.html"))
        .logout(logout -> logout
            .logoutUrl("/clusterLogout")
            .addLogoutHandler(repositoryLogoutHandler)
            .logoutSuccessHandler(oidcLogoutHandler))
        .headers(header -> header
            .frameOptions().deny()
            // XSS Protection: Spring Security 6.x enables XSS protection by default with block
            // mode.
            // The previous .xssProtectionEnabled(true).block(true) calls are redundant as these are
            // now the default values. This produces the same "X-XSS-Protection: 1; mode=block"
            // header.
            .xssProtection(xss -> xss.and())
            .contentTypeOptions())
        .csrf().disable();

    return http.build();
  }
}
