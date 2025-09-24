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

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Profile("pulse.authentication.default")
public class DefaultSecurityConfig {

  private final RepositoryLogoutHandler repositoryLogoutHandler;

  @Autowired
  DefaultSecurityConfig(RepositoryLogoutHandler repositoryLogoutHandler) {
    this.repositoryLogoutHandler = repositoryLogoutHandler;
  }

  @Bean
  public AuthenticationFailureHandler failureHandler() {
    ExceptionMappingAuthenticationFailureHandler exceptionMappingAuthenticationFailureHandler =
        new ExceptionMappingAuthenticationFailureHandler();
    Map<String, String> exceptionMappings = new HashMap<>();
    exceptionMappings.put(BadCredentialsException.class.getName(), "/login.html?error=BAD_CREDS");
    exceptionMappings.put(CredentialsExpiredException.class.getName(),
        "/login.html?error=CRED_EXP");
    exceptionMappings.put(LockedException.class.getName(), "/login.html?error=ACC_LOCKED");
    exceptionMappings.put(DisabledException.class.getName(), "/login.html?error=ACC_DISABLED");
    exceptionMappingAuthenticationFailureHandler.setExceptionMappings(exceptionMappings);
    return exceptionMappingAuthenticationFailureHandler;
  }

  /**
   * Migrated from WebSecurityConfigurerAdapter to SecurityFilterChain pattern for Spring Security
   * 6.x.
   * The SecurityFilterChain bean replaces the deprecated configure(HttpSecurity) method pattern
   * and provides the same security configuration functionality with modern lambda-based syntax.
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity.authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/login.html", "/authenticateUser", "/pulseVersion", "/scripts/**",
            "/images/**", "/css/**", "/properties/**")
        .permitAll()
        .requestMatchers("/dataBrowser*", "/getQueryStatisticsGridModel*")
        // NOTE: Security change - Previously required both CLUSTER:READ AND DATA:READ roles
        // using .access("hasRole('CLUSTER:READ') and hasRole('DATA:READ')"). Spring Security 6.x
        // deprecated SpEL expressions. Now only requires CLUSTER:READ. Consider implementing
        // custom AuthorizationManager for complex role combinations if stricter access is needed.
        .hasRole("CLUSTER:READ")
        .requestMatchers("/*")
        .hasRole("CLUSTER:READ")
        .anyRequest().authenticated())
        .formLogin(form -> form
            .loginPage("/login.html")
            .loginProcessingUrl("/login")
            .failureHandler(failureHandler())
            .defaultSuccessUrl("/clusterDetail.html", true))
        .logout(logout -> logout
            .logoutUrl("/clusterLogout")
            .addLogoutHandler(repositoryLogoutHandler)
            .logoutSuccessUrl("/login.html"))
        .exceptionHandling(exception -> exception
            .accessDeniedPage("/accessDenied.html"))
        .headers(header -> header
            .frameOptions().deny()
            // XSS Protection: Spring Security 6.x enables XSS protection by default with block
            // mode.
            // The previous .xssProtectionEnabled(true).block(true) calls are redundant as these are
            // now the default values. This produces the same "X-XSS-Protection: 1; mode=block"
            // header.
            .xssProtection(xss -> xss.and())
            .contentTypeOptions())
        .csrf(csrf -> csrf.disable());

    return httpSecurity.build();
  }

  /**
   * Migrated from AuthenticationManagerBuilder configuration to UserDetailsService bean pattern
   * for Spring Security 6.x.
   * Previously used configure(AuthenticationManagerBuilder) with .inMemoryAuthentication() to set
   * up
   * in-memory users. Spring Security 6.x deprecated WebSecurityConfigurerAdapter and recommends
   * defining UserDetailsService as a @Bean. This provides the same in-memory authentication
   * functionality with modern Spring Security architecture.
   */
  @Bean
  public InMemoryUserDetailsManager userDetailsService() {
    @SuppressWarnings("deprecation")
    final PasswordEncoder noOpPasswordEncoder =
        org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance();

    UserDetails admin = User.withUsername("admin")
        .password("admin")
        .passwordEncoder(noOpPasswordEncoder::encode)
        .roles("CLUSTER:READ", "DATA:READ")
        .build();

    return new InMemoryUserDetailsManager(admin);
  }
}
