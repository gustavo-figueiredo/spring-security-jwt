package com.example.spring.security.jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {
    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> {
                    headers.frameOptions(frame -> {
                        frame.disable();
                    });
                })
                .authorizeHttpRequests(
                        authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                                .requestMatchers("/").permitAll()
                                .requestMatchers("/h2-console/**").permitAll()
                                .requestMatchers(HttpMethod.POST,"/login").permitAll()
                                .requestMatchers(HttpMethod.POST,"/users").permitAll()
                                .requestMatchers("/admins").hasAnyRole("ADMIN")
                                .requestMatchers(HttpMethod.GET,"/users").hasAnyRole("USERS", "MANAGERS")
                                .anyRequest().authenticated())
                                .sessionManagement(session -> {
                                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                                })
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

}

/*
 * 
 * 
 * 
 * @Configuration
 * 
 * @EnableWebSecurity
 * 
 * @EnableGlobalMethodSecurity(prePostEnabled = true)
 * public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
 * 
 * @Bean
 * public BCryptPasswordEncoder encoder(){
 * return new BCryptPasswordEncoder();
 * }
 * 
 * private static final String[] SWAGGER_WHITELIST = {
 * "/v2/api-docs",
 * "/swagger-resources",
 * "/swagger-resources/**",
 * "/configuration/ui",
 * "/configuration/security",
 * "/swagger-ui.html",
 * "/webjars/**"
 * };
 * 
 * @Override
 * protected void configure(HttpSecurity http) throws Exception {
 * http.headers().frameOptions().disable();
 * http.cors().and().csrf().disable()
 * .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
 * .authorizeRequests()
 * .antMatchers(SWAGGER_WHITELIST).permitAll()
 * .antMatchers("/h2-console/**").permitAll()
 * .antMatchers(HttpMethod.POST,"/login").permitAll()
 * .antMatchers(HttpMethod.POST,"/users").permitAll()
 * .antMatchers(HttpMethod.GET,"/users").hasAnyRole("USERS","MANAGERS")
 * .antMatchers("/managers").hasAnyRole("MANAGERS")
 * .anyRequest().authenticated()
 * .and()
 * .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
 * }
 * 
 * @Bean //HABILITANDO ACESSAR O H2-DATABSE NA WEB
 * public ServletRegistrationBean h2servletRegistration(){
 * ServletRegistrationBean registrationBean = new ServletRegistrationBean( new
 * WebServlet());
 * registrationBean.addUrlMappings("/h2-console/*");
 * return registrationBean;
 * }
 * }
 */