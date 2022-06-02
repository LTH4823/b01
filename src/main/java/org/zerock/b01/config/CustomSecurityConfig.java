package org.zerock.b01.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Log4j2
public class CustomSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("======================================");
        log.info("======================================");
        log.info("=======CustomSecurityConfig ==========");
        log.info("======================================");
        log.info("======================================");
        http.formLogin();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {

        log.info("------------web configure-------------------");
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());

    }


}
