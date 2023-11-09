package com.example.demo.MyFilter;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<RequestForwardFilter> requestForwardFilterRegistration() {
        FilterRegistrationBean<RequestForwardFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RequestForwardFilter());
        registration.addUrlPatterns("/*");
        registration.setName("requestForwardFilter");
        registration.setOrder(1);
        return registration;
    }
}
