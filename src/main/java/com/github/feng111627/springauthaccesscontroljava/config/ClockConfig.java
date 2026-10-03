package com.github.feng111627.springauthaccesscontroljava.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClockConfig {

    @Bean
    public MutableClock authClock() {
        return new MutableClock();
    }
}
