package com.github.feng111627.springauthaccesscontroljava.config;

import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TimeConfig {

    @Bean
    public TimeSource systemTimeSource() {
        return System::currentTimeMillis;
    }
}
