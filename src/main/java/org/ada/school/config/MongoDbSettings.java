package org.ada.school.config;

import com.mongodb.MongoClientOptions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/8/2022
 * @project user-api
 */
@Configuration
public class MongoDbSettings {

    @Bean
    public MongoClientOptions mongoOptions() {
        return MongoClientOptions
                .builder()
                .maxConnectionIdleTime(60000)
                .build();
    }

}