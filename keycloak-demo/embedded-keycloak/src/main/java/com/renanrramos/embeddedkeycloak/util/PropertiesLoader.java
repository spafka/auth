package com.renanrramos.embeddedkeycloak.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * @author renan.ramos
 *
 */
public class PropertiesLoader {

	private static final Logger LOG = LoggerFactory.getLogger(PropertiesLoader.class);

	private static final String RESOURCE_FILE_NAME = "application.properties";

	private static Properties config = new Properties();

	public static Properties loadProperties() {
		Resource applicationProperties = new ClassPathResource(RESOURCE_FILE_NAME);
		LOG.info("Application properties file path: {}", applicationProperties.getFilename());
		try {
			InputStream input = applicationProperties.getInputStream();
			LOG.info("InputStream available: {}", input.available());
			config.load(input);
			input.close();
		} catch (IOException e) {
			LOG.info("Can't read file: {} --> {}", RESOURCE_FILE_NAME, e.getMessage());
		}
		return config;
	}

	private PropertiesLoader() {
		// Intentionally empty
	}

	public static String getUserProperty(Properties config, String propName) {
		return Optional.ofNullable(config.getProperty(propName)).orElse("");
	}
}
