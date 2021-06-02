/**
 * 
 */
package com.renanrramos.embeddedkeycloak.model;

import org.springframework.beans.factory.annotation.Value;

/**
 * @author renan.ramos
 *
 */
public class AdminUser {
	
	@Value("${keycloak.server.admin-user.username}")
	private String username;
	
	@Value("${keycloak.server.admin-user.password}")
	private String password;

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
