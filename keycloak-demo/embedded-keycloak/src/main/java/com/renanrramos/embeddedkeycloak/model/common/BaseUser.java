/**
 *
 */
package com.renanrramos.embeddedkeycloak.model.common;

import static com.renanrramos.embeddedkeycloak.util.KeycloakPropertyConstants.EMAIL_PROPERTY;
import static com.renanrramos.embeddedkeycloak.util.KeycloakPropertyConstants.FIRST_NAME_PROPERTY;
import static com.renanrramos.embeddedkeycloak.util.KeycloakPropertyConstants.LAST_NAME_PROPERTY;
import static com.renanrramos.embeddedkeycloak.util.KeycloakPropertyConstants.PASSWORD_PROPERTY;
import static com.renanrramos.embeddedkeycloak.util.KeycloakPropertyConstants.ROLE_PROPERTY;
import static com.renanrramos.embeddedkeycloak.util.KeycloakPropertyConstants.USERNAME_PROPERTY;

import java.util.Properties;

import com.renanrramos.embeddedkeycloak.util.PropertiesLoader;

/**
 * @author renan.ramos
 * @param <T>
 *
 */
public class BaseUser {

	private String firstName;

	private String lastName;

	private String username;

	private String password;

	private String email;

	private String role;

	private Properties config;

	public BaseUser() {
		this.config = PropertiesLoader.loadProperties();
	}

	public String getFirstName() {
		return firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public String getEmail() {
		return email;
	}

	public String getRole() {
		return role;
	}

	public BaseUser withFirstName(String firstName) {
		this.firstName = firstName;
		return this;
	}

	public BaseUser withLastName(String lastName) {
		this.lastName = lastName;
		return this;
	}

	public BaseUser withUsername(String username) {
		this.username = username;
		return this;
	}

	public BaseUser withPassword(String password) {
		this.password = password;
		return this;
	}

	public BaseUser withEmail(String email) {
		this.email = email;
		return this;
	}

	public BaseUser withRole(String role) {
		this.role = role;
		return this;
	}

	public BaseUser getInstance(UserType userType) {
		return new BaseUser()
				.withEmail(
						PropertiesLoader.getUserProperty(this.config, EMAIL_PROPERTY + userType.name().toLowerCase()))
				.withFirstName(PropertiesLoader.getUserProperty(this.config,
						FIRST_NAME_PROPERTY + userType.name().toLowerCase()))
				.withLastName(PropertiesLoader.getUserProperty(this.config,
						LAST_NAME_PROPERTY + userType.name().toLowerCase()))
				.withPassword(PropertiesLoader.getUserProperty(this.config,
						PASSWORD_PROPERTY + userType.name().toLowerCase()))
				.withRole(PropertiesLoader.getUserProperty(this.config, ROLE_PROPERTY + userType.name().toLowerCase()))
				.withUsername(PropertiesLoader.getUserProperty(this.config,
						USERNAME_PROPERTY + userType.name().toLowerCase()));
	}

	@Override
	public String toString() {
		return "BaseUser [firstName=" + firstName + ", lastName=" + lastName + ", username=" + username + ", password="
				+ password + ", email=" + email + ", role=" + role + "]";
	}
}
