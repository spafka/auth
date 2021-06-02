/**
 *
 */
package com.renanrramos.embeddedkeycloak.properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

import com.renanrramos.embeddedkeycloak.model.AdminUser;

/**
 * @author renan.ramos
 *
 */
@ConfigurationProperties(prefix = "keycloak.server")
public class KeycloakServerProperties {

	@Value("${keycloak.server.context-path}")
	private String contextPath;

	@Value("${keycloak.server.realm-import-file}")
	private String realmImportFile;

	private AdminUser adminUser;

	public KeycloakServerProperties() {
		this.adminUser = new AdminUser();
	}

	public String getContextPath() {
		return contextPath;
	}

	public String getRealmImportFile() {
		return realmImportFile;
	}

	public AdminUser getAdminUser() {
		return adminUser;
	}

	public void setContextPath(String contextPath) {
		this.contextPath = contextPath;
	}

	public void setRealmImportFile(String realmImportFile) {
		this.realmImportFile = realmImportFile;
	}

	public void setAdminUser(AdminUser adminUser) {
		this.adminUser = adminUser;
	}
}
