/**
 *
 */
package com.renanrramos.embeddedkeycloak.model.common;

/**
 * @author renan.ramos
 *
 */
public enum UserType {

	ADMINISTRATOR("administrator"),
	COMPANY("company"),
	CUSTOMER("customer");

	UserType(String type) {
		// Intentionally empty
	}

}
