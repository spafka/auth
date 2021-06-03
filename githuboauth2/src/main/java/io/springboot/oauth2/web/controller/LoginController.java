package io.springboot.oauth2.web.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/login")
public class LoginController {
	
	@Value("${oauth.github.app-id}")
	private String appId;
	
	@GetMapping
	public ModelAndView login () {
		ModelAndView modelAndView = new ModelAndView("login/login");
		modelAndView.addObject("appId", this.appId);
		return modelAndView;
	}
}
