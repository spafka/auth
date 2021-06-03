package io.springboot.oauth2.web.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping(value = { "/", "/index" })
public class IndexController {

	@GetMapping
	public ModelAndView index(HttpServletRequest request) {
		
		HttpSession session = request.getSession(false);
		Object attr = null;
		if (session == null || (attr = session.getAttribute("user")) == null ) {
			// 未登录
			return new ModelAndView("redirect:/login");
		}
		
		ModelAndView modelAndView = new ModelAndView("index/index");
		modelAndView.addObject("user", attr);
		return modelAndView;
	}
}
