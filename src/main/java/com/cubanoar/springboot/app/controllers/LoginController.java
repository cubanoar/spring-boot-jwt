package com.cubanoar.springboot.app.controllers;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String login(@RequestParam(name = "error", required = false) String error, 
						@RequestParam(name = "logout", required = false) String logout,
						Model model, 
						Principal principal, 
						RedirectAttributes flash) {
		
		if (principal != null) {
			flash.addFlashAttribute("info", "Ya tiene una sesión abierta");
			return "redirect:/";
		}
		
		if (error != null) {
			model.addAttribute("error", "Username o Password incorrectos!!!");
		}

		if (logout != null) {
			model.addAttribute("success", "Sesión cerrada con éxito!!!");
		}
		
		
		return "login";
	}
}
