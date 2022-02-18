package com.cubanoar.springboot.app.controllers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.cubanoar.springboot.app.models.entity.Cliente;
import com.cubanoar.springboot.app.models.service.IClienteService;
import com.cubanoar.springboot.app.models.service.IUploadFileService;
import com.cubanoar.springboot.app.util.paginator.PageRender;

@Controller
@SessionAttributes("cliente")
public class ClienteController {

	protected final Log logger = LogFactory.getLog(this.getClass());
	
	@Autowired
	private IClienteService clienteService;
	
	@Autowired
	private IUploadFileService uploadFileService;
	
	/*@Secured("ROLE_USER")Tambien podemos usar @PreAuthorized es lo mismo*/
	/*Para validar mas de un ROLE @Secured({"ROLE_USER", "ROLE_ADMIN"})*/
	@PreAuthorize("hasRole('ROLE_USER')")
	@GetMapping("/uploads/{filename:.+}")
	public ResponseEntity<Resource> verFoto(@PathVariable String filename){
		
		Resource recurso = null;
		try {
			recurso = uploadFileService.load(filename);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		
		return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\""+ recurso.getFilename() +"\"")
				.body(recurso);
	}
	
	@Secured("ROLE_USER")
	@GetMapping("/ver/{id}")
	public String ver(@PathVariable Long id, Model model , RedirectAttributes flash) {
		
		Cliente cliente = clienteService.fetchByIdWithFacturas(id);
		if (cliente==null) {
			flash.addFlashAttribute("error", "El cliente no existe");
			return "redirect:/listar";
		}
		model.addAttribute("cliente", cliente);
		model.addAttribute("titulo", "Cliente: " + cliente.getNombre() + " " + cliente.getApellido());
		
		return "ver";
	}
	
	/*Metodo que va a responder en formato json*/
	@GetMapping("/listar-rest")
	public @ResponseBody List<Cliente> listarRest(){
		return clienteService.findAll();
	}
	
	@GetMapping({"/listar","/"})
	public String listar(@RequestParam(name="page", defaultValue = "0") int page,
							Model model, 
							Authentication authentication,/*Tambien lo podemos obtener de forma static para obtenerlo en cualquier parte de la aplicacion*/
							HttpServletRequest request) {
		/*Forma Antigua
		Pageable pageRequest = new PageRequest(page, size);*/
		
		//podemos pasarle el nombre del usuario autenticado a la vista, entre otras cosas
		if (authentication != null) {
			logger.info("Hola " + authentication.getName());
		}
		/*Forma static mencionada arriba para validar el ROLE*/
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			logger.info("De forma estatica con SecurityContextHolder.getContext().getAuthentication() - Hola desde auth. forma");
		}
		if(hasRole("ROLE_ADMIN")) {
			logger.info("Hola ".concat(auth.getName()).concat(" tienes acceso!"));
		}else {
			logger.info("Hola ".concat(auth.getName()).concat(" NO tienes acceso!"));
		}
		
		//Otra Forma 2 de valiar el ROLE
		SecurityContextHolderAwareRequestWrapper securityContext = new SecurityContextHolderAwareRequestWrapper(request, "");
		if (securityContext.isUserInRole("ROLE_ADMIN")) {
			logger.info("Forma con SecurityContextHolderAwareRequestWrapper - Hola ".concat(auth.getName()).concat(" tienes acceso!"));
		}else {
			logger.info("Forma con SecurityContextHolderAwareRequestWrapper - Hola ".concat(auth.getName()).concat(" NO tienes acceso!"));
		}
		
		//Otra Forma 3 de validar el ROLE
		if (request.isUserInRole("ROLE_ADMIN")) {
			logger.info("Forma con HttpServletRequest - Hola ".concat(auth.getName()).concat(" tienes acceso!"));
		}else {
			logger.info("Forma con HttpServletRequest - Hola ".concat(auth.getName()).concat(" NO tienes acceso!"));
		}
		
		Pageable pageRequest = PageRequest.of(page, 5);
		
		Page<Cliente> clientes = clienteService.findAll(pageRequest);
		
		PageRender<Cliente> pageRender = new PageRender<>("/listar", clientes);
		model.addAttribute("titulo", "Listado de clientes");
		model.addAttribute("clientes", clientes);
		model.addAttribute("page", pageRender);
		return "listar";
	}
	
	@Secured("ROLE_ADMIN")
	@GetMapping("/form")
	public String crear(Model model) {
		
		Cliente cliente = new Cliente();
		model.addAttribute("cliente", cliente);
		
		model.addAttribute("titulo", "Formulario de clientes");
		return "form";
	}
	
	/*@Secured("ROLE_ADMIN")Tambien podemos usar @PreAuthorized*/
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@GetMapping("/form/{id}")
	public String editar(@PathVariable Long id, RedirectAttributes flash, Model model) {
		Cliente cliente = null;
		
		if (id > 0) {
			cliente = clienteService.findOne(id);
			if (cliente == null) {
				flash.addFlashAttribute("error", "El id del cliente no existe en la BBDD!");
				return "redirect:/listar";
			}
		}else {
			flash.addFlashAttribute("error", "El id del cliente no puede ser 0!");
			return "redirect:/listar";
		}
		
		model.addAttribute("titulo", "Editar Cliente");
		model.addAttribute("cliente", cliente);
		return "form";		
	}

	@Secured("ROLE_ADMIN")
	@PostMapping("/form")
	public String guardar(@Valid Cliente cliente, BindingResult result, Model model, @RequestParam("file") MultipartFile foto,RedirectAttributes flash,SessionStatus status) {
		
		if(result.hasErrors()) {
			model.addAttribute("titulo", "Formulario de clientes");
			return "form";
		}
		
		if (!foto.isEmpty()) {
			
			if (cliente.getId() != null
					&& cliente.getId() > 0
					&& cliente.getFoto() != null
					&& cliente.getFoto().length() > 0) {
				
				uploadFileService.delete(cliente.getFoto());
				
				}
				
			 String uniqueFilename = null;
			try {
				uniqueFilename = uploadFileService.copy(foto);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			 flash.addFlashAttribute("info", "'" + uniqueFilename + "'" + " subido correctamente");
			
			 cliente.setFoto(uniqueFilename);
		}
		
		String mensajeFlash = (cliente.getId() != null)? "Cliente editado con éxito" : "Cliente creado con éxito";
		
		clienteService.save(cliente);
		status.setComplete();//elimina el objeto cliente de la sesion
		flash.addFlashAttribute("success", mensajeFlash);
		return "redirect:/listar";
	}
	
	@Secured("ROLE_ADMIN")
	@GetMapping("/eliminar/{id}")
	public String eliminar(@PathVariable Long id, RedirectAttributes flash) {
		if (id > 0) {
			Cliente cliente = clienteService.findOne(id);
			
			clienteService.delete(id);
			flash.addFlashAttribute("success", "Cliente eliminado con exito");
			
			
				if (uploadFileService.delete(cliente.getFoto())) {
					flash.addFlashAttribute("info", "Foto " + cliente.getFoto() + " eliminada con éxito");
				}
		}
		return "redirect:/listar";
	}
	
	private boolean hasRole(String role) {
		
		SecurityContext context = SecurityContextHolder.getContext();
		
		if (context == null) {
			return false;
		}
		
		Authentication auth = context.getAuthentication();
		
		if (auth == null) {
			return false;
		}
		
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
		
		return authorities.contains(new SimpleGrantedAuthority(role));
		
		/*
		 * for (GrantedAuthority authority : authorities) { if
		 * (role.equals(authority.getAuthority())) {
		 * logger.info("Hola usuario ".concat(auth.getName())
		 * .concat(" tu role es: ".concat(authority.getAuthority()))); return true; } }
		 * 
		 * return false;
		 */
	}
}
