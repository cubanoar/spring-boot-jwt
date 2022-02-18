package com.cubanoar.springboot.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.cubanoar.springboot.app.models.entity.Usuario;

public interface IUsuarioDao extends CrudRepository<Usuario, Long> {

	/*A traves del nombre del metodo( Query method name), 
	 * se ejecutara la consulta JPQL
	 * "SELECT u FROM Usuario u WHERE u.username=?1"
	 * */
	public Usuario findByUsername(String username);
}
