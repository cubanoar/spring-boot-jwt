/*Populate tables*/
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Pepe', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Ana', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Luci', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Barbi', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('JJ', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Alice', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Nora', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Day', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Renu', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('CAstro', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Raul', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('John', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Suco', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('John', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Aghj', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Jyui', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Pert', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Oasd', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Pasd', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Jbnm', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Pert', 'Aguilar', 'pepe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Iasd', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Erg', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Yweb', 'Wick', 'john@gmail.com', '2017-08-28', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES('Uweb', 'Wick', 'john@gmail.com', '2017-08-28', '');

/*Populate tabla productos*/
INSERT INTO productos (nombre,precio,create_at) VALUES('TV Led Samsung',64000,NOW());
INSERT INTO productos (nombre,precio,create_at) VALUES('Airpods',4000,NOW());
INSERT INTO productos (nombre,precio,create_at) VALUES('Bicicleta',36000,NOW());
INSERT INTO productos (nombre,precio,create_at) VALUES('Ps4',50000,NOW());
INSERT INTO productos (nombre,precio,create_at) VALUES('Aire Acondicionado',85000,NOW());
INSERT INTO productos (nombre,precio,create_at) VALUES('Monitor 24',15000,NOW());
INSERT INTO productos (nombre,precio,create_at) VALUES('Protector Linea',1000,NOW());

/*Creamos algunas facturas*/
INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES('Factura equipos de oficina',null, 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 1);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(2, 1, 4);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 5);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 7);

INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES('Factura bicicleta','Viene en caja', 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(3, 2, 6);

/*Usuarios con sus Roles*/
INSERT INTO `users` (username, password, enabled) VALUES ('dasiel','$2a$10$O9wxmH/AeyZZzIS09Wp8YOEMvFnbRVJ8B4dmAMVSGloR62lj.yqXG',1);
INSERT INTO `users` (username, password, enabled) VALUES ('admin','$2a$10$DOMDxjYyfZ/e7RcBfUpzqeaCs8pLgcizuiQWXPkU35nOhZlFcE9MS',1);

INSERT INTO `authorities` (user_id, authority) VALUES (1,'ROLE_USER');
INSERT INTO `authorities` (user_id, authority) VALUES (2,'ROLE_ADMIN');
INSERT INTO `authorities` (user_id, authority) VALUES (2,'ROLE_USER');
