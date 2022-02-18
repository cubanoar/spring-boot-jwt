package com.cubanoar.springboot.app.view.pdf;

import java.awt.Color;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.document.AbstractPdfView;

import com.cubanoar.springboot.app.models.entity.Factura;
import com.cubanoar.springboot.app.models.entity.ItemFactura;
import com.lowagie.text.Document;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;


@Component("factura/ver")
public class FacturaPdfView extends AbstractPdfView{

	@Override
	protected void buildPdfDocument(Map<String, Object> model, Document document, PdfWriter writer,
			HttpServletRequest request, HttpServletResponse response) throws Exception {
		// Obtenemos del model la factura, debe ser el mismo nombre que en el controlador
		Factura factura = (Factura) model.get("factura");
		
		//Creando las tablas
		PdfPTable tabla = new PdfPTable(1);//le pasamos la cantidad de columnas
		
		PdfPCell cell = null;
		cell = new PdfPCell(new Phrase("Datos del cliente"));
		cell.setBackgroundColor(new Color(184,218,255));
		cell.setPadding(6);
		tabla.addCell(cell);
		
		tabla.addCell(factura.getCliente().getNombre() + " " + factura.getCliente().getApellido());
		tabla.addCell(factura.getCliente().getEmail());
		tabla.setSpacingAfter(20);//Para dar espacio despues de la tabla
		
		document.add(tabla);
		
		PdfPTable tabla2 = new PdfPTable(1);
		cell = new PdfPCell(new Phrase("Datos de la Factura"));
		cell.setBackgroundColor(new Color(195,230,203));
		cell.setPadding(6);
		tabla2.addCell(cell);
		
		tabla2.addCell("Folio: "  + factura.getId());
		tabla2.addCell("Decripición: " + factura.getDescripcion());
		tabla2.addCell("Fecha: " + factura.getCreateAt());
		tabla2.setSpacingAfter(20);
		
		//Añadiendo las tablas
		document.add(tabla2);
		
		PdfPTable tabla3 = new PdfPTable(4);
		//tabla3.setWidthPercentage(100);
		/*le pasamos las medidas de cada columna*/
		tabla3.setWidths(new float [] {3f, 1, 1, 1});
		tabla3.addCell("Producto");
		tabla3.addCell("Precio");
		tabla3.addCell("Cantidad");
		tabla3.addCell("Total");
		
		for (ItemFactura item : factura.getItems()) {
			tabla3.addCell(item.getProducto().getNombre());
			tabla3.addCell(item.getProducto().getPrecio().toString());
			
			cell = new PdfPCell(new Phrase(item.getCantidad().toString()));
			cell.setHorizontalAlignment(PdfPCell.ALIGN_CENTER);
			
			tabla3.addCell(cell);
			tabla3.addCell(item.calcularImporte().toString());
		}
		
		cell = new PdfPCell(new Phrase("Total: "));
		cell.setColspan(3);
		cell.setHorizontalAlignment(PdfPCell.ALIGN_RIGHT);
		tabla3.addCell(cell);
		tabla3.addCell(factura.getTotal().toString());
		
		document.add(tabla3);
		
	}

}
