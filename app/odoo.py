from flask import Flask, render_template
from xmlrpc.client import ServerProxy
from datetime import datetime, timedelta
import base64

# Configuración de conexión a Odoo
odoo_url = "https://mypet.help"
db = "mypet"
username = "admin@maspracti.co"
password = "Lc#33f?N!"

common = ServerProxy(f"{odoo_url}/xmlrpc/2/common")
uid = common.authenticate(db, username, password, {})
models = ServerProxy(f"{odoo_url}/xmlrpc/2/object")

# Obtener productos activos, con precio > 0, y publicados en el sitio web
def get_active_products_with_images_and_urls(limit=10):

    # Filtros: activos, precio > 0, publicados en el sitio web
    filters = [
        ['active', '=', True],
        ['list_price', '>', 0],
        ['website_published', '=', True],
    ]
    
    # Consultar productos en Odoo
    products = models.execute_kw(
        db, uid, password,
        'product.product', 'search_read',
        [filters],
        {
            'fields': ['id', 'name', 'list_price', 'image_1920', 'website_url'],  # Campos requeridos
            'limit': limit
        }
    )

    # Generar URL y decodificar imágenes en Base64
    for product in products:
        # Crear slug dinámico
        product_slug = product['name'].replace(" ", "-").lower()
        # URL del producto
        product['url'] = f"{odoo_url}{product['website_url']}"
        # Decodificar imagen
        if product['image_1920']:
            product['image_1920'] = f"data:image/jpeg;base64,{product['image_1920']}"

    return products

# Función para obtener el nombre de la tienda
def get_website_name():
    website = models.execute_kw(
        db, uid, password,
        'website', 'search_read',
        [[]],  # Sin filtros, obtenemos todos los registros de la tienda
        {'fields': ['name']}  # Obtenemos solo el nombre de la tienda
    )

    return website[0]['name']

# Función para obtener las ventas totales del último mes
def get_total_sales_last_month():
    # Fecha de inicio y fin del último mes
    today = datetime.now()
    start_date = (today.replace(day=1) - timedelta(days=1)).replace(day=1).strftime("%Y-%m-%d")
    end_date = today.replace(day=1).strftime("%Y-%m-%d")
    
    # Buscar órdenes de venta confirmadas en el rango de fechas
    sales = models.execute_kw(
        db, uid, password,
        'sale.order', 'search_read',
        [[['state', 'in', ['sale', 'done']],  # Estados confirmados
          ['date_order', '>=', start_date],
          ['date_order', '<', end_date]]],  # Rango de fechas
        {'fields': ['amount_total'], 'limit': 1000}
    )
    
    # Calcular el monto total
    total_sales = sum(order['amount_total'] for order in sales)
    return total_sales
