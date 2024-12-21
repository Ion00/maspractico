from flask import render_template, Blueprint, jsonify, flash, request, redirect, url_for
from flask_login import login_required, current_user
from .odoo import get_active_products_with_images_and_urls, get_website_name, get_total_sales_last_month
from .forms import RegistrationForm, UpdateUserForm  # Importa el formulario creado
from app.models import User
from app.decorators import token_required
from app import bcrypt, db



# Definir un Blueprint para organizar mejor las rutas
main = Blueprint("main", __name__)

@main.route("/new_products")
def new_products():
    # Consultar productos y enviarlos al template
    products = get_active_products_with_images_and_urls(limit=10)
    store = get_website_name()
    return render_template("new_products.html", products=products, store=store)

@main.route('/dashboard')
@token_required
def dashboard(current_user):
    return f"Dashboard protegido - Bienvenido {current_user.correo_e}!"

@main.route("/total_sales")
@login_required
def total_sales():
    # Consultar las ventas totales del último mes
    total_sales = get_total_sales_last_month()
    #return render_template("new_products.html", products=products, store=store)
    return f"Las ventas totales del último mes son {total_sales}!"


# Ruta para listar todos los usuarios
@main.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    users = User.query.all()
    return render_template('list_users.html', users=users)

# Ruta para actualizar un usuario
@main.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        form = UpdateUserForm()

        # Prellenar el formulario si el método es GET
        if request.method == 'GET':
            form.email.data = user.correo_e

        # Procesar el formulario si el método es POST
        if request.method == 'POST' and form.validate_on_submit():
            try:
                user.correo_e = form.email.data

                # Actualizar la contraseña si se proporciona
                password = form.password.data
                if password:
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    user.clave = hashed_password

                # Guardar cambios en la base de datos
                db.session.commit()
                flash('Usuario actualizado correctamente!', 'success')
                return redirect(url_for('main.list_users'))
            except Exception as e:
                db.session.rollback()  # Revertir los cambios si ocurre un error
                flash(f'Error al actualizar el usuario: {str(e)}', 'danger')

        return render_template('update_profile.html', form=form, user=user)

    except KeyError as e:
        flash(f'Dato faltante: {str(e)}', 'danger')
        return redirect(url_for('main.list_users'))
    except AttributeError as e:
        flash(f'Error de atributo: {str(e)}', 'danger')
        return redirect(url_for('main.list_users'))
    except Exception as e:
        # Captura cualquier otro error inesperado
        flash(f'Ocurrió un error inesperado: {str(e)}', 'danger')
        return redirect(url_for('main.list_users'))



# Ruta para eliminar un usuario
@main.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('list_users'))


# Ruta para crear un usuario nuevo
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Crear una instancia del formulario

    if form.validate_on_submit():  # Verificar si el formulario es válido
        try:
            # Llamar al método estático `create_user` del modelo `User`
            User.create_user(email=form.email.data, password=form.password.data)

            flash(f'La cuenta para {form.email.data} fue creada exitosamente.', 'success')
            return redirect(url_for('main.dashboard'))  # Redirigir después del registro
        except ValueError as e:
            flash(str(e), 'danger')  # Mostrar el error al usuario
        except Exception as e:
            flash(f'Ocurrió un error inesperado: {str(e)}', 'danger')

    # Renderizar el formulario en caso de errores o en el primer acceso
    return render_template('register.html', form=form)
