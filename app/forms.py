from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegistrationForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[
        DataRequired(message="El correo electrónico es obligatorio."),
        Email(message="Ingrese un correo electrónico válido.")
    ])
    password = PasswordField('Contraseña', validators=[
        DataRequired(message="La contraseña es obligatoria."),
        Length(min=6, message="La contraseña debe tener al menos 6 caracteres.")
    ])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[
        DataRequired(message="La confirmación de la contraseña es obligatoria."),
        EqualTo('password', message="Las contraseñas deben coincidir.")
    ])
    submit = SubmitField('Registrar')

class UpdateUserForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[
        DataRequired(message="El correo electrónico es obligatorio."),
        Email(message="Ingrese un correo electrónico válido.")
    ])
    password = PasswordField('Contraseña', validators=[
    ])
    submit = SubmitField('Actualizar')
