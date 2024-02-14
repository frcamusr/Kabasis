from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser, Empresa, Area  # Importa tu modelo personalizado


from django.shortcuts import render, redirect,  get_object_or_404
from django.views.generic import View
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required

from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

from django.contrib.auth.password_validation import password_validators_help_text_html


##Formulario creación de usuarios personalizados
class CustomUserCreationForm(UserCreationForm):

    tipo_usuario = forms.ChoiceField(
        choices=CustomUser.TIPO_USUARIO_CHOICES,
        label="Tipo de Usuario",
        required=True,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    profile_picture = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control-file'}),
        label="Imagen de Perfil"
    )

    razon_social = forms.ModelChoiceField(
        queryset=Empresa.objects.none(),
        label="Razón social",
        required=False,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    area = forms.ModelChoiceField(
        queryset=Area.objects.none(),
        label="Área",
        required=False,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('current_user', None)
        super(CustomUserCreationForm, self).__init__(*args, **kwargs)

        # Establecer y bloquear el tipo de usuario en 'Alumno'
        self.fields['tipo_usuario'].initial = 'Alumno'
        self.fields['tipo_usuario'].disabled = True

        # Filtrar las opciones de área según la empresa del usuario
        if user and user.empresa:
            self.fields['area'].queryset = Area.objects.filter(empresa=user.empresa)

        # Configurar el campo de empresa
        if user and user.tipo_usuario == 'Administrador Kabasis':
            self.fields['razon_social'].queryset = Empresa.objects.all()
        elif user and user.empresa:
            self.fields['razon_social'].queryset = Empresa.objects.filter(id=user.empresa.id)
            self.fields['razon_social'].initial = user.empresa
            self.fields['razon_social'].disabled = True  # Opcional: deshabilitar el campo para que no se pueda cambiar

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'tipo_usuario', 'first_name', 'last_name', 'profile_picture', 'password1', 'password2']


##Formulario creación de usuarios personalizados tipo asistente
class CustomUserAsistenteCreationForm(UserCreationForm):

    tipo_usuario = forms.ChoiceField(
        choices=CustomUser.TIPO_USUARIO_CHOICES,
        label="Tipo de Usuario",
        required=True,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    profile_picture = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control-file'}),
        label="Imagen de Perfil"
    )

    razon_social = forms.ModelChoiceField(
        queryset=Empresa.objects.none(),
        label="Razón social",
        required=False,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    area = forms.ModelChoiceField(
        queryset=Area.objects.none(),
        label="Área",
        required=False,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('current_user', None)
        super(CustomUserAsistenteCreationForm, self).__init__(*args, **kwargs)

        # Establecer y bloquear el tipo de usuario en 'Asistente Administrativo'
        self.fields['tipo_usuario'].initial = 'Asistente Administrativo'
        self.fields['tipo_usuario'].disabled = True

        # Filtrar las opciones de área según la empresa del usuario
        if user and user.empresa:
            self.fields['area'].queryset = Area.objects.filter(empresa=user.empresa)

        # Configurar el campo de empresa
        if user and user.tipo_usuario == 'Administrador Kabasis':
            self.fields['razon_social'].queryset = Empresa.objects.all()
        elif user and user.empresa:
            self.fields['razon_social'].queryset = Empresa.objects.filter(id=user.empresa.id)
            self.fields['razon_social'].initial = user.empresa
            self.fields['razon_social'].disabled = True  # Opcional: deshabilitar el campo para que no se pueda cambiar

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'tipo_usuario', 'first_name', 'last_name', 'profile_picture', 'password1', 'password2']


##Formulario creación de usuarios personalizados
class CustomUserAdministradorCreationForm(UserCreationForm):

    tipo_usuario = forms.ChoiceField(
        choices=CustomUser.TIPO_USUARIO_CHOICES,
        label="Tipo de Usuario",
        required=True,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    profile_picture = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control-file'}),
        label="Imagen de Perfil"
    )

    razon_social = forms.ModelChoiceField(
        queryset=Empresa.objects.none(),
        label="Razón social",
        required=False,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    area = forms.ModelChoiceField(
        queryset=Area.objects.none(),
        label="Área",
        required=False,
        widget=forms.Select(attrs={'class': 'custom-select'}),
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('current_user', None)
        super(CustomUserAdministradorCreationForm, self).__init__(*args, **kwargs)

        # Establecer y bloquear el tipo de usuario en 'Administrador'
        self.fields['tipo_usuario'].initial = 'Administrador'
        self.fields['tipo_usuario'].disabled = True

        # Filtrar las opciones de área según la empresa del usuario
        if user and user.empresa:
            self.fields['area'].queryset = Area.objects.filter(empresa=user.empresa)

        # Configurar el campo de empresa
        if user and user.tipo_usuario == 'Administrador Kabasis':
            self.fields['razon_social'].queryset = Empresa.objects.all()
        elif user and user.empresa:
            self.fields['razon_social'].queryset = Empresa.objects.filter(id=user.empresa.id)
            self.fields['razon_social'].initial = user.empresa
            self.fields['razon_social'].disabled = True  # Opcional: deshabilitar el campo para que no se pueda cambiar

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'tipo_usuario', 'first_name', 'last_name', 'profile_picture', 'password1', 'password2']

##tarjeta ver perfil##

from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password

User = get_user_model()

class UserProfileForm(forms.ModelForm):
    current_password = forms.CharField(widget=forms.PasswordInput(), required=False, label="Contraseña Actual")
    new_password = forms.CharField(widget=forms.PasswordInput(), required=False, label="Nueva Contraseña")
    confirm_password = forms.CharField(widget=forms.PasswordInput(), required=False, label="Confirmar Nueva Contraseña")

    class Meta:
        model = User
        fields = ['username', 'profile_picture', 'first_name', 'last_name', 'current_password', 'new_password', 'confirm_password']

    def __init__(self, *args, **kwargs):
        super(UserProfileForm, self).__init__(*args, **kwargs)
        self.fields['new_password'].help_text = password_validators_help_text_html()

    def clean(self):
        cleaned_data = super().clean()
        current_password = cleaned_data.get("current_password")
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and new_password != confirm_password:
            self.add_error('confirm_password', "Las nuevas contraseñas no coinciden.")

        if current_password:
            if not check_password(current_password, self.instance.password):
                self.add_error('current_password', "La contraseña actual no es correcta.")
            elif not new_password:
                self.add_error('new_password', "Debe introducir una nueva contraseña.")
        
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        new_password = self.cleaned_data.get("new_password")
        if new_password:
            user.set_password(new_password)
        if commit:
            user.save()
        return user


##formulario crear empresa
from django import forms



##formulario Áreas


from django.db import IntegrityError
from .models import Area

class AreaForm(forms.Form):
    nombres = forms.CharField(
        label='Nombres de áreas',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingrese nombres de áreas separados por comas'
        })
    )

    def save(self, user, commit=True):
        nombres_areas = [nombre.strip().capitalize() for nombre in self.cleaned_data['nombres'].split(',')]
        areas_creadas = []
        for nombre in nombres_areas:
            if nombre:
                area, created = Area.objects.get_or_create(nombre=nombre, defaults={'empresa': user.empresa})
                if not created:
                    # Si el área ya existía y no está asignada a ninguna empresa, la asignamos.
                    # Si el área ya estaba asignada a otra empresa, puedes decidir si actualizarla o no.
                    if area.empresa is None:
                        area.empresa = user.empresa
                        area.save()
                areas_creadas.append(area)
        return areas_creadas
    

class AreaFormInicio(forms.Form):
    nombres = forms.CharField(
        label='Nombres de áreas',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingrese nombres de áreas separados por comas'
        })
    )

    def save(self, user, commit=True):
        nombres_areas = [nombre.strip().capitalize() for nombre in self.cleaned_data['nombres'].split(',')]
        areas_creadas = []
        for nombre in nombres_areas:
            if nombre:
                area, created = Area.objects.get_or_create(nombre=nombre, defaults={'empresa': user.empresa})
                if not created:
                    # Si el área ya existía y no está asignada a ninguna empresa, la asignamos.
                    # Si el área ya estaba asignada a otra empresa, puedes decidir si actualizarla o no.
                    if area.empresa is None:
                        area.empresa = user.empresa
                        area.save()
                areas_creadas.append(area)
        return areas_creadas


class CSVUploadForm(forms.Form):
    archivo_csv = forms.FileField()

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super(CSVUploadForm, self).__init__(*args, **kwargs)
        if user and user.empresa:
            self.fields['area'] = forms.ModelChoiceField(
                queryset=Area.objects.filter(empresa=user.empresa),
                required=False,
                empty_label="Seleccione el Área"
            )



class CustomUserUpdateForm(forms.ModelForm):
    razon_social = forms.CharField(required=False)  # Campo existente para el nombre de la empresa
    area = forms.ModelChoiceField(
        queryset=Area.objects.none(),  # Inicialmente el queryset está vacío
        required=False,
        label="Área"
    )

    password1 = forms.CharField(
        label='Nueva Contraseña', 
        widget=forms.PasswordInput, 
        required=False
    )
    password2 = forms.CharField(
        label='Confirmar Nueva Contraseña', 
        widget=forms.PasswordInput, 
        required=False
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'first_name', 'last_name', 'profile_picture', 'razon_social', 'area', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        current_user = kwargs.pop('current_user', None)
        super(CustomUserUpdateForm, self).__init__(*args, **kwargs)

        # Configurar el valor inicial para nombre_empresa y area si existen
        if self.instance and self.instance.empresa:
            self.fields['razon_social'].initial = self.instance.empresa.razon_social
            self.fields['area'].queryset = Area.objects.filter(empresa=self.instance.empresa)  # Cambio aquí
            if self.instance.area:
                self.fields['area'].initial = self.instance.area

        # Restringir la edición del campo nombre_empresa si el usuario actual no es 'Administrador Kabasis'
        if current_user and current_user.tipo_usuario != 'Administrador Kabasis':
            self.fields['razon_social'].disabled = True

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Las contraseñas no coinciden")
        return password2

    def save(self, commit=True):
        user = super(CustomUserUpdateForm, self).save(commit=False)
        
        # Actualizar la empresa relacionada si es necesario
        social_razon = self.cleaned_data.get('razon_social')
        if social_razon:
            empresa, created = Empresa.objects.get_or_create(razon_social=social_razon)
            user.empresa = empresa

        # Actualizar el área relacionada
        area_seleccionada = self.cleaned_data.get('area')
        if area_seleccionada:
            user.area = area_seleccionada

         # Actualiza la contraseña si se proporcionó una nueva
        password = self.cleaned_data.get('password1')
        if password:
            user.set_password(password)

        if commit:
            user.save()

        return user

    

#formulario editar usuario
class CustomUserAsistenteUpdateForm(forms.ModelForm):
    razon_social = forms.CharField(required=False, disabled=True)  # Campo deshabilitado para el nombre de la empresa
    area = forms.ModelChoiceField(
        queryset=Area.objects.none(),  # Inicialmente el queryset está vacío
        required=False,
        label="Área"
    )

    password1 = forms.CharField(
        label='Nueva Contraseña', 
        widget=forms.PasswordInput, 
        required=False
    )
    password2 = forms.CharField(
        label='Confirmar Nueva Contraseña', 
        widget=forms.PasswordInput, 
        required=False
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'first_name', 'last_name', 'profile_picture', 'razon_social', 'area', 'password1', 'password2']


    def __init__(self, *args, **kwargs):
        current_user = kwargs.pop('current_user', None)
        super(CustomUserAsistenteUpdateForm, self).__init__(*args, **kwargs)

        # Configurar el valor inicial para nombre_empresa y area si existen
        if self.instance and self.instance.empresa:
            self.fields['razon_social'].initial = self.instance.empresa.razon_social
            self.fields['area'].queryset = Area.objects.filter(empresas_asociadas=self.instance.empresa)
            if self.instance.area:
                self.fields['area'].initial = self.instance.area

        # Restringir la edición del campo nombre_empresa si el usuario actual no es 'Administrador Kabasis'
        if current_user and current_user.tipo_usuario != 'Administrador Kabasis':
            self.fields['razon_social'].disabled = True

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Las contraseñas no coinciden")
        return password2

    def save(self, commit=True):
        user = super(CustomUserAsistenteUpdateForm, self).save(commit=False)
        
        # Actualizar la empresa relacionada si es necesario
        social_razon = self.cleaned_data.get('razon_social')
        if social_razon:
            empresa, created = Empresa.objects.get_or_create(razon_social=social_razon)
            user.empresa = empresa

        # Actualizar el área relacionada
        area_seleccionada = self.cleaned_data.get('area')
        if area_seleccionada:
            user.area = area_seleccionada

         # Actualiza la contraseña si se proporcionó una nueva
        password = self.cleaned_data.get('password1')
        if password:
            user.set_password(password)

        if commit:
            user.save()

        return user
    

#formulario editar usuario
class CustomUserAdministradorUpdateForm(forms.ModelForm):
    razon_social = forms.CharField(required=False, disabled=True)  # Campo deshabilitado para el nombre de la empresa
    area = forms.ModelChoiceField(
        queryset=Area.objects.none(),  # Inicialmente el queryset está vacío
        required=False,
        label="Área"
    )

    password1 = forms.CharField(
        label='Nueva Contraseña', 
        widget=forms.PasswordInput, 
        required=False
    )
    password2 = forms.CharField(
        label='Confirmar Nueva Contraseña', 
        widget=forms.PasswordInput, 
        required=False
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'first_name', 'last_name', 'profile_picture', 'razon_social', 'area', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        current_user = kwargs.pop('current_user', None)

        super(CustomUserAdministradorUpdateForm, self).__init__(*args, **kwargs)

        # Configurar el valor inicial para razon_social y area si existen
        if self.instance and self.instance.empresa:
            self.fields['razon_social'].initial = self.instance.empresa.razon_social
            self.fields['area'].queryset = Area.objects.filter(empresas_asociadas=self.instance.empresa)
            if self.instance.area:
                self.fields['area'].initial = self.instance.area

        if current_user:
            # Lógica adicional basada en current_user
            pass


    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Las contraseñas no coinciden")
        return password2

    def save(self, commit=True):
        user = super(CustomUserAdministradorUpdateForm, self).save(commit=False)
        
        # Actualizar la empresa relacionada si es necesario
        social_razon = self.cleaned_data.get('razon_social')
        if social_razon:
            empresa, created = Empresa.objects.get_or_create(razon_social=social_razon)
            user.empresa = empresa

        # Actualizar el área relacionada
        area_seleccionada = self.cleaned_data.get('area')
        if area_seleccionada:
            user.area = area_seleccionada

         # Actualiza la contraseña si se proporcionó una nueva
        password = self.cleaned_data.get('password1')
        if password:
            user.set_password(password)

        if commit:
            user.save()

        return user



from captcha.fields import CaptchaField

#formulario de ingreso de usuarios
class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(label='Correo electrónico', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su correo electrónico'}))
    username = forms.CharField(label='Nombre de usuario', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su nombre de usuario'}))
    first_name = forms.CharField(label='Nombre', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su nombre'}))
    last_name = forms.CharField(label='Apellidos', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su apellido'}))
    password1 = forms.CharField(label='Contraseña', widget=forms.PasswordInput(attrs={'placeholder': 'Ingrese su contraseña'}), required=True)
    password2 = forms.CharField(label='Confirmar contraseña', widget=forms.PasswordInput(attrs={'placeholder': 'Confirme su contraseña'}), required=True)
    captcha = CaptchaField()

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'password1', 'password2', 'captcha']

    def __init__(self, *args, **kwargs):
        super(UserRegistrationForm, self).__init__(*args, **kwargs)

        #indicaciones para contraseña correcta
        self.fields['password1'].help_text = password_validators_help_text_html()

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            self.add_error('password2', "Las contraseñas no coinciden")

        return cleaned_data

    def save(self, commit=True):
        user = super(UserRegistrationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])

        user.tipo_usuario = 'Administrador'

        if commit:
            user.save()
        
        return user

##vista que maneja el html de enviar invitación de registro
###Invitación por correo 

from django import forms
import base64


from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

class EmailInvitationForm(forms.Form):
    email = forms.CharField(
        label='Correos electrónicos',
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Ingrese los correos electrónicos separados por coma'})
    )
    area = forms.ModelChoiceField(
        queryset=Area.objects.none(),
        label='Área',
        required=False
    )
    mensaje_personalizado = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Escribe aquí tu mensaje de invitación personalizado.'}),
        required=False,
        label='Mensaje Personalizado'
    )

    def __init__(self, *args, **kwargs):
        selected_area_name = kwargs.pop('selected_area_name', None)
        user = kwargs.pop('user', None)
        super(EmailInvitationForm, self).__init__(*args, **kwargs)

        if user and user.empresa:
            self.fields['area'].queryset = Area.objects.filter(empresa=user.empresa)
            id_empresa_codificado = base64.urlsafe_b64encode(str(user.empresa.id).encode()).decode()
            link_registro = f'http://192.168.1.38/autenticacion/form_invitacion/?empresa_id={id_empresa_codificado}'

            # Establecer mensaje predeterminado con el enlace de registro
            if selected_area_name:
                mensaje_predeterminado = (
                    f"Te invitamos a unirte a la área de {selected_area_name} en Kabasis. "
                    f"Regístrate en {link_registro} y comienza a explorar cursos y recursos en seguridad digital."
                )
            else:
                mensaje_predeterminado = (
                    ""
                )
            self.fields['mensaje_personalizado'].initial = mensaje_predeterminado
    
    def clean_email(self):
        emails = self.cleaned_data['email'].split(',')
        valid_emails = []
        for email in emails:
            email = email.strip()
            validate_email(email)
            valid_emails.append(email)
        return valid_emails


#Formulario que registra un usuario con una empresa precargada este enviado por correo
class UserAndEmpresaEmailForm(UserCreationForm):
    email = forms.EmailField(label='Correo electrónico', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su correo electrónico'}))
    username = forms.CharField(label='Nombre de usuario', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su nombre de usuario'}))
    first_name = forms.CharField(label='Nombre', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su nombre'}))
    last_name = forms.CharField(label='Apellidos', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese su apellido'}))
    password1 = forms.CharField(label='Contraseña', widget=forms.PasswordInput(attrs={'placeholder': 'Ingrese su contraseña'}), required=True)
    password2 = forms.CharField(label='Confirmar contraseña', widget=forms.PasswordInput(attrs={'placeholder': 'Confirme su contraseña'}), required=True)
    razon_social = forms.CharField(label='Razon social', required=True, widget=forms.TextInput(attrs={'placeholder': 'Ingrese el nombre de su empresa'}))
    area_id = forms.CharField(widget=forms.HiddenInput(), required=False)
    nombre_area = forms.CharField(label='Área', required=False, widget=forms.TextInput(attrs={'readonly': 'readonly'}))


    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'profile_picture', 'password1', 'password2', 'razon_social', 'nombre_area']
        labels = {
            'email': 'Correo electrónico',
            'username': 'Nombre de usuario',
            'first_name': 'Nombre',
            'last_name': 'Apellido',
            'password1': 'Contraseña',
            'password2': 'Confirmar contraseña',
            'razon_social': 'Razon social',
            'profile_picture': 'Imagen de perfil',
        }

    def __init__(self, *args, **kwargs):
        self.empresa_id = kwargs.pop('empresa_id', None)
        self.area_id = kwargs.pop('area_id', None)
        
        super(UserAndEmpresaEmailForm, self).__init__(*args, **kwargs)
        if self.empresa_id:
            try:
                empresa = Empresa.objects.get(id=self.empresa_id)
                self.fields['razon_social'].initial = empresa.razon_social
                self.fields['razon_social'].widget.attrs['readonly'] = True
            except Empresa.DoesNotExist:
                pass
        # Resto del constructor
        if self.area_id:
            try:
                area = Area.objects.get(id=self.area_id)
                self.fields['nombre_area'].initial = area.nombre
                self.fields['nombre_area'].widget.attrs['readonly'] = True
            except Area.DoesNotExist:
                pass
        
            self.fields['password1'].help_text = password_validators_help_text_html()


    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])

        # Asignar tipo_usuario a 'Alumno'
        user.tipo_usuario = 'Alumno'

        if self.empresa_id:
            user.empresa = Empresa.objects.get(id=self.empresa_id)
        
        if self.area_id:
            user.area = Area.objects.get(id=self.area_id)

        if commit:
            user.save()
            # Si hay un archivo en profile_picture, guárdalo después de haber guardado el usuario
            if 'profile_picture' in self.files:
                user.profile_picture = self.files['profile_picture']
                user.save()  # Guarda de nuevo para almacenar la imagen

            self.save_m2m()  # Guarda las relaciones many-to-many si las hay

        return user

    def clean_password1(self):
        password1 = self.cleaned_data.get("password1")
        try:
            validate_password(password1, self.instance)
        except ValidationError as e:
            self.add_error('password1', e)
        return password1

    # No necesitas el método clean_nombre_empresa, si solo estás pre-cargando este campo


#Formulario que registra una empresa y sus áreas
from django import forms
from .models import Empresa

from django import forms
from .models import Empresa, CustomUser  # Asegúrate de que estos modelos estén correctamente importados

class EmpresaForm(forms.ModelForm):
    razon_social = forms.CharField(
        label='Razón social', 
        required=True, 
        widget=forms.TextInput(attrs={'placeholder': 'Ingrese la razón social de su empresa', 'class': 'form-control'})
    )
    giro = forms.ChoiceField(
        label='Giro', 
        choices=Empresa.GIROS_CHOICES,  # Asegúrate de que GIROS_CHOICES esté definido en tu modelo Empresa
        required=True,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    numero_colaboradores = forms.IntegerField(
        label='Número de colaboradores', 
        required=True, 
        widget=forms.NumberInput(attrs={'placeholder': 'Número de colaboradores', 'class': 'form-control'})
    )
    

    class Meta:
        model = Empresa
        fields = ['razon_social', 'giro', 'numero_colaboradores']

    def clean_razon_social(self):
        razon_social = self.cleaned_data.get('razon_social')
        if razon_social:
            razon_social = razon_social.capitalize()  # Cambia la inicial a mayúscula
        return razon_social

    def save(self, commit=True, user=None):
        empresa = super(EmpresaForm, self).save(commit=False)
        empresa.save()

        if user and isinstance(user, CustomUser):
            user.empresa = empresa
            user.save()

        return empresa


from collections import OrderedDict


##Formulario de login
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from captcha.fields import CaptchaField

class CustomLoginForm(AuthenticationForm):
    captcha = CaptchaField()

    def __init__(self, *args, **kwargs):
        super(CustomLoginForm, self).__init__(*args, **kwargs)
        # Establecer el orden de los campos
        self.fields = OrderedDict([
            ('username', self.fields['username']),
            ('password', self.fields['password']),
            ('captcha', self.fields['captcha'])
        ])

        # Agregar clases a los widgets si es necesario
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'







    