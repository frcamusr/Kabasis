from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import View
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .forms import CustomUserCreationForm, UserProfileForm, EmpresaForm, CustomUserUpdateForm, UserRegistrationForm, AreaForm, EmailInvitationForm, UserAndEmpresaEmailForm, CustomLoginForm, CustomUserAsistenteCreationForm, CustomUserAsistenteUpdateForm, CustomUserAdministradorUpdateForm, CustomUserAdministradorCreationForm, AreaFormInicio
from .models import CustomUser, Empresa, Area, VerificationToken
##csv##
import csv
from .forms import CSVUploadForm  # Importa el formulario para subir el CSV
from django.db import transaction,IntegrityError
##csv##
import base64
from django.contrib.auth.views import LoginView
# fin importaciones
from django.contrib.auth.forms import PasswordChangeForm
import secrets


def registro(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # No activar el usuario todavía
            user.save()

            # Crear token de verificación
            token = VerificationToken.objects.create(user=user)

            # Enviar correo electrónico
            verification_link = request.build_absolute_uri(f'/autenticacion/verify-email/{token.token}/')
            email_subject = 'Confirmación de Inscripción en Kabasis'
            email_message = (
                f'¡Bienvenido/a a Kabasis!\n\n'
                f'Recientemente se ha registrado una cuenta asociada a esta dirección de correo electrónico en Kabasis. '
                f'Si has realizado esta inscripción, te damos la más cordial bienvenida a nuestra plataforma.\n\n'
                f'Para confirmar tu inscripción, por favor, haz clic en el enlace de confirmación que se proporciona a continuación:\n\n'
                f'{verification_link}\n\n'
                f'Si no has realizado esta inscripción y crees que has recibido este correo por error, por favor ignóralo. '
                f'No te preocupes, tu cuenta no se activará hasta que confirmes tu inscripción haciendo clic en el enlace de confirmación.\n\n'
                f'¡Gracias por ser parte de Kabasis!\n\n'
                f'Atentamente,\nEl Equipo de Kabasis'
            )

            send_mail(
                email_subject,
                email_message,
                'from@example.com',
                [user.email],
                fail_silently=False,
            )

            messages.info(request, "Por favor, verifica tu correo electrónico para completar el registro.")
            return redirect('Home')
    else:
        form = UserRegistrationForm()

    return render(request, 'registration/registro.html', {'form': form})


def verify_email(request, token):
    verification_token = get_object_or_404(VerificationToken, token=token)
    user = verification_token.user
    user.is_active = True
    user.save()
    messages.success(request, "Tu cuenta ha sido verificada. Ahora puedes iniciar sesión.")
    return redirect('login')

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def view_profile(request):
    user = request.user
    razon_social = user.empresa.razon_social if user.empresa else 'Sin empresa asignada'
    area_nombre = user.area.nombre if user.area else 'Sin área asignada'  # Obtener el nombre del área

    context = {
        'user': user,
        'razon_social': razon_social,
        'area_nombre': area_nombre  # Pasar el nombre del área al template
    }
    return render(request, 'registration/view_profile.html', context)


from django import forms


@login_required
def edit_profile(request):
    user = request.user
    password_changed = False  # Una bandera para rastrear si la contraseña ha cambiado

    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()

            # Verifica si es la primera vez que el usuario edita su perfil
            if user.is_first_login:
                user.is_first_login = False
                user.save()
                # Cierra la sesión actual
                logout(request)
                messages.info(request, "Como es tu primera vez actualizando tu perfil, por favor inicia sesión nuevamente.")
                return redirect('login')  # Redirige a la página de inicio de sesión

            if form.cleaned_data.get('new_password'):
                # La contraseña ha sido cambiada
                password_changed = True
                messages.success(request, "Has cambiado tu contraseña. Por favor, inicia sesión nuevamente.")
                return redirect('login')  # Redirigir a la página de inicio de sesión
            else:
                # Solo se actualizaron los datos, no la contraseña
                messages.success(request, "Tus datos han sido actualizados correctamente.")
                return redirect('view_profile')

    else:
        form = UserProfileForm(instance=user)

    # Verifica si el usuario es de tipo "Administrador Kabasis"
    if user.tipo_usuario == "Administrador Kabasis":
        # Agregar el campo "nombre empresa" al formulario
        form.fields['nombre_empresa'] = forms.CharField(label="Nombre de la Empresa")

    return render(request, 'registration/edit_profile.html', {'form': form})




# Vista para crear un nuevo usuario personalizado
def crear_usuario_personalizado(request):
    if not request.user.is_authenticated:
        # Redirigir al usuario a la página de inicio de sesión si no está autenticado
        return redirect('login')  # Asegúrate de reemplazar esto con el nombre correcto de tu vista de inicio de sesión

    razon_social_usuario_logueado = request.user.empresa.razon_social if request.user.empresa else 'su empresa'

    
    if request.method == 'POST':
        formulario = CustomUserCreationForm(request.POST, request.FILES, current_user=request.user)
        if formulario.is_valid():
            nuevo_usuario = formulario.save(commit=False)

            # Asociar la empresa seleccionada al usuario
            empresa_seleccionada = formulario.cleaned_data['razon_social']
            if empresa_seleccionada:
                nuevo_usuario.empresa = empresa_seleccionada

            # Asignar el área seleccionada al usuario
            area_seleccionada = formulario.cleaned_data.get('area')
            if area_seleccionada:
                nuevo_usuario.area = area_seleccionada

            nuevo_usuario.save()
            link_login = "http://192.168.1.38/autenticacion/login/"  # URL de la página de inicio de sesión

            send_mail(

            'contacto desde Kabasis',  # subject
                # Modifica aquí el mensaje incluyendo el nombre de la empresa
                f'Bienvenido a Kabasis\n\n'
                'Le informamos que ha sido inscrito en nuestra plataforma para certificarse. \n\n'
                'Sus credenciales de acceso son las siguientes: \n'
                f'Correo de ingreso: {formulario.cleaned_data["email"]} \n'
                f'Contraseña: {formulario.cleaned_data["password1"]} \n\n'
                'Le recomendamos cambiar su contraseña por seguridad. '
                'Para ello, inicie sesión con la contraseña proporcionada y actualícela en la sección de edición de perfil de usuario. \n\n'
                f'Puede iniciar sesión aquí: {link_login}\n\n'  # Incluir el enlace de inicio de sesión
                'Gracias por unirse a Kabasis. ¡Le deseamos mucho éxito en su certificación! \n\n'
                'Atentamente, \n'
                f'{razon_social_usuario_logueado}',  # message
                from_email=settings.EMAIL_HOST_USER,  # from email
                recipient_list=[formulario.cleaned_data['email']],  # recipient emails
                fail_silently=False
            )
            messages.success(request, 'Usuario creado con éxito.')
            return redirect('lista_usuarios_personalizados')
    else:
        formulario = CustomUserCreationForm(current_user=request.user)

    return render(request, 'registration/formulario_usuario.html', {'formulario': formulario})
    
##Crear usuario asistente
def crear_usuario_personalizado_asistente(request):
    if not request.user.is_authenticated:
        # Redirigir al usuario a la página de inicio de sesión si no está autenticado
        return redirect('login')  # Asegúrate de reemplazar esto con el nombre correcto de tu vista de inicio de sesión

    razon_social_usuario_logueado = request.user.empresa.razon_social if request.user.empresa else 'su empresa'

    if request.method == 'POST':
        formulario = CustomUserAsistenteCreationForm(request.POST, request.FILES, current_user=request.user)
        if formulario.is_valid():
            nuevo_usuario = formulario.save(commit=False)

            # Asociar la empresa seleccionada al usuario
            empresa_seleccionada = formulario.cleaned_data['razon_social']
            if empresa_seleccionada:
                nuevo_usuario.empresa = empresa_seleccionada

            # Asignar el área seleccionada al usuario
            area_seleccionada = formulario.cleaned_data.get('area')
            if area_seleccionada:
                nuevo_usuario.area = area_seleccionada

            nuevo_usuario.save()
            link_login = "http://192.168.1.38/autenticacion/login/"  # URL de la página de inicio de sesión

            send_mail(

            'contacto desde Kabasis',  # subject
                # Modifica aquí el mensaje incluyendo el nombre de la empresa
                f'Bienvenido a Kabasis\n\n'
                'Le informamos que ha sido inscrito en nuestra plataforma para certificarse. \n\n'
                'Sus credenciales de acceso son las siguientes: \n'
                f'Correo de ingreso: {formulario.cleaned_data["email"]} \n'
                f'Contraseña: {formulario.cleaned_data["password1"]} \n\n'
                'Le recomendamos cambiar su contraseña por seguridad. '
                'Para ello, inicie sesión con la contraseña proporcionada y actualícela en la sección de edición de perfil de usuario. \n\n'
                f'Puede iniciar sesión aquí: {link_login}\n\n'  # Incluir el enlace de inicio de sesión
                'Gracias por unirse a Kabasis. ¡Le deseamos mucho éxito en su certificación! \n\n'
                'Atentamente, \n'
                f'{razon_social_usuario_logueado}',  # message
                from_email=settings.EMAIL_HOST_USER,  # from email
                recipient_list=[formulario.cleaned_data['email']],  # recipient emails
                fail_silently=False
            )
            messages.success(request, 'Usuario creado con éxito.')
            return redirect('lista_usuarios_personalizados_asistentes')
    else:
        formulario = CustomUserAsistenteCreationForm(current_user=request.user)

    return render(request, 'registration/formulario_usuario_asistente.html', {'formulario': formulario})

##Crear usuario administrador
def crear_usuario_personalizado_administrador(request):
    if not request.user.is_authenticated:
        # Redirigir al usuario a la página de inicio de sesión si no está autenticado
        return redirect('login')  # Asegúrate de reemplazar esto con el nombre correcto de tu vista de inicio de sesión

    razon_social_usuario_logueado = request.user.empresa.razon_social if request.user.empresa else 'su empresa'

    if request.method == 'POST':
        formulario = CustomUserAdministradorCreationForm(request.POST, request.FILES, current_user=request.user)
        if formulario.is_valid():
            nuevo_usuario = formulario.save(commit=False)

            # Asociar la empresa seleccionada al usuario
            empresa_seleccionada = formulario.cleaned_data['razon_social']
            if empresa_seleccionada:
                nuevo_usuario.empresa = empresa_seleccionada

            # Asignar el área seleccionada al usuario
            area_seleccionada = formulario.cleaned_data.get('area')
            if area_seleccionada:
                nuevo_usuario.area = area_seleccionada

            nuevo_usuario.save()
            link_login = "http://192.168.1.38/autenticacion/login/"  # URL de la página de inicio de sesión

            send_mail(

            'contacto desde Kabasis',  # subject
                # Modifica aquí el mensaje incluyendo el nombre de la empresa
                f'Bienvenido a Kabasis\n\n'
                'Le informamos que ha sido inscrito en nuestra plataforma para certificarse. \n\n'
                'Sus credenciales de acceso son las siguientes: \n'
                f'Correo de ingreso: {formulario.cleaned_data["email"]} \n'
                f'Contraseña: {formulario.cleaned_data["password1"]} \n\n'
                'Le recomendamos cambiar su contraseña por seguridad. '
                'Para ello, inicie sesión con la contraseña proporcionada y actualícela en la sección de edición de perfil de usuario. \n\n'
                f'Puede iniciar sesión aquí: {link_login}\n\n'  # Incluir el enlace de inicio de sesión
                'Gracias por unirse a Kabasis. ¡Le deseamos mucho éxito en su certificación! \n\n'
                'Atentamente, \n'
                f'{razon_social_usuario_logueado}',  # message
                from_email=settings.EMAIL_HOST_USER,  # from email
                recipient_list=[formulario.cleaned_data['email']],  # recipient emails
                fail_silently=False
            )
            messages.success(request, 'Usuario creado con éxito.')
            return redirect('lista_usuarios_personalizados_administradores')
    else:
        formulario = CustomUserAdministradorCreationForm(current_user=request.user)

    return render(request, 'registration/formulario_usuario_administrador.html', {'formulario': formulario})




# Vista para listar usuarios personalizados
def lista_usuarios_personalizados(request):
    # Comprobar si el usuario está autenticado y es un Administrador o Administrador Kabasis
    if request.user.is_authenticated and request.user.tipo_usuario in ['Administrador', 'Administrador Kabasis', 'Asistente Administrativo']:
        tipo_usuario_filtrado = 'Alumno'
        # Filtrar usuarios por la empresa del administrador si es necesario
        if request.user.tipo_usuario == 'Administrador':
            usuarios = CustomUser.objects.filter(empresa=request.user.empresa, tipo_usuario=tipo_usuario_filtrado)
        else:
            # Si es Administrador Kabasis, mostrar todos los usuarios
            usuarios = CustomUser.objects.filter(tipo_usuario=tipo_usuario_filtrado)
    else:
        # Si no es un usuario autorizado, redirigir al inicio de sesión
        return redirect('login')  # Asegúrate de reemplazar esto con el nombre correcto de tu vista de inicio de sesión

    return render(request, 'registration/lista_usuarios.html', {'usuarios': usuarios})


# Vista para listar usuarios asistentes
from django.shortcuts import render, redirect

def lista_usuarios_personalizados_asistentes(request):
    # Comprobar si el usuario está autenticado y es un Administrador o Administrador Kabasis
    if request.user.is_authenticated and request.user.tipo_usuario in ['Administrador', 'Administrador Kabasis']:
        tipo_usuario_filtrado = 'Asistente Administrativo'

        # Filtrar usuarios por la empresa del administrador si es necesario y por el tipo de usuario
        if request.user.tipo_usuario == 'Administrador':
            usuarios = CustomUser.objects.filter(empresa=request.user.empresa, tipo_usuario=tipo_usuario_filtrado)
        else:
            # Si es Administrador Kabasis, mostrar todos los usuarios del tipo filtrado
            usuarios = CustomUser.objects.filter(tipo_usuario=tipo_usuario_filtrado)
    else:
        # Si no es un usuario autorizado, redirigir al inicio de sesión
        return redirect('login')  # Asegúrate de reemplazar esto con el nombre correcto de tu vista de inicio de sesión

    return render(request, 'registration/lista_usuarios_asistente.html', {'usuarios': usuarios})


def lista_usuarios_personalizados_administradores(request):
    # Comprobar si el usuario está autenticado y es un Administrador o Administrador Kabasis
    if request.user.is_authenticated and request.user.tipo_usuario in ['Administrador Kabasis']:
        tipo_usuario_filtrado = 'Administrador'

        # Filtrar usuarios por la empresa del administrador si es necesario y por el tipo de usuario
        if request.user.tipo_usuario == 'Administrador':
            usuarios = CustomUser.objects.filter(empresa=request.user.empresa, tipo_usuario=tipo_usuario_filtrado)
        else:
            # Si es Administrador Kabasis, mostrar todos los usuarios del tipo filtrado
            usuarios = CustomUser.objects.filter(tipo_usuario=tipo_usuario_filtrado)
    else:
        # Si no es un usuario autorizado, redirigir al inicio de sesión
        return redirect('login')  # Asegúrate de reemplazar esto con el nombre correcto de tu vista de inicio de sesión

    return render(request, 'registration/lista_usuarios_administradores.html', {'usuarios': usuarios})


##actualizar usuario 
@login_required
def actualizar_usuario_personalizado(request, id_usuario):
    usuario = get_object_or_404(CustomUser, pk=id_usuario)
    if request.method == 'POST':
        # Pasar el usuario actual al formulario
        formulario = CustomUserUpdateForm(request.POST, instance=usuario, current_user=request.user)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, "Usuario actualizado correctamente")
            return redirect('lista_usuarios_personalizados')
    else:
        # Pasar el usuario actual al formulario
        formulario = CustomUserUpdateForm(instance=usuario, current_user=request.user)

    return render(request, 'registration/formulario_usuario.html', {'formulario': formulario})


##actualizar usuario asistente
@login_required
def actualizar_usuario_personalizado_asistente(request, id_usuario):
    usuario = get_object_or_404(CustomUser, pk=id_usuario)
    if request.method == 'POST':
        # Pasar el usuario actual al formulario
        formulario = CustomUserAsistenteUpdateForm(request.POST, instance=usuario, current_user=request.user)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, "Usuario actualizado correctamente")
            return redirect('lista_usuarios_personalizados_asistentes')
    else:
        # Pasar el usuario actual al formulario
        formulario = CustomUserAsistenteUpdateForm(instance=usuario, current_user=request.user)

    return render(request, 'registration/formulario_usuario_asistente.html', {'formulario': formulario})


##actualizar usuario administrador
@login_required
def actualizar_usuario_personalizado_administrador(request, id_usuario):
    usuario = get_object_or_404(CustomUser, pk=id_usuario)
    if request.method == 'POST':
        # Pasar el usuario actual al formulario
        formulario = CustomUserAdministradorUpdateForm(request.POST, instance=usuario, current_user=request.user)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, "Usuario actualizado correctamente")
            return redirect('lista_usuarios_personalizados_administradores')
    else:
        # Pasar el usuario actual al formulario
        formulario = CustomUserAdministradorUpdateForm(instance=usuario, current_user=request.user)

    return render(request, 'registration/formulario_usuario_administrador.html', {'formulario': formulario})


# Vista para eliminar un usuario personalizado
@login_required
def eliminar_usuario_personalizado(request, id_usuario):
    if request.method == 'GET':
        usuario = get_object_or_404(CustomUser, id=id_usuario)
        usuario.delete()
        messages.success(request, 'Usuario eliminado con éxito.')
        return redirect('lista_usuarios_personalizados')
    return redirect('Home')


# Vista para eliminar un usuario asistente
@login_required
def eliminar_usuario_personalizado_asistente(request, id_usuario):
    if request.method == 'GET':
        usuario = get_object_or_404(CustomUser, id=id_usuario)
        usuario.delete()
        messages.success(request, 'Usuario eliminado con éxito.')
        return redirect('lista_usuarios_personalizados_asistentes')
    return redirect('Home')

# Vista para eliminar un usuario administrador
@login_required
def eliminar_usuario_personalizado_administrador(request, id_usuario):
    if request.method == 'GET':
        usuario = get_object_or_404(CustomUser, id=id_usuario)
        usuario.delete()
        messages.success(request, 'Usuario eliminado con éxito.')
        return redirect('lista_usuarios_personalizados_administradores')
    return redirect('Home')


##########Empresas#################

# Vista para crear una nueva empresa
@login_required
def crear_empresa(request):
    # Comprobar si el usuario está autenticado y es un Administrador Kabasis
    if not (request.user.is_authenticated and request.user.tipo_usuario == 'Administrador Kabasis'):
        # Si no es Administrador Kabasis, redirigir al inicio de sesión
        return redirect('login')  # Reemplaza esto con el nombre de tu vista de inicio de sesión

    if request.method == 'POST':
        formulario = EmpresaForm(request.POST, request.FILES)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, 'Empresa creada con éxito.')
            return redirect('crear_empresa')  # Reemplaza esto con la ruta adecuada después de crear la empresa
        else: 
            data = {'form': formulario}
    else:
        data = {'form': EmpresaForm()}

    return render(request, "empresas/crear_empresa.html", data)

@login_required
def listar_empresa(request):
    # Comprobar si el usuario está autenticado y es un Administrador Kabasis
    if request.user.is_authenticated and request.user.tipo_usuario == 'Administrador Kabasis':
        empresas = Empresa.objects.all()
        data = {'empresas': empresas}
        return render(request, "empresas/listar_empresa.html", data)
    else:
        # Si no es Administrador Kabasis, redirigir al inicio de sesión
        return redirect('login')  # Reemplaza esto con el nombre correcto de tu vista de inicio de sesión

@login_required
def actualizar_empresa(request, id):
    # Comprobar si el usuario es Administrador Kabasis
    if not (request.user.is_authenticated and request.user.tipo_usuario == 'Administrador Kabasis'):
        return redirect('login')  # Reemplaza con el nombre de tu vista de inicio de sesión

    empresa = get_object_or_404(Empresa, id=id)
    data = {'form': EmpresaForm(instance=empresa)}

    if request.method == 'POST':
        formulario = EmpresaForm(data=request.POST, instance=empresa, files=request.FILES)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, "Empresa actualizada correctamente")
            return redirect(to="listar_empresa")
        
        data["form"] = formulario
    
    return render(request, "empresas/actualizar_empresa.html", data)

@login_required
def eliminar_empresa(request, id):
    # Comprobar si el usuario es Administrador Kabasis
    if not (request.user.is_authenticated and request.user.tipo_usuario == 'Administrador Kabasis'):
        return redirect('login')  # Reemplaza con el nombre de tu vista de inicio de sesión

    empresa = get_object_or_404(Empresa, id=id)
    empresa.delete()
    messages.success(request, 'Empresa eliminada con éxito.')
    return redirect(to="listar_empresa")


##Administrar Áreas
from django.contrib import messages
from django.shortcuts import render, redirect
from .forms import AreaForm  # Asegúrate de que este importe sea correcto
from django.contrib.auth.decorators import login_required
from django.utils.safestring import mark_safe


@login_required
def crear_area(request):
    errores = []
    nombres_areas_existentes = []  # Lista para almacenar los nombres de las áreas existentes
    exito = False
    if request.user.is_authenticated and request.user.empresa:
        if request.method == 'POST':
            formulario = AreaForm(request.POST)
            if formulario.is_valid():
                nombres_areas = formulario.cleaned_data['nombres'].split(',')
                nombres_areas = [nombre.strip().capitalize() for nombre in nombres_areas if nombre.strip()]
                for nombre_area in nombres_areas:
                    if Area.objects.filter(nombre=nombre_area, empresa=request.user.empresa).exists():
                        nombres_areas_existentes.append(nombre_area)
                    else:
                        Area.objects.create(nombre=nombre_area, empresa=request.user.empresa)
                        messages.success(request, "Area(s) agregada correctamente")
                if nombres_areas_existentes:
                    mensaje_error = "Las siguientes áreas ya existen en su empresa: " + ", ".join(nombres_areas_existentes)
                    errores.append(mensaje_error)
                else:
                    exito = True
            else:
                errores.append('Por favor, corrija los errores en el formulario.')
        else:
            formulario = AreaForm()

        return render(request, "areas/crear_area.html", {'form': formulario, 'errores': errores, 'exito': exito})
    else:
        return redirect('login')
    

#Crear área inicio
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import AreaFormInicio  # Asegúrate de tener el formulario adecuado importado
from .models import Area  # Asegúrate de importar el modelo Area
from django.contrib import messages

@login_required
def crear_area_inicio(request):
    errores = []
    nombres_areas_existentes = []  # Lista para almacenar los nombres de las áreas existentes
    exito = False
    if request.user.is_authenticated and request.user.empresa:
        if request.method == 'POST':
            formulario = AreaFormInicio(request.POST)
            if formulario.is_valid():
                nombres_areas = formulario.cleaned_data['nombres'].split(',')
                nombres_areas = [nombre.strip().capitalize() for nombre in nombres_areas if nombre.strip()]
                for nombre_area in nombres_areas:
                    if Area.objects.filter(nombre=nombre_area, empresa=request.user.empresa).exists():
                        nombres_areas_existentes.append(nombre_area)
                    else:
                        Area.objects.create(nombre=nombre_area, empresa=request.user.empresa)
                        messages.success(request, "Area(s) agregada correctamente")

                if nombres_areas_existentes:
                    mensaje_error = "Las siguientes áreas ya existen en su empresa: " + ", ".join(nombres_areas_existentes)
                    errores.append(mensaje_error)
                else:
                    exito = True

                if exito:
                    # Si todas las áreas fueron agregadas exitosamente y no hay errores, redirigir al Home
                    return redirect('Home')  # Asegúrate de que 'Home' es el nombre correcto de tu vista de inicio

            else:
                errores.append('Por favor, corrija los errores en el formulario.')
        else:
            formulario = AreaFormInicio()

        return render(request, "areas/crear_area_inicio.html", {'form': formulario, 'errores': errores, 'exito': exito})
    else:
        return redirect('login')



##listar Áreas
from django.shortcuts import render, redirect
from .models import Area  # Asegúrate de importar el modelo Area
from django.contrib.auth.decorators import login_required

@login_required
def lista_areas(request):
    # Comprobar si el usuario está autenticado
    if request.user.is_authenticated:
        # Si el usuario es un Administrador Kabasis, mostrar todas las áreas
        if request.user.tipo_usuario == 'Administrador Kabasis':
            areas = Area.objects.all()
        # Si el usuario es un Administrador y tiene una empresa asociada, mostrar solo las áreas de esa empresa
        elif request.user.tipo_usuario == 'Administrador' and request.user.empresa:
            areas = Area.objects.filter(empresa=request.user.empresa)
        else:
            # Si el usuario no es ni Administrador Kabasis ni Administrador con empresa, no mostrar áreas
            areas = Area.objects.none()

        data = {'areas': areas}
        return render(request, "areas/lista_areas.html", data)
    else:
        # Si el usuario no está autenticado, redirigir al inicio de sesión
        return redirect('login')



##actualizar área
@login_required
def actualizar_area(request, id):
    area = get_object_or_404(Area, id=id)

    if request.user.tipo_usuario in ['Administrador', 'Administrador Kabasis']:
        if request.method == 'POST':
            formulario = AreaForm(request.POST)
            if formulario.is_valid():
                # Actualiza los datos del área manualmente
                area.nombre = formulario.cleaned_data['nombres']
                area.save()
                messages.success(request, "Área actualizada correctamente")
                return redirect('lista_areas')
        else:
            # Inicializa el formulario con los datos del área
            formulario = AreaForm(initial={'nombres': area.nombre})
    else:
        messages.error(request, "No tiene permiso para editar esta área o no está autenticado")
        return redirect('lista_areas')

    return render(request, "areas/actualizar_area.html", {'form': formulario})


@login_required
def eliminar_area(request, id):
    # Verificar permisos del usuario
    if not (request.user.is_authenticated and (request.user.tipo_usuario == 'Administrador' or request.user.tipo_usuario == 'Administrador Kabasis')):
        return redirect('login')

    area = get_object_or_404(Area, id=id)
    
    area.delete()
    messages.success(request, 'Área eliminada con éxito.')
    return redirect('lista_areas')


@login_required
def menu_administracion(request):
    
    return render(request, "empresas/menu_administracion.html")


######Creación de usuarios de manera masiva####

def chunks(lst, n):
    """Divide la lista 'lst' en pedazos de tamaño 'n'."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

@transaction.atomic
def carga_masiva(request):
    usuarios_creados = 0
    usuarios_no_creados = 0
    usuarios_existente = []
    created_users = []  # Lista para almacenar los usuarios creados
    BATCH_SIZE = 10  # Tamaño del lote

    if request.method == 'POST':
        form = CSVUploadForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            area_seleccionada = form.cleaned_data['area']
            try:
                with transaction.atomic():
                    csv_file = request.FILES['archivo_csv'].read().decode('utf-8')
                    csv_data = csv.reader(csv_file.splitlines())
                    data_list = list(csv_data)

                    emails_existentes = set()

                    empresa_usuario_logueado = request.user.empresa
                    tipo_usuario = 'Alumno'  # Establece el tipo de usuario por defecto

                    for chunk in chunks(data_list, BATCH_SIZE):
                        for row in chunk:
                            if len(row) < 1:  # Verifica si la fila tiene menos de 1 columna
                                continue  # Salta esta iteración y continúa con la siguiente fila
                            email = row[0]
                            username = email
                            password = secrets.token_urlsafe(12)  # Genera una contraseña segura

                            if CustomUser.objects.filter(email=email).exists():
                                usuarios_existente.append(email)
                                emails_existentes.add(email)
                                usuarios_no_creados += 1
                                continue

                            try:
                                new_user = CustomUser.objects.create(
                                    username=username,
                                    first_name='',
                                    last_name='',
                                    email=email,
                                    tipo_usuario=tipo_usuario,
                                    empresa=empresa_usuario_logueado,
                                    area=area_seleccionada,
                                )
                                new_user.set_password(password)
                                new_user.save()
                                usuarios_creados += 1
                                created_users.append({
                                    'email': email,
                                    'username': username,
                                    'password': password
                                })
                            except IntegrityError:
                                usuarios_existente.append(username)
                                usuarios_no_creados += 1

                    link_login = "http://192.168.1.38/autenticacion/login/"  # URL de la página de inicio de sesión

                    # Envío de correos después de crear todos los usuarios
                    for user in created_users:
                        email = user['email']
                        subject = 'Contacto desde Kabasis'
                        message = (
                            'Bienvenido a Kabasis, \n\n'
                            'Le informamos que ha sido inscrito en nuestra plataforma para certificarse. \n\n'
                            'Sus credenciales de acceso son las siguientes: \n'
                            f'Correo de ingreso: {user["username"]} \n'
                            f'Contraseña: {user["password"]} \n\n'
                            'Le recomendamos encarecidamente cambiar su contraseña lo antes posible, '
                            'la cual ha sido generada de manera aleatoria. Para ello, inicie sesión con la contraseña proporcionada y actualícela en la sección de configuración de su cuenta. \n\n'
                            f'Puede iniciar sesión aquí: {link_login}\n\n'  # Incluir el enlace de inicio de sesión
                            'Gracias por unirse a Kabasis. ¡Le deseamos mucho éxito en su certificación! \n\n'
                            'Atentamente, \n'
                            'El equipo de Kabasis'
                        )
                        from_email = settings.EMAIL_HOST_USER
                        recipient_list = [email]

                        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

                    if emails_existentes:
                        mensajes_correos = ", ".join(emails_existentes)
                        messages.warning(request, f'Se han creado {usuarios_creados} usuarios exitosamente. No se guardaron {usuarios_no_creados} usuarios debido a que los siguientes correos electrónicos ya existían: {mensajes_correos}.')
                    else:
                        messages.success(request, f'Se han creado {usuarios_creados} usuarios exitosamente.')
                        

                    return redirect('carga_masiva')

            except Exception as e:
                messages.error(request, f'Error general: {e}')

    else:
        form = CSVUploadForm(user=request.user)

    return render(request, 'registration/carga_masiva.html', {'form': form})


##Vista envío correo con invitación para el registro
import base64
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail

from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import send_mail
from .forms import EmailInvitationForm  # Asegúrate de importar correctamente tu formulario
import base64
from .models import Area  # Asegúrate de importar tu modelo Area

@login_required
def invitacion_email(request):
    usuario = request.user
    selected_area_name = None

    if usuario.empresa:
        id_empresa = usuario.empresa.id
        id_empresa_codificado = base64.urlsafe_b64encode(str(id_empresa).encode()).decode()
    else:
        id_empresa = ''
        id_empresa_codificado = ''

    if request.method == 'POST':
        form = EmailInvitationForm(request.POST, user=usuario)
        if form.is_valid():
            emails_destinatarios = form.cleaned_data['email']
            area_id_codificado = request.POST.get('area_id')

            link_registro = f"http://192.168.1.38/autenticacion/form_invitacion/?empresa_id={id_empresa_codificado}"
            if area_id_codificado:
                try:
                    area_id = base64.urlsafe_b64decode(area_id_codificado.encode()).decode()
                    area_seleccionada = Area.objects.get(id=area_id)
                    selected_area_name = area_seleccionada.nombre
                    link_registro += f"&area_id={area_id_codificado}"
                except (TypeError, ValueError, Area.DoesNotExist):
                    messages.error(request, 'ID de área inválido.')
                    return redirect('invitacion_email')

            mensaje_personalizado = form.cleaned_data.get('mensaje_personalizado')

            if not mensaje_personalizado.strip():
                mensaje_personalizado = (
                    f"Te invitamos a unirte a la área de {selected_area_name} en Kabasis. "
                    f"Regístrate en {link_registro} y comienza a explorar cursos y recursos en seguridad digital."
                )

            for email_destinatario in emails_destinatarios:
                send_mail(
                    'Invitación para unirse a Kabasis',
                    mensaje_personalizado,
                    'tu_email@ejemplo.com',
                    [email_destinatario],
                    fail_silently=False,
                )

            messages.success(request, 'Invitación enviada con éxito.')
            return redirect('invitacion_email')
    else:
        form = EmailInvitationForm(user=usuario, selected_area_name=selected_area_name)

    context = {
        'form': form,
        'link_registro_base': 'http://192.168.1.38/autenticacion/form_invitacion/',
        'id_empresa_codificado': id_empresa_codificado,
        'razon_social': usuario.empresa.razon_social if usuario.empresa else '',
    }
    return render(request, "registration/email_invitacion.html", context)


#Formulario invitación
def form_invitacion(request):
    # Obtiene los IDs directamente desde la URL sin decodificar
    empresa_id_codificado = request.GET.get('empresa_id')
    area_id_codificado = request.GET.get('area_id')

    # Verifica si se proporcionó el ID de la empresa
    if empresa_id_codificado:
        empresa_id = base64.urlsafe_b64decode(empresa_id_codificado.encode()).decode()
    else:
        messages.error(request, "No se proporcionó ID de empresa.")
        return redirect('login')
    
    if area_id_codificado:
        area_id = base64.urlsafe_b64decode(area_id_codificado.encode()).decode()
    else:
        area_id = None

    # Manejo del formulario
    if request.method == 'POST':
        form = UserAndEmpresaEmailForm(request.POST, request.FILES, empresa_id=empresa_id, area_id=area_id)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_first_login = False  # Establecer is_first_login a False
            user.save()

            # Autenticar y loguear al usuario
            email = form.cleaned_data.get('email')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(email=email, password=raw_password)
            if user is not None:
                login(request, user)

            messages.success(request, "Te has registrado con éxito")
            return redirect('survey')  # Asegúrate de reemplazar 'alguna_ruta_post_registro' con una ruta válida
    else:
        form = UserAndEmpresaEmailForm(empresa_id=empresa_id, area_id=area_id)

    return render(request, 'registration/form_invitacion.html', {'form': form})


from metodoPago.models import RegistroTransaccion

#iniciar sesión
from django.urls import reverse
from django.contrib.auth.views import LoginView

class CustomLoginView(LoginView):
    form_class = CustomLoginForm

    def form_invalid(self, form):
        """
        Si el formulario es inválido, vuelve a renderizar la página de inicio de sesión
        con los errores del formulario.
        """
        return render(self.request, self.template_name, {'form': form})

    def get_success_url(self):
        user = self.request.user

        if user.is_authenticated:
            # Verificación para usuarios que inician sesión por primera vez
            if user.is_first_login:
                if user.is_superuser or user.tipo_usuario == "Administrador":
                    user.is_first_login = False
                    user.save()
                    return reverse('registro_empresa')
                elif user.tipo_usuario == 'Alumno':
                    return reverse('edit_profile')

            # Redirecciones basadas en el tipo de usuario
            if user.tipo_usuario == 'Alumno':
                return reverse('survey')
            elif user.tipo_usuario in ['Administrador Kabasis', 'Asistente']:
                return reverse('Home')
            elif user.tipo_usuario == 'Administrador' and (user.empresa is None or not user.empresa.razon_social):
                # Verifica si el usuario no tiene empresa asociada o si la empresa no tiene nombre
                return reverse('registro_empresa')
            else:
                return reverse('Home')

        return super().get_success_url()



#cerrar sesión
def custom_logout(request):
    logout(request)
    return redirect('Home')  # Redirige a la página principal después del cierre de sesión


#vista para registrar la empresa y las áreas
@login_required
def registro_empresa(request):
    user = request.user

    # Intentar obtener la empresa existente del usuario, si existe
    empresa = getattr(user, 'empresa', None)

    if request.method == 'POST':
        form = EmpresaForm(request.POST, instance=empresa)

        if form.is_valid():
            form.save(user=user)
            messages.success(request, "Información de la empresa registrada con éxito.")
            return redirect('crear_area_inicio')  # Cambia esto por la URL a la que deseas redirigir después del registro
    else:
        # Prellenar el formulario con los datos de la empresa existente, si existe
        form = EmpresaForm(instance=empresa)

    return render(request, 'registration/registro_empresa.html', {'form': form})


#Hacer que cada vez que se cree un superUsuario siempre sea "Administrador Kabasis"
from django.db.models.signals import pre_save
from django.dispatch import receiver

@receiver(pre_save, sender=CustomUser)
def set_default_tipo_usuario(sender, instance, **kwargs):
    if instance.pk is None and instance.is_superuser:
        instance.tipo_usuario = 'Administrador Kabasis'


##Reestablecer la contraseña




