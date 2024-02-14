from django.shortcuts import render, redirect, get_object_or_404
from .forms import CursoForm, UnidadForm, VideoForm, QuestionForm, AnswerForm
from .models import Curso, Progreso, UnidadCurso, QuestionContent, AnswerContent, QuizContent, Video, UnidadCurso
from django.contrib import messages
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from itertools import chain


def cursos(request):
    cursos = Curso.objects.all()
    data = {

        'cursos': cursos
    }
    return render(request, "CursosApp/cursos.html", data)

def agregar_curso(request):

    data = {
        'form': CursoForm()

    }
    
    if request.method == 'POST':
        formulario = CursoForm(data=request.POST, files=request.FILES)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, 'Curso creado con éxito.')
        else: 
            data["form"] = formulario
    
    return render(request, "CursosApp/agregar_curso.html", data)

def listar_curso(request):
    cursos = Curso.objects.all()

    data = {
        'cursos': cursos
    }

    return render(request, "CursosApp/listar_curso.html", data)


def modificar_curso(request, id):

    curso = get_object_or_404(Curso, id=id)

    data= {
        'form': CursoForm(instance = curso)
    }

    if request.method == 'POST':
        formulario = CursoForm(data=request.POST, instance=curso, files=request.FILES)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, "Curso actualizado correctamente")
            return redirect(to="listar_curso")
        
        data["form"] = formulario
    
    return render(request, "CursosApp/modificar_curso.html", data)

def eliminar_curso(request, id):
    curso = get_object_or_404(Curso, id=id)
    curso.delete()
    messages.success(request, 'Curso eliminado con éxito.')
    return redirect(to="listar_curso")


##Ver el curso, las unidades
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Curso, UnidadCurso, QuizContent, Video
from .forms import CursoForm
from django.contrib import messages

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Curso, UnidadCurso, QuizContent, Video

@login_required
def ver_curso(request, id):
    # Verifica si hay cursos en la base de datos
    if not Curso.objects.exists():
        # Verifica si el usuario es un Administrador Kabasis
        if request.user.tipo_usuario == 'Administrador Kabasis':
            # Redirige al formulario de creación de cursos
            return redirect('agregar_curso')
        if request.user.tipo_usuario == 'Administrador':
            # Muestra un mensaje de advertencia
            messages.success(request, "WARNING:Aún no se crean cursos en la plataforma")
            # Redirige al home
            return redirect('Home')  # Asegúrate de reemplazar 'nombre_de_tu_url_home' con el nombre real de tu URL de home

    curso = Curso.objects.get(pk=id)
    unidades = UnidadCurso.objects.filter(curso=curso).order_by('orden')

    for index, unidad in enumerate(unidades):
        unidad.margen_izquierdo = index * 100

    quiz = QuizContent.objects.filter(curso=curso).order_by('orden')  
    video = Video.objects.filter(curso=curso).order_by('orden')
    
    data = {
        'curso': curso,
        'unidades': unidades,
        'quiz': quiz, 
        'video': video
    }

    return render(request, 'CursosApp/ver_curso.html', data)




def obtener_contenidos(request):
    usuario = request.user
    unidad_id = request.GET.get('unidad_id', None)

    if unidad_id is not None:
        try:
            unidad = UnidadCurso.objects.get(id=unidad_id)
        except UnidadCurso.DoesNotExist:
            return JsonResponse({'error': 'Unidad no encontrada'}, status=404)

        quizzes = QuizContent.objects.filter(unidad=unidad).order_by('orden')
        videos = Video.objects.filter(unidad=unidad).order_by('orden')

        # Combina las listas de quizzes y videos
        contenidos = sorted(list(quizzes) + list(videos), key=lambda contenido: contenido.orden)

        # Prepara la respuesta JSON
        data = []
        for contenido in contenidos:
            contenido_dict = {
                'id': contenido.id,
                'titulo': contenido.titulo,
            }

            # Verifica si el contenido es un objeto de tipo Video
            if isinstance(contenido, Video) and hasattr(contenido, 'video_url'):
                contenido_dict['video_url'] = contenido.video_url

            data.append(contenido_dict)


        return JsonResponse(data, safe=False)

    # Si no se proporciona unidad_id o hay otro error
    return JsonResponse({'error': 'Solicitud inválida'}, status=400)


def obtener_contenidos(request):
    usuario = request.user
    unidad_id = request.GET.get('unidad_id', None)

    if unidad_id is not None:
        try:
            unidad = UnidadCurso.objects.get(id=unidad_id)
        except UnidadCurso.DoesNotExist:
            return JsonResponse({'error': 'Unidad no encontrada'}, status=404)

        quizzes = QuizContent.objects.filter(unidad=unidad).order_by('orden')
        videos = Video.objects.filter(unidad=unidad).order_by('orden')

        # Combina las listas de quizzes y videos
        contenidos = sorted(list(quizzes) + list(videos), key=lambda contenido: contenido.orden)

        # Prepara la respuesta JSON
        data = []
        for contenido in contenidos:
            contenido_dict = {
                'id': contenido.id,
                'titulo': contenido.titulo,
                'visto': False  # Valor predeterminado
            }

            # Verifica si es un video y si ha sido visto
            if isinstance(contenido, Video):
                contenido_dict['video_url'] = contenido.video_url
                contenido_dict['visto'] = Progreso.objects.filter(
                    user=usuario, 
                    unidad=contenido.unidad,
                    videos_vistos=contenido).exists()

            # Agrega aquí la lógica para los quizzes si es necesario
            

            data.append(contenido_dict)

        return JsonResponse(data, safe=False)

    # Si no se proporciona unidad_id o hay otro error
    return JsonResponse({'error': 'Solicitud inválida'}, status=400)



############################## UNIDADES ######################################



def agregar_unidad(request):
    if request.method == 'POST':
        formulario = UnidadForm(request.POST, request.FILES)
        if formulario.is_valid():
            unidad = formulario.save(commit=False)  # No guardar inmediatamente para asignar curso
            curso_id = request.POST.get('curso')  # Asumiendo que el campo del formulario se llama 'curso'

            # Concatenar el nombre del curso al título de la unidad
            unidad.titulo = f"{unidad.titulo}"

            unidad.save()  # Ahora guarda la unidad con el curso asignado y el nombre modificado
            messages.success(request, 'Unidad creada con éxito.')
            formulario = UnidadForm() 
        else:
            messages.error(request, 'Error al crear la unidad. Por favor, verifica el formulario.')
    else:
        formulario = UnidadForm()

    data = {'form': formulario}
    return render(request, "unidades/agregar_unidad.html", data)



@login_required
def listar_unidad(request, id):
    curso = Curso.objects.get(pk=id)
    unidades = UnidadCurso.objects.filter(curso=curso).order_by('orden')

    # Calcula los márgenes para los botones restantes
    margen_izquierdo = [(unidad.orden - 2) * 100 for unidad in unidades[2:]]

    data = {
        'curso': curso,
        'unidades': unidades,
        'margen_izquierdo': margen_izquierdo,
    }

    return render(request, 'unidades/listar_unidad.html', data)




def eliminar_unidad(request, id):
    unidad = get_object_or_404(UnidadCurso, pk=id)
    curso_id = unidad.curso.id  # Obtiene el ID del curso al que pertenece la unidad
    unidad.delete()
    
    # Modifica la siguiente línea para pasar el ID correctamente
    return redirect('listar_unidad', id=curso_id)




def modificar_unidad(request, id):
    unidad = get_object_or_404(UnidadCurso, id=id)
    curso_id = unidad.curso.id  # Obtiene el ID del curso al que pertenece la unidad

    data = {
        'form': UnidadForm(instance=unidad)
    }

    if request.method == 'POST':
        formulario = UnidadForm(data=request.POST, instance=unidad, files=request.FILES)
        if formulario.is_valid():
            formulario.save()
            messages.success(request, "Unidad actualizada correctamente")
            
            # Redirige a la vista 'listar_unidad' con el ID del curso como parámetro
            return redirect('listar_unidad', id=curso_id)

        data["form"] = formulario

    return render(request, "unidades/modificar_unidad.html", data)




def ver_video(request, video_id):
    video = get_object_or_404(Video, pk=video_id)
    idCurso = video.curso_id

    return render(request, 'video/ver_videos.html', {'video': video , 'idCurso': idCurso})


#################CONTENIDO#################



# Preguntas: crear, eliminar y actualizar
# Preguntas: crear, eliminar y actualizar
def crear_question(request, id):
    if request.method == 'POST':
        form = QuestionForm(request.POST)
        if form.is_valid():
            # Crear una nueva instancia de Question y asignar el quiz
            question = QuestionContent(quiz_id=id)
            question.question_type = form.cleaned_data['question_type']
            question.text = form.cleaned_data['text']
            question.option_a = form.cleaned_data['option_a']
            question.option_b = form.cleaned_data['option_b']
            question.option_c = form.cleaned_data['option_c']
            question.option_d = form.cleaned_data['option_d']
            question.correct_answer = form.cleaned_data['correct_answer']
            question.save()
            # Redirigir a la página del quiz
            return redirect(reverse('listar_quiz', args=[id]))
    else:
        form = QuestionForm()
    return render(request, 'quiz/crear_preguntaContent.html', {'form': form, 'id_quiz': id})



def delete_question(request, id):
    question = QuestionContent.objects.get(quiz_id=id)

    question.delete()
    return redirect(reverse('listar_quiz', args=[id]))


# def update_question, este tendra un formulario para actualizar la pregunta
def update_question(request, id):

    if request.method == 'POST':
        form = QuestionForm(request.POST)
        question = QuestionContent.objects.get(quiz_id=id)
        tipo = question.question_type

        if form.is_valid():
            # guardar la pregunta y sus opciones, usando el id de la pregunta

            if tipo == 'text':
                #form = QuestionForm(initial={'text': question.text})
                # guardar las preguntas con el formulario de texto
                question.text = form.cleaned_data['text']
                question.save()
                return redirect(reverse('listar_quiz', args=[id]))

            else:
                #form = QuestionForm(initial={'text': question.text, 'option_a': question.option_a, 'option_b': question.option_b, 'option_c': question.option_c, 'option_d': question.option_d, 'correct_answer': question.correct_answer})

                question.text = form.cleaned_data['text']
                question.option_a = form.cleaned_data['option_a']
                question.option_b = form.cleaned_data['option_b']
                question.option_c = form.cleaned_data['option_c']
                question.option_d = form.cleaned_data['option_d']
                question.correct_answer = form.cleaned_data['correct_answer']
                question.save()
                return redirect(reverse('listar_quiz', args=[id]))
        else:
            if tipo == 'text':
                form = QuestionForm(initial={'text': question.text})
            else:
                form = QuestionForm(initial={'text': question.text, 'option_a': question.option_a, 'option_b': question.option_b, 'option_c': question.option_c, 'option_d': question.option_d, 'correct_answer': question.correct_answer})
        
   
    return render(request, 'update_question.html', {'form': form, 'question': question, 'tipo': tipo})


# mostrar los enlaces de todos los quiz creados para cada unidad y curso:


def listar_material(request, idCurso, unidad):
    quizzes = QuizContent.objects.filter(curso_id=idCurso, unidad_id=unidad)
    video = Video.objects.filter(curso_id=idCurso, unidad_id=unidad)

    # Combina ambas consultas y ordena por el campo 'orden'
    content_list = sorted(chain(quizzes, video), key=lambda x: x.orden)

    # Obtener valores únicos de orden
    order_values = set(content.orden for content in content_list)

    idCurso = idCurso
    unidad = unidad

    return render(request, 'admContenido/listar_material.html', {'content_list': content_list, 'idCurso': idCurso, 'unidad': unidad, 'order_values': order_values})


def actualizar_orden(request, model_name, content_id, new_order):
    model_mapping = {
        'quiz': QuizContent,
        'video': Video,
    }

    model_class = model_mapping.get(model_name)
    

    if not model_class:
        return JsonResponse({'status': 'error', 'message': 'Modelo no válido'})

    content = get_object_or_404(model_class, id=content_id)

    # Guardar el orden antiguo antes de actualizarlo
    old_order = content.orden

    # Buscar si existe algún contenido con el nuevo orden
    

    if QuizContent.objects.filter(orden=new_order).first():
        # Intercambiar los órdenes inmediatamente
        existing_content = QuizContent.objects.get(orden=new_order)
        existing_content.orden = old_order 
        existing_content.save()


    if Video.objects.filter(orden=new_order).first():
        # Intercambiar los órdenes
        existing_content = Video.objects.get(orden=new_order)
        existing_content.orden = old_order
        existing_content.save()

    # Actualizar el campo de orden
    content.orden = new_order
    content.save()

    return JsonResponse({'status': 'success', 'new_order': new_order})


#Quiz: crear, editar, eliminar y listar

# views.py


def crear_quiz(request, idCurso, unidad):
    if request.method == 'POST':
        titulo = request.POST.get('titulo')
        descripcion = request.POST.get('descripcion')
        orden = request.POST.get('orden')

        # Crear instancia del modelo con los datos del formulario
        quiz = QuizContent(
            curso_id=idCurso,
            unidad_id=unidad,
            titulo=titulo,
            descripcion=descripcion,
            orden=orden
        )
        quiz.save()

        # Redireccionar a donde desees después de guardar el quiz
        return redirect(reverse('listar_material', args=[idCurso, unidad]))

    # Renderizar el formulario para la creación del quiz
    return render(request, 'quiz/crear_quiz.html', {'idCurso': idCurso, 'unidad': unidad})


# edit_quiz solo envia a la lista de quiz
def edit_quiz(request, id):
    quiz = QuizContent.objects.get(id=id)
    idCurso = quiz.curso_id
    unidad = quiz.unidad_id
    return redirect(reverse('listar_quiz', args=[quiz.id]))

def editar_info_quiz(request, id):
    quiz = get_object_or_404(QuizContent, id=id)

    if request.method == 'POST':
        # Actualizar los campos necesarios
        quiz.titulo = request.POST.get('titulo')
        quiz.descripcion = request.POST.get('descripcion')
        quiz.orden = request.POST.get('orden')
        quiz.save()
        
        return redirect(reverse('listar_quiz' , args=[quiz.id]))

    return render(request, 'quiz/editar_info_quiz.html', {'quiz': quiz})

def update_orders_after_delete(model_class, deleted_order):
    # Obtener todos los elementos con un orden mayor al eliminado
    # si model_class es QuizContent, entonces ver si existen videos y quiz con orden mayor al eliminado y restarle 1


    quizs = QuizContent.objects.filter(orden__gt=deleted_order)
    videos = Video.objects.filter(orden__gt=deleted_order)

    # Actualizar el orden de los quiz
    for quiz in quizs:
        quiz.orden -= 1
        quiz.save()
    
    # Actualizar el orden de los videos
    for video in videos:
        video.orden -= 1
        video.save()


# Eliminar quiz y sus preguntas
def delete_quiz(request, id):
    quiz = QuizContent.objects.get(id=id)
    quiz.delete()
    return redirect(reverse('listar_material', args=[quiz.curso_id, quiz.unidad_id]))

def listar_quiz(request, id):
    quiz = QuizContent.objects.get(id=id)
    idCurso = quiz.curso_id
    unidad = quiz.unidad_id
    questions = QuestionContent.objects.filter(quiz_id=id)
    return render(request, 'quiz/listar_quiz.html', {'questions': questions, 'quiz':quiz ,'idCurso': idCurso, 'unidad': unidad})


def formulario2(request, id):
    # Obtener todas las preguntas
    questions = QuestionContent.objects.filter(quiz_id=id)
    if request.method == 'POST':
        
        for pregunta in questions:
            question_id = request.POST.get(f'question_id_{pregunta.id}')
            text_answer = request.POST.get(f'text_answer_{pregunta.id}')
            option_answer = request.POST.get(f'option_answer_{pregunta.id}')
            # if form.is_valid():
            # Guardar la respuesta
            answer = AnswerContent()
            # answer question es id de la pregunta
            answer.question = QuestionContent.objects.get(id=question_id)
            # answer user es el usuario que esta respondiendo la pregunta
            answer.user = request.user
            answer.text_answer = text_answer
            # answer option_answer es la opcion que el usuario selecciono, puede ser null
            # si es nulo y por lo tanto diferente de a, b, c, d, entonces no se guarda
            if option_answer in ['a', 'b', 'c', 'd']:
                answer.option_answer = option_answer

            answer.save()



        return redirect('agradecimientos')
    else:
        form = AnswerForm()

    return render(request, 'admContenido/formulario.html', {'form': form, 'questions': questions})


# def agradecimientos, este tendra un mensaje de agradecimiento por haber respondido la encuesta
def agradecimientos(request):
    return render(request, 'admContenido/agradecimientos.html')

# definimos la vista previa del quiz, este debe ser igual al formulario pero sin el boton de enviar y sin guardar las respuestas
def vista_previa(request, id):
    # Obtener todas las preguntas
    questions = QuestionContent.objects.filter(quiz_id=id)

    # Puedes hacer lo que necesites con las preguntas para la vista previa,
    # como pasarlas al template y renderizarlas

    return render(request, 'admContenido/vista_previa.html', {'id':id,'questions': questions})


def editContenido(request):
    cursos = Curso.objects.all()
    Unidad = UnidadCurso.objects.all()
    
    data = {

        'cursos': cursos,
        'unidad': Unidad,
    }
    return render(request, "admContenido/editContenido.html" , data)


def obtener_unidades(request, curso_id):
    unidades = UnidadCurso.objects.filter(curso_id=curso_id).values('id','titulo')
    curso_nombre = Curso.objects.get(id=curso_id).nombre
    
    data = {
        'cursoNombre': curso_nombre,
        'unidades': list(unidades)
    }
    
    return JsonResponse(data)


# por cada unidad y curso enlistar los contenidos, quiz, videos y actividades desde la base de datos y modelos
def obtener_contenido(request, unidad_id):
    # obtener el contenido de la unidad
    # obtener los videos de la unidad
    # obtener los quiz de la unidad
    quiz = QuizContent.objects.filter(unidad_id=unidad_id).values('id','question_id')
    # listar lo anterior para mostrarlo en la vista
    data = {
        
        'quiz': list(quiz),
    }
    # retornar la data en formato json para que pueda ser leida por javascript
    return JsonResponse(data)


############Video######################
def crear_video(request, idCurso, unidad):
    if request.method == 'POST':
        form = VideoForm(request.POST)
        if form.is_valid():
            # Crear una nueva instancia de Contenido y asignar el curso y unidad
            video = Video(curso_id=idCurso, unidad_id=unidad)
            video.titulo = form.cleaned_data['titulo']
            video.video_url = form.cleaned_data['video_url']
            video.descripcion = form.cleaned_data['descripcion']
            video.orden = form.cleaned_data['orden']
            video.save()
            # Redirigir a la página del quiz
            return redirect(reverse('listar_material', args=[idCurso, unidad]))
    else:
        form = VideoForm()
    return render(request, 'video/crear_video.html', {'form': form, 'idCurso': idCurso, 'unidad': unidad})


def agregar_video(request):
    if request.method == 'POST':
        formulario = VideoForm(request.POST, request.FILES)
        if formulario.is_valid():
            video = formulario.save(commit=False)  # No guardar inmediatamente para asignar curso
            unidad_id = request.POST.get('unidad')  # Asumiendo que el campo del formulario se llama 'curso'
            unidad = UnidadCurso.objects.get(pk=unidad_id)  # Obtén el curso correspondiente desde la base de datos
            # Concatenar el nombre del curso al título de la unidad
            video.titulo = f"{unidad.titulo} - {video.titulo}"
            video.unidad = unidad  # Asignar el curso al que pertenece esta unidad
            video.save()  # Ahora guarda la unidad con el curso asignado y el nombre modificado
            messages.success(request, 'video creado con éxito.')
            formulario = VideoForm() 
        else:
            messages.error(request, 'Error al crear el video. Por favor, verifica el formulario.')
    else:
        formulario = VideoForm()

    data = {'form': formulario}
    return render(request, "video/agregar_video.html", data)





def listar_video(request, id=None):
    if id:
        videos = Video.objects.filter(unidad__curso_id=id)
    else:
        videos = Video.objects.all()

    data = {
        'videos': videos,
    }

    return render(request, 'video/listar_video.html', data)



def eliminar_video(request, id):
    video = get_object_or_404(Video, pk=id)
    deleted_video_order = Video.objects.get(id=id).orden
    unidad_id = video.unidad.id  # Obtiene el ID del curso al que pertenece la unidad

    video.delete()
    update_orders_after_delete(Video, deleted_video_order)
    messages.success(request, "video eliminado correctamente")
    # Modifica la siguiente línea para pasar el ID correctamente
    # return a listar_material con el idCurso y unidad
    return redirect('listar_material', idCurso=video.curso.id, unidad=unidad_id)




def editar_video(request, id):
    video = Video.objects.get(id=id)
    idCurso = video.curso_id
    unidad = video.unidad_id

    if request.method == 'POST':
        form = VideoForm(request.POST, instance=video)  # Utiliza instance=video aquí
        if form.is_valid():
            form.save()
            return redirect(reverse('listar_material', args=[idCurso, unidad]))
    else:
        form = VideoForm(instance=video)  # Y aquí también

    return render(request, 'video/modificar_video.html', {'form': form, 'idCurso': idCurso, 'unidad': unidad})




def update_progress(request):
    video_id = request.POST.get('video_id')
    user = request.user

    try:
        video = Video.objects.get(id=video_id)
        progreso, created = Progreso.objects.get_or_create(user=user, unidad=video.unidad)
        progreso.videos_vistos.add(video)
        progreso.save()

        return JsonResponse({'status': 'success', 'message': 'Progreso actualizado.'})
    except Video.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Video no encontrado.'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    


