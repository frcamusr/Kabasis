from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from .forms import QuestionForm, AnswerForm
from .models import Question, Answer, Puntaje
from django.contrib.auth.decorators import login_required
from CursosApp.models import Curso, UnidadCurso
from django.contrib.auth.models import User
from django.urls import reverse
from django.http import HttpResponseRedirect





@login_required
def survey(request):
    # si el usuario ya ha completado el formulario, redirigir a la pagina home
    usuario_ya_completo_formulario = Answer.objects.filter(user=request.user).exists()
    if usuario_ya_completo_formulario:
        # este debe enviar a la pagina kabasisWeb.urls a la vista vacia
        return HttpResponseRedirect('/cursos/ver_curso/1/')
    else:
        return render(request, 'completarSurvey.html')


def preguntas(request):
    questions = Question.objects.all()
    return render(request, 'preguntas.html', {'questions': questions})


def create_question(request):
    if request.method == 'POST':
        form = QuestionForm(request.POST)
        if form.is_valid():
            # Guardar la pregunta y sus opciones
            question = Question()
            question.question_type = form.cleaned_data['question_type']
            question.text = form.cleaned_data['text']
            question.option_a = form.cleaned_data['option_a']
            question.option_b = form.cleaned_data['option_b']
            question.option_c = form.cleaned_data['option_c']
            question.option_d = form.cleaned_data['option_d']
            question.correct_answer = form.cleaned_data['correct_answer']
            question.save()
        return redirect('preguntas')
    else:
        form = QuestionForm()
    return render(request, 'crear_pregunta.html', {'form': form})


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session
from django.utils import timezone
from .models import Question, Answer

@login_required
def formulario(request):
    # Verificar si el usuario ya ha completado el formulario
    usuario_ya_completo_formulario = Answer.objects.filter(user=request.user).exists()
    if usuario_ya_completo_formulario:
        # Si el usuario ya ha completado el formulario, redirige a la página de resultado
        return redirect('resultado')  # Reemplaza con el nombre de tu vista de resultado

    # Obtener todas las preguntas
    questions = Question.objects.all()

    if request.method == 'POST':
        # Procesar respuestas del formulario
        for pregunta in questions:
            question_id = request.POST.get(f'question_id_{pregunta.id}')
            text_answer = request.POST.get(f'text_answer_{pregunta.id}')
            option_answer = request.POST.get(f'option_answer_{pregunta.id}')

            # Guardar la respuesta
            answer = Answer()
            answer.question = Question.objects.get(id=question_id)
            answer.user = request.user
            answer.text_answer = text_answer

            # Verificar si option_answer es una opción válida (a, b, c, d)
            if option_answer in ['a', 'b', 'c', 'd']:
                answer.option_answer = option_answer

            answer.save()

        # Redirigir a la página de resultado después de procesar el formulario
        return redirect('resultado')  # Reemplaza con el nombre de tu vista de resultado

    return render(request, 'formulario.html', {'questions': questions})


def delete_question2(request, id):
    question = Question.objects.get(id=id)
    question.delete()
    return redirect('preguntas')


# def resultado, este mostrara el porcentaje de respuestas correctas comparando answer.option_answer con question.correct_answer y recibiendo el id del usuario

def resultado(request):
    # Obtener todas las preguntas
    questions = Question.objects.all()
    # Obtener todas las respuestas
    answers = Answer.objects.all()
    # Obtener el usuario que esta respondiendo
    user = request.user
    # Obtener las respuestas del usuario
    answers_user = Answer.objects.filter(user=user)
    # creamos una variable para guardar el numero de respuestas correctas
    correct_answers = 0
    # con un ciclo for comparamos las respuestas del usuario con las respuestas correctas
    for answer in answers_user:
        if answer.option_answer == answer.question.correct_answer:
            correct_answers += 1
    # creamos una variable para el total de preguntas en Question
    total_questions = Question.objects.count()
    # creamos una variable para el porcentaje de respuestas correctas
    porcentaje = (correct_answers / total_questions) * 100

    # redondeamos el porcentaje sin decimales
    porcentaje = round(porcentaje, 0)
    # convertimos el porcentaje a entero
    porcentaje = int(porcentaje)

    # guardamos en la base de datos Puntaje el porcentaje y el usuario
    puntaje = Puntaje()
    puntaje.porcentaje = porcentaje
    puntaje.user = user
    puntaje.save()
    

    # retornamos el porcentaje
    return render(request, 'resultado.html', {'porcentaje': porcentaje})


# def update_question, este tendra un formulario para actualizar la pregunta
def update_question(request, id):

    if request.method == 'POST':
        form = QuestionForm(request.POST)
        question = Question.objects.get(id=id)
        tipo = question.question_type
 
        
        if form.is_valid():
            # guardar la pregunta y sus opciones, usando el id de la pregunta
            if tipo == 'text':
                #form = QuestionForm(initial={'text': question.text})
                # guardar las preguntas con el formulario de texto
                question.text = form.cleaned_data['text']
                question.save()
                return redirect('preguntas')

            else:
                #form = QuestionForm(initial={'text': question.text, 'option_a': question.option_a, 'option_b': question.option_b, 'option_c': question.option_c, 'option_d': question.option_d, 'correct_answer': question.correct_answer})
                question.text = form.cleaned_data['text']
                question.option_a = form.cleaned_data['option_a']
                question.option_b = form.cleaned_data['option_b']
                question.option_c = form.cleaned_data['option_c']
                question.option_d = form.cleaned_data['option_d']
                question.correct_answer = form.cleaned_data['correct_answer']
                question.save()
                return redirect('preguntas')
        else:
            if tipo == 'text':
                form = QuestionForm(initial={'text': question.text})
            else:
                form = QuestionForm(initial={'text': question.text, 'option_a': question.option_a, 'option_b': question.option_b, 'option_c': question.option_c, 'option_d': question.option_d, 'correct_answer': question.correct_answer})
        
   
    return render(request, 'update_question.html', {'form': form, 'question': question, 'tipo': tipo})


def descripcion_survey(request):
    return render(request, 'descripcion_survey.html')
