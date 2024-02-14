from django.urls import path
from . import views

urlpatterns = [

    path('', views.survey, name='survey'),
    path('crear_pregunta/', views.create_question, name='crear_pregunta'),
    path('preguntas/', views.preguntas, name='preguntas'),
    path('survey/formulario/', views.formulario, name='formulario'),
    path('resultado/', views.resultado, name='resultado'),
    # delete_question
    path('delete_question2/<int:id>/', views.delete_question2, name='delete_question2'),
    # actualizar pregunta usando el mismo formulario de crear pregunta
    path('update_question/<int:id>/', views.update_question, name='update_question'),   
    path('descripcion_survey/', views.descripcion_survey, name='descripcion_survey'),
 
]

