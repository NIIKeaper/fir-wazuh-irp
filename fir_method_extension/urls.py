from django.urls import path
from . import views

app_name = 'fir_method_extension'

urlpatterns = [
    path('v1/siem-ingest/', views.siem_ingest_api, name='siem_ingest'),
    path('ir-dashboard/', views.ir_dashboard, name='ir_dashboard'),

    path('ir/', views.ir_queue, name='ir_queue'),
    path('ir/<int:incident_id>/', views.ir_incident_detail, name='ir_incident_detail'),
    path('ir/<int:incident_id>/accept/', views.accept_incident_action, name='accept_incident'),
    path('ir/step/<int:step_execution_id>/update/', views.complete_step_action, name='update_step'),

    path('ir/<int:incident_id>/notes/', views.save_analyst_notes, name='save_notes'),
    path('ir/<int:incident_id>/export/', views.export_incident_report, name='export_report'),
    path('ir/<int:incident_id>/export/<str:format>/', views.export_incident_report, name='export_report_format'),
    path('ir/<int:incident_id>/status/', views.update_incident_status, name='update_status'),
]