from django.urls import path
from .views import GuideEnrollmentDetailView, GuideEnrollmentView, SignupView,LoginView,GenerateOTPView,VerifyOTPView,ResetPasswordView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('generate-otp/', GenerateOTPView.as_view(), name='generate_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('enrollments/', GuideEnrollmentView.as_view(), name='guide_enrollment_list'),
    path('enrollments/<int:pk>/', GuideEnrollmentDetailView.as_view(), name='guide_enrollment_detail'),
]
