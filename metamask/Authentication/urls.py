
from django.urls import path
from .views import *

urlpatterns = [
    path('register/', CustomUserRegistration.as_view(), name='user-registration'),
    path('api/secret-phrases/<str:username>/', SecretPhrasesList.as_view(), name='secret-phrases-list'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/change-password/', ChangePasswordView.as_view(), name='change-password'),
    ########################################################################################################################################

    path('Webregister/', RegisterView.as_view(), name='Webregister'),
    path('verify-otp/', OTPVerifyView.as_view(), name='verify-otp'),
    path('Weblogin/', WebLoginView.as_view(), name='Weblogin'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('encrypt-decrypt/', EncryptDecryptView.as_view(), name='encrypt_decrypt'),
    path('api-keys/', ApiKeyView.as_view(), name='api-keys'),
    path('contact-us/', ContactUsCreateView.as_view(), name='contact-us-create'),
]