from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.http import JsonResponse
from .utils import *
from .serializers import *
import binascii
from .models import *
import uuid
from faker import Faker
import json
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login,get_user_model
from django.db.models import Q
from Crypto.Random import get_random_bytes
from django.shortcuts import get_object_or_404
import random
import string
fake = Faker()


class CustomUserRegistration(APIView):
    def post(self, request):
        username = request.data.get('username')

        if CustomUser.objects.filter(username=username).exists():
            response_data = {
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': 'Username address already in use.'
            }
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        serializer = CustomUserSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # Generate and save the secret phrases
            user.secret_phrase_1 = fake.word()
            user.secret_phrase_2 = fake.word()
            user.secret_phrase_3 = fake.word()
            user.secret_phrase_4 = fake.word()
            user.secret_phrase_5 = fake.word()
            user.secret_phrase_6 = fake.word()
            user.secret_phrase_7 = fake.word()
            user.secret_phrase_8 = fake.word()
            user.secret_phrase_9 = fake.word()
            user.secret_phrase_10 = fake.word()
            user.secret_phrase_11 = fake.word()
            user.secret_phrase_12 = fake.word()
            user.save()

            # Include the secret phrases in the response
            secret_phrases = [
                user.secret_phrase_1,
                user.secret_phrase_2,
                user.secret_phrase_3,
                user.secret_phrase_4,
                user.secret_phrase_5,
                user.secret_phrase_6,
                user.secret_phrase_7,
                user.secret_phrase_8,
                user.secret_phrase_9,
                user.secret_phrase_10,
                user.secret_phrase_11,
                user.secret_phrase_12,
            ]

            response_data = {
                'status_code': status.HTTP_201_CREATED,
                'message': 'Welcome, your account is successfully registered.',
                'secret_phrases': secret_phrases,
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        else:
            response_data = {
                'status_code': status.HTTP_400_BAD_REQUEST,
                'errors': serializer.errors
            }
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)


class SecretPhrasesList(APIView):
    def get(self, request, username):
        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        secret_phrases = [
            user.secret_phrase_1,
            user.secret_phrase_2,
            user.secret_phrase_3,
            user.secret_phrase_4,
            user.secret_phrase_5,
            user.secret_phrase_6,
            user.secret_phrase_7,
            user.secret_phrase_8,
            user.secret_phrase_9,
            user.secret_phrase_10,
            user.secret_phrase_11,
            user.secret_phrase_12,
        ]

        return Response({'secret_phrases': secret_phrases}, status=status.HTTP_200_OK)

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        secret_phrases = request.data.get('secret_phrases', [])

        if username and password:
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
        elif secret_phrases:
            # Build a query for matching secret phrases
            query = Q()
            for secret in secret_phrases:
                query &= Q(secret_phrase_1=secret) | Q(secret_phrase_2=secret) | Q(secret_phrase_3=secret) | Q(secret_phrase_4=secret) | Q(secret_phrase_5=secret) | Q(secret_phrase_6=secret) | Q(secret_phrase_7=secret) | Q(secret_phrase_8=secret) | Q(secret_phrase_9=secret) | Q(secret_phrase_10=secret) | Q(secret_phrase_11=secret) | Q(secret_phrase_12=secret)

            found_user = CustomUser.objects.filter(query).first()

            if found_user:
                # You can perform actions for secret phrase login here
                return Response({'message': 'Secret phrases matched', 'username': found_user.username, 'custom_id': found_user.custom_id}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Secret phrases do not match any user'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    def post(self, request):
        username = request.data.get('username')
        new_password = request.data.get('new_password')

        if username and new_password:
            try:
                user = CustomUser.objects.get(username=username)
                user.password = make_password(new_password)
                user.save()
                return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)
        


#################################################################################################################################################################################



User = get_user_model() 




class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if WebUser.objects.filter(email=request.data['email']).exists():
            return Response({'message': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = get_random_string(length=6, allowed_chars='0123456789')
            OTP.objects.create(email=email, otp=otp)
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'dhimansahil.ameotech@gmail.com',
                [email],
                fail_silently=False,
            )
            return Response({'message': 'OTP sent to your email'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class OTPVerifyView(APIView):
    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        print(request.data, '=========================')
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            if OTP.objects.filter(email=email, otp=otp).exists():
                user_data = {
                    'email': email,
                    'password': request.data['password'],
                    'confirm_password': request.data['confirm_password']
                }
                user_serializer = UserSerializer(data=user_data)
                if user_serializer.is_valid():
                    user_serializer.save()
                    OTP.objects.filter(email=email).delete()
                    return Response({'message': 'Registration successful'}, status=status.HTTP_201_CREATED)
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class WebLoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(username=email, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'user_id': user.id,
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                }, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

def send_reset_password_email(email, otp):
    send_mail(
        'Reset Password OTP',
        f'Your OTP for resetting password is: {otp}',
        'your_sender_email@example.com',  # Change this to your sender email
        [email],
        fail_silently=False,
    )


class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if email:
            user = WebUser.objects.filter(email=email).first()
            if user:
                otp = get_random_string(length=6, allowed_chars='0123456789')
                OTP.objects.create(email=email, otp=otp)
                send_reset_password_email(email, otp)
                return Response({'message': 'Reset OTP sent to your email'}, status=status.HTTP_200_OK)
        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    

class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
            otp_obj = OTP.objects.filter(email=email, otp=otp).first()
            if otp_obj:
                user = WebUser.objects.filter(email=email).first()
                user.set_password(new_password)
                user.save()
                otp_obj.delete()
                return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class EncryptDecryptView(APIView):
    def post(self, request):
        data = request.data
        secret_key = get_random_bytes(16)
        print("Length of secret key:", len(secret_key))
        json_data = json.dumps(data)
        clientId, encrypted_data = encrypt(json_data.encode('utf-8'), secret_key)
        EncryptedData.objects.create(iv=clientId, encrypted_data=encrypted_data, secretId=base64.b64encode(secret_key).decode('utf-8'))  # Store the secret key
        return Response({'clientId': clientId}, status=status.HTTP_201_CREATED)

    def get(self, request):
        clientId = request.query_params.get('clientId')
        clientId = clientId.replace(' ', '+')
        print(clientId, '=============')
        if clientId is None:
            return JsonResponse({'message': 'clientId is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            encrypted_data_obj = EncryptedData.objects.get(iv=clientId)
        except EncryptedData.DoesNotExist:
            return JsonResponse({'message': 'No clientId data found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            key = base64.b64decode(encrypted_data_obj.secretId)
        except binascii.Error:
            return JsonResponse({'message': 'Invalid base64-encoded key'}, status=status.HTTP_400_BAD_REQUEST)

        print("Length of secret key:", len(key))
        decrypted_data = decrypt(encrypted_data_obj.iv, encrypted_data_obj.encrypted_data, key)
        decrypted_data_dict = json.loads(decrypted_data)
        return JsonResponse(decrypted_data_dict, status=status.HTTP_200_OK)

class ApiKeysListCreateAPIView(APIView):
    def get(self, request):
        api_keys = ApiKeys.objects.all()
        serializer = ApiKeysSerializer(api_keys, many=True)
        return Response(serializer.data)

    def post(self, request):
        api_key = str(uuid.uuid4())
        request.data['Api_key'] = api_key
        serializer = ApiKeysSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def generate_api_key(self):
        key_length = 32
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(key_length))

class ApiKeysRetrieveUpdateDestroyAPIView(APIView):
    def get_object(self, pk):
        return get_object_or_404(ApiKeys, pk=pk)

    def get(self, request, pk):
        api_key = self.get_object(pk)
        serializer = ApiKeysSerializer(api_key)
        return Response(serializer.data)

    def put(self, request, pk):
        api_key = self.get_object(pk)
        serializer = ApiKeysSerializer(api_key, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        api_key = self.get_object(pk)
        api_key.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserApiKeysAPIView(APIView):
    def get(self, request):
        user_id = request.query_params.get('user_id')
        if not user_id:
            return Response({"message": "User ID is required in the query parameters."}, status=400)

        user_keys = ApiKeys.objects.filter(user_id=user_id).first()
        if user_keys:
            serializer = ApiKeysSerializer(user_keys)
            return Response(serializer.data)
        else:
            return Response({"message": "User does not have an API key."}, status=404)
    
class ContactUsCreateView(APIView):
    def post(self, request):
        serializer = ContactUsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


