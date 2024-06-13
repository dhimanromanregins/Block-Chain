from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator,MaxLengthValidator, MaxValueValidator, MinValueValidator, validate_email
class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[
            MinLengthValidator(8, message="Password must be at least 8 characters long."),
        ]
    )

    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[
            MinLengthValidator(8, message="Confirm Password must be at least 8 characters long."),
        ]
    )

    class Meta:
        model = CustomUser
        fields = ("id",'username', 'password', 'confirm_password','secret_phrase_1')

        extra_kwargs = {
            'username': {'required': True, 'validators': [MinLengthValidator(4), MaxLengthValidator(150)]},
        }

    def validate(self, data):
        # Check if password and confirm_password match
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError("Password and confirm_password do not match.")
        return data

    def create(self, validated_data):
        # Remove confirm_password from the validated_data
        validated_data.pop('confirm_password', None)
        # Create a new user with a hashed password
        user = CustomUser.objects.create_user(**validated_data)
        return user
    


##############################################################################################################################################################################
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'confirm_password')

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8, max_length=128)


class ApiKeysSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApiKeys
        fields = ['user', 'Api_key']

class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = ['id', 'full_name', 'email', 'phone_number', 'message']