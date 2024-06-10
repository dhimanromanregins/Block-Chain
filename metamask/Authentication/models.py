from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.crypto import get_random_string
from faker import Faker
import uuid
fake = Faker()

class CustomUser(AbstractUser):
    custom_id = models.CharField(max_length=255, unique=True, editable=False)
    secret_phrase_1 = models.CharField(max_length=200, blank=True)
    secret_phrase_2 = models.CharField(max_length=200, blank=True)
    secret_phrase_3 = models.CharField(max_length=200, blank=True)
    secret_phrase_4 = models.CharField(max_length=200, blank=True)
    secret_phrase_5 = models.CharField(max_length=200, blank=True)
    secret_phrase_6 = models.CharField(max_length=200, blank=True)
    secret_phrase_7 = models.CharField(max_length=200, blank=True)
    secret_phrase_8 = models.CharField(max_length=200, blank=True)
    secret_phrase_9 = models.CharField(max_length=200, blank=True)
    secret_phrase_10 = models.CharField(max_length=200, blank=True)
    secret_phrase_11 = models.CharField(max_length=200, blank=True)
    secret_phrase_12 = models.CharField(max_length=200, blank=True)

    def save(self, *args, **kwargs):
        if not self.custom_id:
            # Generate a random 7-digit number and prepend 'ID-'
            self.custom_id = f'ID-{get_random_string(length=7, allowed_chars="1234567890")}'

        super(CustomUser, self).save(*args, **kwargs)

#############################################################################################################################################



class WebUser(AbstractUser):
    email = models.EmailField(unique=True)

    groups = models.ManyToManyField(
        Group,
        related_name='webuser_set',
        blank=True,
        help_text=('The groups this user belongs to. A user will get all permissions granted to each of their groups.'),
        verbose_name=('groups'),
    )
    
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='webuser_set',
        blank=True,
        help_text=('Specific permissions for this user.'),
        verbose_name=('user permissions'),
    )

class OTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.email} - {self.otp} - {self.created_at}'
    

class EncryptedData(models.Model):
    iv = models.CharField(max_length=24)
    encrypted_data = models.TextField()
    secretId = models.CharField(max_length=10000)
    def __str__(self):
        return f'{self.iv}'


class ApiKeys(models.Model):
    user = models.ForeignKey(WebUser, on_delete=models.CASCADE)
    Api_key = models.UUIDField(primary_key=True,default=uuid.uuid4, editable=False, unique=True)
    def __str__(self):
        return f'{self.user}'


class ContactUs(models.Model):
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone_number = models.BigIntegerField(null=True, blank=True)
    message = models.TextField()

    def __str__(self):
        return f'{self.full_name}'



