from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone
import datetime
import random
# User = get_user_model()

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)



class User(AbstractBaseUser):
    firstname = models.CharField(max_length=30)
    lastname = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    profile_image = models.FileField(upload_to='profile_images/', null=True, blank=True) 
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['firstname', 'lastname', 'phone']

    def __str__(self):
        return self.email

    def is_otp_valid(self):
        if self.otp_created_at:
            return timezone.now() < self.otp_created_at + datetime.timedelta(minutes=5)
        return False


class GuideEnrollment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='guide_enrollments')
    role_description = models.TextField()
    enrollment_date = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.email} - Guide Enrollment"

