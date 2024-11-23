from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate,get_user_model
from rest_framework import serializers
from django.core.mail import send_mail
from .models import User,GuideEnrollment
from django.utils import timezone
import random

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirmpass = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'firstname', 'email', 'phone', 'profile_image', 'password', 'confirmpass']
        # extra_kwargs = {
        #     'profile_image': {'required': False} 
        # }

    def validate(self, data):
        if data['password'] != data['confirmpass']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('confirmpass')
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                              username=email, 
                              password=password)
            if not user:
                raise serializers.ValidationError("Invalid login credentials.")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled.")
        else:
            raise serializers.ValidationError("Both 'email' and 'password' are required.")
        
        # Return the actual user object, not a dict
        return {
            'email': email,
            'user': user
        }

class GenerateOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        email = data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        
        return data
    

    def create(self, validated_data):
        email = validated_data.get('email')
        user = User.objects.get(email=email)

        

        # Generate and set OTP
        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        # Send email with OTP
        send_mail(
            'Your OTP Code',
            f'Your OTP is {otp}',
            'noreply@example.com',
            [user.email],
            fail_silently=False,
        )

        return  {'user': user, 'otp': otp} 


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        if not user.otp:
            raise serializers.ValidationError("OTP not generated for this user.")

        if not user.is_otp_valid():
            raise serializers.ValidationError("OTP has expired.")

        if user.otp != otp:
            raise serializers.ValidationError("Invalid OTP.")

        return data


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        if not user.check_password(old_password):
            raise serializers.ValidationError("Old password is incorrect.")

        if new_password != confirm_password:
            raise serializers.ValidationError("New passwords do not match.")

        return data

    def create(self, validated_data):
        email = validated_data.get('email')
        new_password = validated_data.get('new_password')

        user = get_user_model().objects.get(email=email)
        user.set_password(new_password)
        user.save()

        return {'email': email, 'new_password': new_password}


def generate_otp():
    return f"{random.randint(100000, 999999)}"


class GuideEnrollmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = GuideEnrollment
        fields = ['id', 'user', 'role_description', 'enrollment_date', 'is_approved', 'is_active']
