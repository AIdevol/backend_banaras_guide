from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import GuideEnrollmentSerializer, ResetPasswordSerializer, SignupSerializer, LoginSerializer,GenerateOTPSerializer, VerifyOTPSerializer
from .models import GuideEnrollment, User
from django.core.mail import send_mail
from rest_framework.permissions import IsAuthenticated

class SignupView(generics.RetrieveUpdateAPIView, generics.CreateAPIView):
    serializer_class = SignupSerializer
     
    def get_permissions(self):
        if self.request.method in ['GET', 'PUT']:
            self.permission_classes = [IsAuthenticated]
        else:
            self.permission_classes = []
        return super().get_permissions()
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = RefreshToken.for_user(user)
        return Response({
            'user': serializer.data,
            'token': {
                'refreshToken': str(token),
                'accessToken': str(token.access_token),
            }
        }, status=status.HTTP_201_CREATED)

    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)



class LoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, 
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user'] 
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': {
                'accessToken': str(refresh.access_token),
                'refreshToken': str(refresh),
                'id':user.id,
                'firstname': user.firstname,
                'lastname': user.lastname,
                'email': user.email,
                'phone': user.phone,
            },
            
        }, status=status.HTTP_200_OK)
    
class GenerateOTPView(generics.CreateAPIView):
    serializer_class = GenerateOTPSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result= serializer.save()
        return Response({"detail": "OTP has been sent to your email.",
                         "your-otp":result['otp'],}, status=status.HTTP_200_OK)


class VerifyOTPView(generics.CreateAPIView):
    serializer_class = VerifyOTPSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"detail": "OTP verified successfully."}, status=status.HTTP_200_OK)


class ResetPasswordView(generics.CreateAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Get the email and new password from the validated data
        email = serializer.validated_data['email']
        new_password = serializer.validated_data['new_password']

        # Send an email notification with the new password
        send_mail(
            'Your Password Has Been Reset',
            f'Your new password is: {new_password}',
            'noreply@example.com',
            [email],
            fail_silently=False,
        )

        return Response({
            'detail': 'Password has been reset successfully. A new password has been sent to your email.',
            'new_password': new_password,
        }, status=status.HTTP_200_OK)
    

class GuideEnrollmentView(generics.ListCreateAPIView):
    queryset = GuideEnrollment.objects.all()
    serializer_class = GuideEnrollmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class GuideEnrollmentDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = GuideEnrollment.objects.all()
    serializer_class = GuideEnrollmentSerializer
    permission_classes = [permissions.IsAuthenticated]
