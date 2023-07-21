from django.contrib.auth import authenticate
from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from account.models import User

from account.serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, \
    UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, \
    UserVerifyRegistrationSerializer
from account.renderers import UserRenderer

# email
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from account.utils import Util


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            email = user.email
            if User.objects.filter(email=email).exists():
                if user.is_active:
                    return Response({'msg': 'This account already activated!'}, status=status.HTTP_200_OK)

                uid = urlsafe_base64_encode(force_bytes(user.id))
                print('Encoded UID', uid)
                token = get_tokens_for_user(user)
                print('USER REGISTRATION Token', token)
                link = 'http://localhost:3000/api/user/registration-verify/' + uid + '/' + PasswordResetTokenGenerator().make_token(user)
                print('Password Reset Link', link)
                # Send EMail
                body = 'Click Following Link to Reset Your Password ' + link
                data = {
                    'subject': 'Reset Your Password',
                    'body': body,
                    'to_email': user.email
                }
                Util.send_email(data)
                return Response({"message": "Registration Successful. We send an email to your account."
                                            "Please verify this email"}, status=status.HTTP_201_CREATED)
            else:
                return Response({"error": 'You are not a Registered User'}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserRegistrationVerification(APIView):
    renderer_classes = [UserRenderer]

    def get(self, request, uid, token):
        serializer = UserVerifyRegistrationSerializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Your Email Verification Successful. You can login now.'}, status=status.HTTP_200_OK)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'non_field_errors': ['Email or Password is not Valid']}},
                            status=status.HTTP_404_NOT_FOUND)


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Changed Successfully'}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset Successfully'}, status=status.HTTP_200_OK)
