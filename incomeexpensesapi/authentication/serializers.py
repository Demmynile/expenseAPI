from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str , smart_bytes , DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode , urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util

class RegisterSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ["email", "username", "password"]

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError("The username should only contain alphanumeric characters")
        return attrs

    def create(self, validated_data):
        # Remove the password from validated_data and hash it
        password = validated_data.pop('password')
        user = User(**validated_data)  # Create the user instance
        user.set_password(password)    # Hash the password
        user.save()                    # Save the user with the hashed password
        return user
        


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3, read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        """
        Retrieve the user's tokens.
        """
        try:
            user = User.objects.get(email=obj['email'])
            return {
                'refresh': user.tokens()['refresh'],
                'access': user.tokens()['access']
            }
        except User.DoesNotExist:
            raise AuthenticationFailed('User does not exist.')

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        """
        Validate email and password for authentication.
        """
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        # Debugging information
        print(f"Email provided: {email}")
        print(f"Password provided: {password}")

        # Filter user by email
        filtered_user_by_email = User.objects.filter(email=email)
        if not filtered_user_by_email.exists():
            raise AuthenticationFailed('User with this email does not exist.')

        # Check if the `auth_provider` field exists
        user = filtered_user_by_email.first()
        if hasattr(user, 'auth_provider') and user.auth_provider != 'email':
            raise AuthenticationFailed(
                detail=f'Please continue your login using {user.auth_provider}'
            )

        # Authenticate user
        user = auth.authenticate(email=email, password=password)

        
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again.')
        if not user.is_active:
            raise AuthenticationFailed('Account is disabled, contact admin.')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified.')

        # Return validated user data
        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)

     