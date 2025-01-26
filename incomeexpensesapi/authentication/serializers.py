from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed

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
        
            

     