from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework import status
from .models import User, RefreshToken
from .utils import (
    generate_access_token,
    generate_refresh_token,
    hash_refresh_token,
    verify_refresh_token,
    send_ip_change_warning
)
from django.conf import settings
import jwt
from datetime import datetime, timedelta

class TokenObtainView(APIView):
    def get(self, request, user_id):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        ip_address = request.META.get('REMOTE_ADDR')
        access_token = generate_access_token(user_id, ip_address)
        refresh_token = generate_refresh_token()

        # Удаляем старые Refresh-токены
        RefreshToken.objects.filter(user=user).delete()
        RefreshToken.objects.create(
            user=user,
            token_hash=hash_refresh_token(refresh_token),
            ip_address=ip_address,
            expires_at=datetime.utcnow() + settings.REFRESH_TOKEN_LIFETIME
        )

        return JsonResponse({
            'access_token': access_token,
            'refresh_token': refresh_token
        }, status=status.HTTP_200_OK)

class TokenRefreshView(APIView):
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return JsonResponse({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            access_token = request.data.get('access_token')
            payload = jwt.decode(access_token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM], options={'verify_exp': False})
            user_id = payload['user_id']
            original_ip = payload['ip_address']
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid access token'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            token_obj = RefreshToken.objects.get(user=user, expires_at__gt=datetime.utcnow())
        except (User.DoesNotExist, RefreshToken.DoesNotExist):
            return JsonResponse({'error': 'Invalid or expired refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        if not verify_refresh_token(refresh_token, token_obj.token_hash):
            return JsonResponse({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        current_ip = request.META.get('REMOTE_ADDR')
        if current_ip != original_ip:
            send_ip_change_warning(user, original_ip, current_ip)

        new_access_token = generate_access_token(user_id, current_ip)
        new_refresh_token = generate_refresh_token()

        token_obj.token_hash = hash_refresh_token(new_refresh_token)
        token_obj.ip_address = current_ip
        token_obj.expires_at = datetime.utcnow() + settings.REFRESH_TOKEN_LIFETIME
        token_obj.save()

        return JsonResponse({
            'access_token': new_access_token,
            'refresh_token': new_refresh_token
        }, status=status.HTTP_200_OK)

class TokenVerifyView(APIView):
    def post(self, request):
        token = request.data.get('access_token')
        if not token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                return JsonResponse({'error': 'Access token required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            return JsonResponse({
                'valid': True,
                'payload': payload
            }, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)