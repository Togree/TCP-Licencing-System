import json
import os

import rsa

from django.utils.timezone import now
from datetime import datetime, timedelta

from django.contrib.auth.hashers import make_password
from django.shortcuts import render, get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from licenseManager import settings
from licenses.models import UserAccount, License
from licenses.serializers import UserAccountSerializer, UserCreateSerializer, CustomUserSerializer, LicenseSerializer
from licenses.utils import generate_license, verify_license, load_rsa_keys


# Create your views here.

# Expose public key API call
class PublicKeyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        """Expose the public key via an API."""
        public_key_path = os.path.join(settings.BASE_DIR, "licenses/keys/public_key.pem")

        if not os.path.exists(public_key_path):
            return Response({"error": "Public key not found."}, status=404)

        with open(public_key_path, "r") as f:
            public_key = f.read()

        return Response({"public_key": public_key}, status=200)


# Register normal user APi call
class UserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [AllowAny],
        'list': [IsAdminUser],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserAccountSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Set the user as active
            serializer.validated_data['is_active'] = True

            # Set usertype as admin
            serializer.validated_data['user_type'] = 'normal'
            serializer.save()

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Register Admin API call
class AdminUserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [AllowAny],
        'list': [IsAdminUser],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Set the user as active
            serializer.validated_data['is_active'] = True

            # Set usertype as admin
            serializer.validated_data['user_type'] = 'admin'

            serializer.save()

            return Response({'message': 'Account created succesfuly'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# license API call
class LicenseViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        """
        List all licenses.
        """
        try:
            licenses = License.objects.all()
            serializer = LicenseSerializer(licenses, many=True, context={"request": request})
            return Response({"error": False, "message": "All Licenses", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": "An Error Occurred", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def create(self, request):
        """
        Create a new license.
        """
        client_id = request.data.get("client_id")
        license_type = request.data.get("license_type")
        exp = request.data.get("exp", None)
        duration_days = request.data.get("duration_days", None)

        if not client_id or not license_type:
            return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

        # Convert exp to datetime if provided
        expiration_date = None
        if exp:
            try:
                expiration_date = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            except ValueError:
                return Response({"error": "Invalid expiry date format. Use ISO 8601 (e.g., '2025-04-21T12:00:00Z')."},
                                status=status.HTTP_400_BAD_REQUEST)
        elif duration_days:
            try:
                expiration_date = now() + timedelta(days=int(duration_days))
            except ValueError:
                return Response({"error": "Invalid duration_days format. Must be an integer."},
                                status=status.HTTP_400_BAD_REQUEST)

        # Check if license already exists for the client
        if License.objects.filter(client_id=client_id).exists():
            return Response({"error": "License for this client already exists."}, status=status.HTTP_409_CONFLICT)

        # Generate RSA key and sign the license data
        private_key, _ = load_rsa_keys()  # Load RSA keys
        issued_at = now()

        # License data for signing
        license_data = {
            "client_id": client_id,
            "license_type": license_type,
            "issued_at": issued_at.strftime("%Y-%m-%d %H:%M:%S"),
            "exp": expiration_date.strftime("%Y-%m-%d %H:%M:%S") if expiration_date else "Never",
        }

        # Convert to JSON and sign
        license_json = json.dumps(license_data, separators=(',', ':'), sort_keys=True)
        signature = rsa.sign(license_json.encode(), private_key, "SHA-256").hex()

        # Create and save license in DB
        license_obj = License.objects.create(
            client_id=client_id,
            license_type=license_type,
            issued_at=issued_at,
            exp=expiration_date,
            signature=signature,  # Store the signature
            status="active"
        )

        return Response({"message": "License created", "data": LicenseSerializer(license_obj).data},
                        status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], permission_classes=[])  # No authentication required
    def verify(self, request):
        """Verify a license without authentication."""
        client_id = request.data.get("client_id")
        provided_signature = request.data.get("signature")

        if not client_id or not provided_signature:
            return Response({"status": "error", "message": "Missing required fields."}, status=status.HTTP_400_BAD_REQUEST)

        verification_result = verify_license(client_id, provided_signature)
        return Response(verification_result, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def revoke(self, request, pk=None):
        """Revoke a license (Admin only)."""
        try:
            license_obj = License.objects.get(pk=pk)
            if license_obj.status == "revoked":
                return Response({"error": "License is already revoked."}, status=status.HTTP_400_BAD_REQUEST)
            license_obj.status = "revoked"
            license_obj.save()
            return Response({"message": "License revoked successfully."}, status=status.HTTP_200_OK)
        except License.DoesNotExist:
            return Response({"error": "License not found."}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def reactivate(self, request, pk=None):
        """Reactivate a revoked license (Admin only)."""
        try:
            license_obj = License.objects.get(pk=pk)
            if license_obj.status == "active":
                return Response({"error": "License is already active."}, status=status.HTTP_400_BAD_REQUEST)
            license_obj.status = "active"
            license_obj.save()
            return Response({"message": "License reactivated successfully."}, status=status.HTTP_200_OK)
        except License.DoesNotExist:
            return Response({"error": "License not found."}, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        """Delete a generated license (Admin only)."""
        try:
            license_obj = License.objects.get(pk=pk)
            license_obj.delete()
            return Response({"message": "License deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except License.DoesNotExist:
            return Response({"error": "License not found."}, status=status.HTTP_404_NOT_FOUND)
