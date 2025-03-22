from django.contrib.auth.hashers import make_password
from django.shortcuts import render, get_object_or_404
from rest_framework import status, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from licenses.models import UserAccount, License
from licenses.serializers import UserAccountSerializer, UserCreateSerializer, CustomUserSerializer, LicenseSerializer
from licenses.utils import generate_license, verify_license


# Create your views here.

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


class LicenseViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        try:
            licenses = License.objects.all()
            serializer = LicenseSerializer(licenses, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Licenses", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

    def create(self, request):
        client_id = request.data.get("client_id")
        license_type = request.data.get("license_type")
        exp = request.data.get("exp", None)

        if not client_id or not license_type:
            return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

        license_obj = generate_license(client_id, license_type, exp)
        return Response({"message": "License created", "data": LicenseSerializer(license_obj).data}, status=status.HTTP_201_CREATED)

    def verify(self, request, pk=None):
        try:
            license_obj = License.objects.get(pk=pk)
            is_valid = verify_license(license_obj)
            return Response({"valid": is_valid}, status=status.HTTP_200_OK)
        except License.DoesNotExist:
            return Response({"error": "License not found"}, status=status.HTTP_404_NOT_FOUND)