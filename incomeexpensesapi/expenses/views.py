from django.shortcuts import render
from rest_framework.generics import ListCreateAPIView ,RetrieveUpdateDestroyAPIView
from rest_framework import permissions
from .serializers import ExpenseSerializer
from .models import Expense
from rest_framework.exceptions import PermissionDenied
from .permissions import IsOwner

# Create your views here.
class ExpenseListAPIView(ListCreateAPIView):
    serializer_class = ExpenseSerializer
    queryset = Expense.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return self.queryset.filter(owner=self.request.user)
        return self.queryset.none()


class ExpenseDetailAPIView(RetrieveUpdateDestroyAPIView):
    serializer_class = ExpenseSerializer
    queryset = Expense.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwner]
    lookup_field = "id"

    def perform_create(self, serializer):
        # Explicitly block AnonymousUser
        if not self.request.user.is_authenticated:
            raise PermissionDenied("Authentication required to perform this action.")
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return self.queryset.none()
        return self.queryset.filter(owner=self.request.user)


    