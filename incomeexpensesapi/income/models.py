from django.db import models
from authentication.models import User

# Create your models here.
class Income(models.Model):
    SOURCES_OPTIONS = [
        ('SALARY' , 'SALARY'),
        ('BUSINESS' , 'BUSINESS'),
        ('SIDE-HUSTLES' , 'SIDE-HUSTLES'), 
        ('OTHERS' , 'OTHERS')

    ]

    source = models.CharField(choices=SOURCES_OPTIONS , max_length=255)
    amount = models.FloatField()
    description = models.TextField()
    owner = models.ForeignKey(to=User , on_delete=models.CASCADE)
    date = models.DateField(null = False , blank=False)
   
    class Meta:
        ordering: ['-date']


    def __str__(self):
        return str(self.owner)+ 's income'