# Generated by Django 5.1.4 on 2025-01-30 09:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("expenses", "0002_alter_expense_amount"),
    ]

    operations = [
        migrations.AlterField(
            model_name="expense",
            name="amount",
            field=models.FloatField(),
        ),
    ]
