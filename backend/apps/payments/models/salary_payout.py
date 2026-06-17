from django.db import models

class SalaryPayout(models.Model):
    month = models.IntegerField()
    year = models.IntegerField()
    processed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("month", "year")