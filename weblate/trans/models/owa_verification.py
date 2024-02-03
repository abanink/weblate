from django.db import models

class OwaVerification(models.Model):
    token = models.CharField(max_length=32)
    remote_url = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['token'])
        ]
    